# frozen_string_literal: true

require_relative 'cbor'
require_relative 'types'
require_relative 'dns'
require_relative 'tls'
require_relative 'revocation'
require_relative 'transport'
require_relative 'timeutil'

module LinkkeysLocalRp
  # CSIL-RPC over the injected Transport, TLS-pinned to a domain's DNS
  # `fp=` records -- this SDK's only network surface (design doc, "Required
  # Network Access"): domain public keys, revocations, and claim-ticket
  # redemption, all unauthenticated-TLS TCP CSIL-RPC calls pinned the same
  # way `crates/linkkeys/src/tcp/tls.rs` pins the S2S path.
  #
  # There is no csilgen Ruby target yet (a request has been filed at
  # ~/repos/catalystcommunity/csilgen/docs/csilgen-requests/), so this
  # module hand-rolls the CSIL-RPC envelope + framing directly, exactly
  # mirroring what the Rust and Python reference SDKs' own `rpc.rs`/`rpc.py`
  # do (both bypass their languages' generated client wrappers for the same
  # reason: those wrappers pass a transport-agnostic, lowercased
  # `(service, method)` pair to an injected `Transport.call()` seam, but the
  # real `CsilRpcRequest` on the wire needs the verbatim CSIL names instead
  # -- `service="DomainKeys"`, `op="get-domain-keys"` -- which can't be
  # generically recovered from the lowercased form). This SDK only ever
  # calls two services (three operations), so hand-building the three real
  # `CsilRpcRequest`s directly and reusing `Types`' to_cbor/from_cbor for
  # the typed payloads is both correct and small.
  module Rpc
    # Mirrors the server's own cap (`crates/linkkeys-rpc-client/src/lib.rs`)
    # so a malicious/compromised peer cannot drive this client to an
    # unbounded allocation via a forged length prefix.
    MAX_FRAME_SIZE = 1024 * 1024

    CSIL_RPC_VERSION = 1
    TAG_ENCODED_CBOR = 24

    class Error < StandardError; end
    class ProtocolError < Error; end

    class ServerError < Error
      attr_reader :status, :server_message

      def initialize(status, message)
        @status = status
        @server_message = message
        super("server error (#{status}): #{message}")
      end
    end

    class NoTrustedDomainKeys < Error
      attr_reader :domain

      def initialize(domain)
        @domain = domain
        super("no trusted public keys could be established for domain: #{domain}")
      end
    end

    DomainEndpoint = Struct.new(:fingerprints, :tcp_addr, keyword_init: true)

    module_function

    def recv_exact(sock, n)
      chunks = []
      remaining = n
      while remaining.positive?
        chunk = sock.read(remaining)
        raise ProtocolError, 'connection closed before expected bytes were received' if chunk.nil? || chunk.empty?

        chunks << chunk
        remaining -= chunk.bytesize
      end
      chunks.join
    end
    private_class_method :recv_exact

    def send_frame(sock, data)
      sock.write([data.bytesize].pack('N'))
      sock.write(data)
    end
    private_class_method :send_frame

    def recv_frame(sock)
      length = recv_exact(sock, 4).unpack1('N')
      raise ProtocolError, "peer frame too large (#{length} bytes, max #{MAX_FRAME_SIZE})" if length > MAX_FRAME_SIZE

      recv_exact(sock, length)
    end
    private_class_method :recv_frame

    def encode_request(service, op, payload)
      envelope = {
        'v' => CSIL_RPC_VERSION,
        'service' => service,
        'op' => op,
        'payload' => Cbor::CborTag.new(TAG_ENCODED_CBOR, payload)
      }
      Cbor.encode(envelope)
    end
    private_class_method :encode_request

    # Returns [status, error, payload].
    def decode_response(data)
      value = Cbor.decode(data)
      raise ProtocolError, 'RPC response envelope is not a CBOR map' unless value.is_a?(Hash)

      status = value['status']
      raise ProtocolError, "RPC response missing integer 'status'" unless status.is_a?(Integer)

      error = value['error']
      payload_tag = value['payload']
      payload = payload_tag.is_a?(Cbor::CborTag) && payload_tag.tag == TAG_ENCODED_CBOR ? payload_tag.value : ''.b

      [status, error, payload]
    end
    private_class_method :decode_response

    # Look up a domain's trust anchor + TCP endpoint over DNS TXT. Fails
    # closed: a missing/unparseable record, or a `_linkkeys` record with no
    # `fp=` entries, or a `_linkkeys_apis` record with no `tcp=` entry, is
    # an error -- this SDK never proceeds without a fingerprint set to pin
    # to.
    def discover_domain_endpoint(dns, domain)
      anchor_name = Dns.linkkeys_dns_name(domain)
      fingerprints = []
      dns.txt_lookup(anchor_name).each do |txt|
        record = begin
          Dns.parse_linkkeys_txt(txt)
        rescue Dns::DnsParseError
          next
        end
        next if record.fingerprints.empty?

        fingerprints = record.fingerprints
        break
      end
      raise Dns::DnsParseError, "no usable #{anchor_name} TXT record with fp= entries" if fingerprints.empty?

      apis_name = Dns.linkkeys_apis_dns_name(domain)
      tcp_addr = nil
      dns.txt_lookup(apis_name).each do |txt|
        apis = begin
          Dns.parse_linkkeys_apis_txt(txt)
        rescue Dns::DnsParseError
          next
        end
        next unless apis.tcp

        tcp_addr = apis.tcp
        break
      end
      raise Dns::DnsParseError, "no usable #{apis_name} TXT record with tcp= entry" unless tcp_addr

      DomainEndpoint.new(fingerprints: fingerprints, tcp_addr: tcp_addr)
    end

    # Open a fresh TLS connection to `endpoint`, pinned to its
    # fingerprints, send one CSIL-RPC request, and return the decoded
    # success payload.
    def call(transport, endpoint, service, op, payload)
      raw_sock = transport.dial(endpoint.tcp_addr)
      hostname = Tls.extract_hostname(endpoint.tcp_addr)
      tls_sock = Tls.dial_tls_pinned(raw_sock, hostname, endpoint.fingerprints)
      begin
        request_bytes = encode_request(service, op, payload)
        send_frame(tls_sock, request_bytes)
        response_bytes = recv_frame(tls_sock)
        status, error, resp_payload = decode_response(response_bytes)
        raise ServerError.new(status, error || 'unknown error') unless status.zero?

        resp_payload
      ensure
        tls_sock.close
      end
    end
    private_class_method :call

    # Fetch `domain`'s currently-trusted public keys:
    # `DomainKeys/get-domain-keys` over TCP CSIL-RPC, pinned to the
    # domain's DNS `fp=` set, with signing keys pinned directly and
    # encryption keys trusted only via a pinned signing key's vouch.
    # `DomainKeys/get-revocations` is ALWAYS fetched afterward too --
    # regardless of the response's `recent_revocations_available` hint,
    # which is server-asserted and not itself authenticated, so a
    # compromised/lying IDP could otherwise set it to false to hide a
    # sibling-signed revocation certificate for one of its own keys. A
    # failed/errored/dropped get-revocations call is fatal (fail closed):
    # we would rather abort the login than silently proceed on a key set
    # that might include a key the domain's own siblings have revoked. Any
    # certificate that DOES arrive and quorum-verify is applied: its
    # target key is dropped from the trusted set no matter what the
    # fetched key entry itself says (its own revoked_at may well be unset
    # -- that is the whole point of the sibling-certificate channel; see
    # Revocation.apply_revocations). An empty trusted result -- whether
    # from the start or after revocations are applied -- is
    # NoTrustedDomainKeys, fail closed.
    def fetch_domain_keys(transport, dns, domain)
      endpoint = discover_domain_endpoint(dns, domain)

      payload = Types::EmptyRequest.new.to_cbor
      resp_bytes = call(transport, endpoint, 'DomainKeys', 'get-domain-keys', payload)
      resp = Types::GetDomainKeysResponse.from_cbor(resp_bytes)

      now = Time.now.getutc
      trusted = Dns.trust_keys(resp.keys, endpoint.fingerprints, now)
      raise NoTrustedDomainKeys, domain if trusted.empty?

      since = Timeutil.to_rfc3339(now - (30 * 86_400))
      req_payload = Types::GetRevocationsRequest.new(since: since).to_cbor
      # No rescue here: a get-revocations error/timeout/protocol failure
      # must propagate and abort the login, not be swallowed into "assume
      # no revocations" (see doc comment above).
      resp_bytes = call(transport, endpoint, 'DomainKeys', 'get-revocations', req_payload)
      revocations = Types::GetRevocationsResponse.from_cbor(resp_bytes).revocations
      trusted = Revocation.apply_revocations(trusted, revocations, domain, now)

      raise NoTrustedDomainKeys, domain if trusted.empty?

      trusted
    end

    # Redeem a claim ticket with `domain`'s IDP: `LocalRp/redeem-claim-ticket`
    # over TCP CSIL-RPC, pinned via the domain's DNS `fp=` set.
    # Unauthenticated at the transport layer (no client cert) -- the
    # redemption request itself is signed with the local RP's signing key,
    # which is the possession proof the server checks.
    def redeem_claim_ticket(transport, dns, domain, signed_request)
      endpoint = discover_domain_endpoint(dns, domain)
      payload = signed_request.to_cbor
      resp_bytes = call(transport, endpoint, 'LocalRp', 'redeem-claim-ticket', payload)
      Types::LocalRpTicketRedemptionResponse.from_cbor(resp_bytes)
    end
  end
end
