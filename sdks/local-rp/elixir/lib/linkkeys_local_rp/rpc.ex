defmodule LinkkeysLocalRp.Rpc do
  @moduledoc """
  CSIL-RPC over the injected transport, TLS-pinned to a domain's DNS
  `fp=` records — this SDK's only network surface (design doc, "Required
  Network Access"): domain public keys, revocations, and claim-ticket
  redemption, all unauthenticated-TLS TCP CSIL-RPC calls pinned the same
  way `crates/linkkeys/src/tcp/tls.rs` pins the S2S path.

  There is no csilgen Elixir target, so this module hand-rolls the
  CSIL-RPC envelope directly over `LinkkeysLocalRp.Cbor` — the same
  framing the sibling SDKs' own `rpc.rs`/`rpc.py` hand-roll. (Their
  generated clients historically also passed a lowercased service name
  unusable on the wire; that csilgen defect has since been fixed upstream,
  but with no Elixir generator target, hand-rolling remains the Elixir
  path regardless.)
  """

  alias LinkkeysLocalRp.Cbor
  alias LinkkeysLocalRp.Cbor.Tag
  alias LinkkeysLocalRp.Dns
  alias LinkkeysLocalRp.Revocation
  alias LinkkeysLocalRp.Tls
  alias LinkkeysLocalRp.Transport
  alias LinkkeysLocalRp.Types

  # Mirrors the server's own cap (`crates/linkkeys-rpc-client/src/lib.rs`)
  # so a malicious/compromised peer cannot drive this client to an
  # unbounded allocation via a forged length prefix.
  @max_frame_size 1024 * 1024

  @csil_rpc_version 1
  @tag_encoded_cbor 24

  defmodule RpcError do
    defexception [:message]
  end

  defmodule ProtocolError do
    defexception [:message]
  end

  defmodule ServerError do
    defexception [:message, :status]

    @impl true
    def exception({status, message}) do
      %__MODULE__{status: status, message: "server error (#{status}): #{message}"}
    end
  end

  defmodule NoTrustedDomainKeys do
    defexception [:message, :domain]

    @impl true
    def exception(domain) do
      %__MODULE__{domain: domain, message: "no trusted public keys could be established for domain: #{domain}"}
    end
  end

  defmodule DomainEndpoint do
    @moduledoc "A discovered domain's pinned trust-anchor fingerprints (`_linkkeys`) and its CSIL-RPC TCP address (`_linkkeys_apis` `tcp=`)."
    defstruct [:fingerprints, :tcp_addr]
  end

  # `sock` here is always the TLS-wrapped `:ssl` socket returned by
  # `LinkkeysLocalRp.Tls.dial_tls_pinned/4` — every CSIL-RPC frame in this
  # SDK travels over the pinned TLS connection, never a bare TCP socket.
  defp send_frame(sock, data) do
    len = <<byte_size(data)::32>>
    :ok = :ssl.send(sock, len)
    :ok = :ssl.send(sock, data)
  end

  defp recv_exact(sock, n) do
    case :ssl.recv(sock, n) do
      {:ok, data} when byte_size(data) == n -> {:ok, data}
      {:ok, _short} -> {:error, %ProtocolError{message: "connection closed before expected bytes were received"}}
      {:error, reason} -> {:error, %ProtocolError{message: "recv failed: #{inspect(reason)}"}}
    end
  end

  defp recv_frame(sock) do
    with {:ok, len_bytes} <- recv_exact(sock, 4) do
      <<length::32>> = len_bytes

      if length > @max_frame_size do
        {:error, %ProtocolError{message: "peer frame too large (#{length} bytes, max #{@max_frame_size})"}}
      else
        recv_exact(sock, length)
      end
    end
  end

  defp encode_request(service, op, payload) do
    Cbor.encode(%{
      "v" => @csil_rpc_version,
      "service" => service,
      "op" => op,
      "payload" => %Tag{tag: @tag_encoded_cbor, value: Cbor.bytes(payload)}
    })
  end

  defp decode_response(data) do
    case Cbor.decode(data) do
      %{"status" => status} = tree when is_integer(status) ->
        error = Map.get(tree, "error")

        payload =
          case Map.get(tree, "payload") do
            %Tag{tag: @tag_encoded_cbor, value: v} -> Cbor.bytes!(v)
            _ -> <<>>
          end

        {:ok, status, error, payload}

      _ ->
        {:error, %ProtocolError{message: "RPC response envelope is not a CBOR map with integer 'status'"}}
    end
  rescue
    e -> {:error, %ProtocolError{message: "RPC response decode failed: #{Exception.message(e)}"}}
  end

  @doc """
  Look up a domain's trust anchor + TCP endpoint over DNS TXT. Fails
  closed: a missing/unparseable record, or a `_linkkeys` record with no
  `fp=` entries, or a `_linkkeys_apis` record with no `tcp=` entry, is an
  error — this SDK never proceeds without a fingerprint set to pin to.
  """
  @spec discover_domain_endpoint(Dns.resolver(), String.t()) :: {:ok, DomainEndpoint.t()} | {:error, term}
  def discover_domain_endpoint(dns, domain) do
    anchor_name = Dns.linkkeys_dns_name(domain)

    with {:ok, anchor_txts} <- dns.(anchor_name),
         fingerprints when fingerprints != [] <- find_fingerprints(anchor_txts) do
      apis_name = Dns.linkkeys_apis_dns_name(domain)

      with {:ok, apis_txts} <- dns.(apis_name),
           tcp_addr when is_binary(tcp_addr) <- find_tcp_addr(apis_txts) do
        {:ok, %DomainEndpoint{fingerprints: fingerprints, tcp_addr: tcp_addr}}
      else
        _ -> {:error, %Dns.DnsParseError{message: "no usable #{apis_name} TXT record with tcp= entry"}}
      end
    else
      _ -> {:error, %Dns.DnsParseError{message: "no usable #{anchor_name} TXT record with fp= entries"}}
    end
  end

  defp find_fingerprints(txts) do
    Enum.find_value(txts, [], fn txt ->
      case safe_parse_linkkeys_txt(txt) do
        %Dns.LinkKeysRecord{fingerprints: fps} when fps != [] -> fps
        _ -> nil
      end
    end)
  end

  # A single malformed/unparseable TXT record is not fatal on its own —
  # there may be other TXT records at the same name; only exhausting all
  # of them is an error (surfaced by the empty-list checks in
  # `discover_domain_endpoint/2`).
  defp safe_parse_linkkeys_txt(txt) do
    Dns.parse_linkkeys_txt(txt)
  rescue
    _ -> nil
  end

  defp find_tcp_addr(txts) do
    Enum.find_value(txts, nil, fn txt ->
      case safe_parse_linkkeys_apis_txt(txt) do
        %Dns.LinkKeysApis{tcp: tcp} when is_binary(tcp) -> tcp
        _ -> nil
      end
    end)
  end

  defp safe_parse_linkkeys_apis_txt(txt) do
    Dns.parse_linkkeys_apis_txt(txt)
  rescue
    _ -> nil
  end

  defp call(transport, %DomainEndpoint{} = endpoint, service, op, payload) do
    with {:ok, raw_sock} <- transport.(endpoint.tcp_addr) do
      hostname = Tls.extract_hostname(endpoint.tcp_addr)

      try do
        tls_sock = Tls.dial_tls_pinned(raw_sock, hostname, endpoint.fingerprints)

        try do
          request_bytes = encode_request(service, op, payload)
          send_frame(tls_sock, request_bytes)

          with {:ok, response_bytes} <- recv_frame(tls_sock),
               {:ok, status, error, resp_payload} <- decode_response(response_bytes) do
            if status != 0 do
              {:error, %ServerError{status: status, message: error || "unknown error"}}
            else
              {:ok, resp_payload}
            end
          end
        after
          :ssl.close(tls_sock)
        end
      rescue
        e -> {:error, e}
      end
    end
  end

  @doc """
  Fetch `domain`'s currently-trusted public keys:
  `DomainKeys/get-domain-keys` over TCP CSIL-RPC, pinned to the domain's
  DNS `fp=` set, with signing keys pinned directly and encryption keys
  trusted only via a pinned signing key's vouch. ALWAYS also fetches
  `DomainKeys/get-revocations` — regardless of the response's
  `recent_revocations_available` flag, which is merely a server-side
  optimization hint, never a trust decision this client may rely on (a
  compromised/malicious IDP could otherwise simply omit or clear that flag
  to suppress delivery of a revocation targeting one of its own keys) —
  and drops any key a quorum-verified sibling revocation certificate
  targets. A `get-revocations` fetch or decode failure is FATAL (fails the
  whole call, fail closed): revocation delivery is exactly the mechanism
  that lets a verifier learn a key it would otherwise trust has been
  compromised, so silently proceeding without it on error would defeat
  revocation entirely — an empty *list* is a legitimate, successful
  "nothing revoked" answer, but a failure to even ask is not. An empty
  final trusted result is `NoTrustedDomainKeys` — fail closed, matching
  the server's own posture.
  """
  @spec fetch_domain_keys(Transport.t(), Dns.resolver(), String.t()) :: {:ok, list} | {:error, term}
  def fetch_domain_keys(transport, dns, domain) do
    with {:ok, endpoint} <- discover_domain_endpoint(dns, domain) do
      payload = Types.empty_request_to_cbor(%Types.EmptyRequest{})

      with {:ok, resp_bytes} <- call(transport, endpoint, "DomainKeys", "get-domain-keys", payload) do
        resp = Types.get_domain_keys_response_from_cbor(resp_bytes)
        now = DateTime.utc_now()
        trusted = Dns.trust_keys(resp.keys, endpoint.fingerprints, now)

        if trusted == [] do
          {:error, NoTrustedDomainKeys.exception(domain)}
        else
          with {:ok, trusted} <- apply_revocations_step(transport, endpoint, domain, trusted, now) do
            if trusted == [],
              do: {:error, NoTrustedDomainKeys.exception(domain)},
              else: {:ok, trusted}
          end
        end
      end
    end
  end

  # Always fetches DomainKeys/get-revocations and applies every
  # quorum-verified certificate to `trusted`. A fetch/decode failure here
  # is propagated as `{:error, reason}` — fail closed, never swallowed —
  # per this module's fetch_domain_keys/3 doc above.
  defp apply_revocations_step(transport, endpoint, domain, trusted, now) do
    since =
      now
      |> DateTime.add(-30, :day)
      |> DateTime.truncate(:second)
      |> DateTime.to_iso8601()

    req_payload = Types.get_revocations_request_to_cbor(%Types.GetRevocationsRequest{since: since})

    with {:ok, resp_bytes} <- call(transport, endpoint, "DomainKeys", "get-revocations", req_payload) do
      try do
        revocations = Types.get_revocations_response_from_cbor(resp_bytes).revocations

        trusted =
          if revocations != [], do: Revocation.apply_revocations(trusted, revocations, domain, now), else: trusted

        {:ok, trusted}
      rescue
        e -> {:error, %ProtocolError{message: "get-revocations response decode failed: #{Exception.message(e)}"}}
      end
    end
  end

  @doc """
  Redeem a claim ticket with `domain`'s IDP: `LocalRp/redeem-claim-ticket`
  over TCP CSIL-RPC, pinned via the domain's DNS `fp=` set. Unauthenticated
  at the transport layer (no client cert) — the redemption request itself
  is signed with the local RP's signing key, which is the possession proof
  the server checks.
  """
  @spec redeem_claim_ticket(Transport.t(), Dns.resolver(), String.t(), Types.SignedLocalRpTicketRedemptionRequest.t()) ::
          {:ok, Types.LocalRpTicketRedemptionResponse.t()} | {:error, term}
  def redeem_claim_ticket(transport, dns, domain, %Types.SignedLocalRpTicketRedemptionRequest{} = signed_request) do
    with {:ok, endpoint} <- discover_domain_endpoint(dns, domain) do
      payload = Types.signed_local_rp_ticket_redemption_request_to_cbor(signed_request)

      with {:ok, resp_bytes} <- call(transport, endpoint, "LocalRp", "redeem-claim-ticket", payload) do
        {:ok, Types.local_rp_ticket_redemption_response_from_cbor(resp_bytes)}
      end
    end
  end
end
