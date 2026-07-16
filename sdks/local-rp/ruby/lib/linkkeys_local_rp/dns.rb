# frozen_string_literal: true

require 'set'
require_relative 'crypto'
require_relative 'cbor'

module LinkkeysLocalRp
  # DNS TXT lookup seam + `_linkkeys`/`_linkkeys_apis` record parsing and
  # key pinning.
  #
  # Mirrors `crates/liblinkkeys/src/dns.rs` (record parsing, pinning, vouch
  # verification, `trust_keys`) plus the DNS *lookup* seam itself. Per the
  # design doc's "Required Network Access" / "SDK endpoint discovery and
  # pinning": the resolver is configurable, defaulting to the system
  # resolver -- LAN resolver spoofing is an accepted, documented tradeoff
  # for this mode.
  #
  # Dependency note: `Resolv::DNS` is Ruby stdlib and supports TXT record
  # queries directly (`Resolv::DNS::Resource::IN::TXT`), so no external gem
  # is needed here (unlike Python, whose standard library has no DNS TXT
  # lookup capability at all).
  module Dns
    DEFAULT_TCP_PORT = 4987

    class DnsParseError < StandardError; end
    class NoLinkKeysRecord < DnsParseError; end
    class MissingVersion < DnsParseError; end

    class UnsupportedVersion < DnsParseError
      attr_reader :version

      def initialize(version)
        @version = version
        super("unsupported linkkeys version: #{version}")
      end
    end

    class MissingApisEndpoint < DnsParseError; end
    class InvalidFormat < DnsParseError; end

    LinkKeysRecord = Struct.new(:fingerprints, keyword_init: true)
    LinkKeysApis = Struct.new(:tcp, :https_base, keyword_init: true)

    module_function

    def linkkeys_dns_name(domain) = "_linkkeys.#{domain}"
    def linkkeys_apis_dns_name(domain) = "_linkkeys_apis.#{domain}"

    def require_lk1_version!(parts)
      version_part = parts.find { |p| p.start_with?('v=') }
      raise MissingVersion, 'missing v= tag in TXT record' if version_part.nil?

      version = version_part[2..]
      raise UnsupportedVersion, version unless version == 'lk1'
    end
    private_class_method :require_lk1_version!

    def parse_linkkeys_txt(txt)
      parts = txt.split
      require_lk1_version!(parts)
      fingerprints = parts.select { |p| p.start_with?('fp=') }.map { |p| p[3..] }
      LinkKeysRecord.new(fingerprints: fingerprints)
    end

    def normalize_tcp_endpoint(value)
      return value if value.empty? || value.include?(':')

      "#{value}:#{DEFAULT_TCP_PORT}"
    end
    private_class_method :normalize_tcp_endpoint

    def parse_linkkeys_apis_txt(txt)
      parts = txt.split
      require_lk1_version!(parts)

      tcp_raw = parts.find { |p| p.start_with?('tcp=') }&.then { |p| p[4..] }
      tcp = tcp_raw && !tcp_raw.empty? ? normalize_tcp_endpoint(tcp_raw) : nil

      https_raw = parts.find { |p| p.start_with?('https=') }&.then { |p| p[6..] }
      https_base = https_raw && !https_raw.empty? ? "https://#{https_raw}" : nil

      raise MissingApisEndpoint, '_linkkeys_apis record has neither tcp= nor https=' if tcp.nil? && https_base.nil?

      LinkKeysApis.new(tcp: tcp, https_base: https_base)
    end

    def valid_fingerprint?(fp)
      fp.length == 64 && fp.match?(/\A[0-9a-fA-F]+\z/)
    end

    # Recompute each candidate key's fingerprint (never trust the wire
    # `fingerprint` field) and keep only keys whose recomputed fingerprint
    # is a member of `pinned`.
    def pin_keys_to_fingerprints(keys, pinned)
      pinned_lower = pinned.select { |f| valid_fingerprint?(f) }.map(&:downcase).to_set
      keys.select { |k| pinned_lower.include?(Crypto.fingerprint(k.public_key).downcase) }
    end

    KEY_VOUCH_TAG = 'linkkeys-key-vouch-v1alpha'

    def key_vouch_payload(enc_fingerprint, enc_expires_at)
      Cbor.encode([KEY_VOUCH_TAG, enc_fingerprint, enc_expires_at])
    end

    # Verify that `signing_key` vouches for `enc_key` (encryption keys are
    # not published in DNS; they are trusted only via a DNS-pinned signing
    # key's vouch).
    def verify_key_vouch(enc_key, signing_key, now)
      return false unless enc_key.signed_by_key_id == signing_key.key_id
      return false unless Crypto.signing_key_validity(signing_key.expires_at, signing_key.revoked_at, now) == Crypto::KeyValidity::VALID
      return false if enc_key.key_signature.nil?

      recomputed_fp = Crypto.fingerprint(enc_key.public_key)
      payload = key_vouch_payload(recomputed_fp, enc_key.expires_at)
      begin
        Crypto.resolve_and_verify(signing_key.algorithm, payload, enc_key.key_signature, signing_key.public_key)
        true
      rescue Crypto::Error
        false
      end
    end

    # Establish the trusted key set from a fetched key list and the
    # DNS-pinned fingerprint set. Signing keys are pinned directly;
    # encryption keys are trusted only when a pinned signing key vouches
    # for them. Callers MUST treat an empty result as "no trustworthy keys"
    # and fail closed.
    def trust_keys(keys, pinned, now)
      signing = keys.select { |k| k.key_usage == 'sign' }
      pinned_signing = pin_keys_to_fingerprints(signing, pinned)

      trusted = pinned_signing.dup
      keys.each do |k|
        next unless k.key_usage == 'encrypt'

        trusted << k if pinned_signing.any? { |sk| verify_key_vouch(k, sk, now) }
      end
      trusted
    end

    # Caller-injected DNS TXT lookup seam duck-type: any object responding
    # to `txt_lookup(name) -> Array<String>`, one entry per TXT record (the
    # concatenation of that record's RFC1035 character-strings).
    class SystemDnsResolver
      def txt_lookup(name)
        require 'resolv'
        resolver = Resolv::DNS.new
        begin
          resources = resolver.getresources(name, Resolv::DNS::Resource::IN::TXT)
        ensure
          resolver.close
        end
        resources.map { |r| r.strings.join.dup.force_encoding(::Encoding::UTF_8) }
      rescue StandardError => e
        raise "DNS TXT lookup failed for #{name}: #{e.message}"
      end
    end
  end
end
