# frozen_string_literal: true

require 'openssl'
require_relative 'crypto'

module LinkkeysLocalRp
  # Client-side TLS pinning: verify a peer's certificate by its SPKI public
  # key fingerprint against a DNS-published `fp=` set -- no CA chain,
  # matching the trust model `crates/linkkeys/src/tcp/tls.rs` uses for
  # every LinkKeys TCP peer.
  #
  # Every LinkKeys domain TLS certificate is generated from an Ed25519
  # domain signing key. Per RFC 8410, an Ed25519 SubjectPublicKeyInfo's
  # `subjectPublicKey` BIT STRING contents ARE exactly the 32 raw public
  # key bytes (no ASN.1 padding/framing inside the bit string) -- ahead of
  # those 32 bytes sits a fixed 12-byte DER prefix
  # (`302a300506032b6570032100`). Ruby's `openssl` gem conveniently exposes
  # `OpenSSL::PKey::PKey#raw_public_key` on a key object obtained FROM a
  # certificate too (not only on a freshly-generated raw key), so this
  # module reads that directly rather than hand-slicing the DER prefix.
  # `raw_public_key` raises `OpenSSL::PKey::PKeyError` for any non-OKP key
  # type (RSA, EC, ...), which this module treats as
  # `UnsupportedCertificateKeyType` -- this SDK only ever needs to handle
  # Ed25519 leaf certificates, since there is no other key type in the
  # LinkKeys TLS trust model.
  #
  # Ruby's `OpenSSL::SSL` cannot express "verify only by SPKI pin, ignore
  # WebPKI/hostname" as a built-in verification mode, so this module uses
  # `OpenSSL::SSL::VERIFY_NONE` (skip the built-in chain/hostname checks
  # entirely) and performs the pin check itself, manually, as a MANDATORY
  # post-handshake step -- the socket is closed and an error raised before
  # a single application byte is trusted if the pin doesn't match.
  module Tls
    class Error < StandardError; end
    class PinMismatch < Error; end
    class UnsupportedCertificateKeyType < Error; end
    class CertificateExpired < Error; end

    module_function

    def extract_hostname(host_port)
      idx = host_port.rindex(':')
      return host_port if idx.nil?

      host = host_port[0...idx]
      host.empty? ? host_port : host
    end

    # Extract the SPKI raw public-key bytes from a DER certificate and
    # return their SHA-256 hex fingerprint -- the same value
    # `crates/linkkeys/src/tcp/tls.rs` computes from
    # `spki.subject_public_key.data`.
    def leaf_public_key_fingerprint(der_bytes)
      cert = begin
        OpenSSL::X509::Certificate.new(der_bytes)
      rescue OpenSSL::X509::CertificateError => e
        raise Error, "peer certificate could not be parsed: #{e.message}"
      end

      now = Time.now.getutc
      if now < cert.not_before.getutc || now > cert.not_after.getutc
        raise CertificateExpired, 'peer certificate is not within its validity period'
      end

      raw_public_key =
        begin
          cert.public_key.raw_public_key
        rescue OpenSSL::PKey::PKeyError
          raise UnsupportedCertificateKeyType, "expected an Ed25519 certificate public key, got #{cert.public_key.class}"
        end
      raise UnsupportedCertificateKeyType, 'expected a 32-byte Ed25519 public key' unless raw_public_key.bytesize == 32

      Crypto.fingerprint(raw_public_key)
    end

    # Wrap `raw_sock` in a TLS client connection pinned to
    # `expected_fingerprints`, presenting no client certificate (public
    # domain-key/revocation fetch and ticket redemption must not require
    # mutual TLS -- design doc, "Required Network Access"). Raises Error
    # and closes the socket if the peer's certificate does not pin to any
    # of `expected_fingerprints`.
    def dial_tls_pinned(raw_sock, server_hostname, expected_fingerprints)
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE

      tls_sock = OpenSSL::SSL::SSLSocket.new(raw_sock, ctx)
      tls_sock.hostname = server_hostname
      begin
        tls_sock.connect
      rescue StandardError
        raw_sock.close
        raise
      end

      begin
        der_bytes = tls_sock.peer_cert&.to_der
        raise Error, 'peer presented no certificate' if der_bytes.nil?

        fp = leaf_public_key_fingerprint(der_bytes)
        expected_lower = expected_fingerprints.map(&:downcase)
        unless expected_lower.include?(fp.downcase)
          raise PinMismatch, "certificate fingerprint #{fp} does not match any expected fingerprint"
        end
      rescue StandardError
        tls_sock.close
        raise
      end

      tls_sock
    end
  end
end
