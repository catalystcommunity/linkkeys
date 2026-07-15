# frozen_string_literal: true

require 'openssl'
require 'digest'
require_relative 'timeutil'

module LinkkeysLocalRp
  # Crypto primitives for the local-RP SDK, backed entirely by the bundled
  # `openssl` gem (design doc's Ruby language-matrix row: `OpenSSL::PKey.
  # new_raw_private_key`/`new_raw_public_key` handle Ed25519/X25519 raw
  # bytes; `OpenSSL::Cipher` does AES-256-GCM and chacha20-poly1305; no
  # rbnacl — libsodium cannot do portable AES-256-GCM anyway, which is the
  # entire reason the design doc rules out a libsodium-centric route for
  # every language in this project). Verified directly against this
  # package's own conformance vectors (`callback_box.json`'s aes-256-gcm AND
  # chacha20-poly1305 positive cases both decrypt to the exact expected
  # plaintext under this module's HKDF/AEAD calls) before this module was
  # written out in full — see the implementation report for the probe.
  #
  # Every function here is pure: no I/O, no network, no filesystem, no
  # system clock reads (see `signing_key_validity`, which takes `now`
  # explicitly) — matching `liblinkkeys`'s own discipline.
  module Crypto
    ALGORITHM_ED25519 = 'ed25519'
    AEAD_SUITE_AES_256_GCM = 'aes-256-gcm'
    AEAD_SUITE_CHACHA20_POLY1305 = 'chacha20-poly1305'

    class Error < StandardError; end
    class SigningFailed < Error; end
    class VerificationFailed < Error; end

    class UnsupportedAlgorithm < Error
      attr_reader :algorithm

      def initialize(algorithm)
        @algorithm = algorithm
        super("unsupported algorithm: #{algorithm}")
      end
    end

    class EncryptionFailed < Error; end
    class DecryptionFailed < Error; end
    class InvalidKeyLength < Error; end

    # ---------------------------------------------------------------
    # Signing / AEAD suite registries
    # ---------------------------------------------------------------

    module SigningAlgorithm
      ED25519 = ALGORITHM_ED25519

      module_function

      def parse_str(s) = s == ED25519 ? ED25519 : nil
      def all_supported = [ED25519].freeze
    end

    module AeadSuite
      AES_256_GCM = AEAD_SUITE_AES_256_GCM
      CHACHA20_POLY1305 = AEAD_SUITE_CHACHA20_POLY1305
      ALL = [AES_256_GCM, CHACHA20_POLY1305].freeze

      module_function

      def parse_str(s) = ALL.include?(s) ? s : nil
      def all_supported = ALL

      # Pick the first suite in `advertised` (preference order) this
      # implementation supports. Used by whichever side chooses among an
      # advertised list, so a suite outside the advertised list can never be
      # selected.
      def select_supported(advertised)
        advertised.each do |s|
          suite = parse_str(s)
          return suite unless suite.nil?
        end
        nil
      end
    end

    module_function

    # Returns [public_key_bytes, private_key_bytes] -- private is the raw
    # 32-byte seed.
    def generate_ed25519_keypair
      pkey = OpenSSL::PKey.generate_key('ED25519')
      [pkey.raw_public_key, pkey.raw_private_key]
    end

    # Returns [public_key_bytes, private_key_bytes], both 32 bytes. A
    # dedicated encryption keypair -- NEVER derived from an Ed25519 signing
    # key (design doc: "Encryption Key Is Separate, Not Derived").
    def generate_x25519_keypair
      pkey = OpenSSL::PKey.generate_key('X25519')
      [pkey.raw_public_key, pkey.raw_private_key]
    end

    def sign_with_algorithm(algorithm, message, private_key_bytes)
      raise UnsupportedAlgorithm, algorithm unless algorithm == SigningAlgorithm::ED25519
      raise InvalidKeyLength, 'Ed25519 private key must be 32 bytes' unless private_key_bytes.bytesize == 32

      pkey = OpenSSL::PKey.new_raw_private_key('ED25519', private_key_bytes)
      pkey.sign(nil, message)
    rescue OpenSSL::PKey::PKeyError => e
      raise SigningFailed, e.message
    end

    # Raises VerificationFailed (or InvalidKeyLength) on failure; returns
    # nil on success.
    def verify_with_algorithm(algorithm, message, signature, public_key_bytes)
      raise UnsupportedAlgorithm, algorithm unless algorithm == SigningAlgorithm::ED25519
      raise InvalidKeyLength, 'Ed25519 public key must be 32 bytes' unless public_key_bytes.bytesize == 32

      pkey = OpenSSL::PKey.new_raw_public_key('ED25519', public_key_bytes)
      ok = pkey.verify(nil, signature, message)
      raise VerificationFailed, 'signature verification failed' unless ok

      nil
    rescue OpenSSL::PKey::PKeyError => e
      raise VerificationFailed, e.message
    end

    # Parse a wire-format algorithm string before verifying -- the entry
    # point for assertion/claim verification paths.
    def resolve_and_verify(algorithm, message, signature, public_key_bytes)
      alg = SigningAlgorithm.parse_str(algorithm)
      raise UnsupportedAlgorithm, algorithm if alg.nil?

      verify_with_algorithm(alg, message, signature, public_key_bytes)
    end

    # sha256(public_key_bytes) lowercase hex -- the canonical LinkKeys
    # fingerprint format used everywhere (DNS fp=, TLS SPKI pinning, local
    # RP identity).
    def fingerprint(public_key_bytes)
      Digest::SHA256.hexdigest(public_key_bytes)
    end

    module KeyValidity
      VALID = :valid
      REVOKED = :revoked
      EXPIRED = :expired
      BAD_EXPIRY = :bad_expiry
    end

    # `now` is an explicit Time (never read from the system clock in this
    # module, mirroring liblinkkeys's WASM-viable discipline).
    def signing_key_validity(expires_at, revoked_at, now)
      return KeyValidity::REVOKED unless revoked_at.nil?

      begin
        expires = Timeutil.parse_rfc3339(expires_at)
      rescue ArgumentError
        return KeyValidity::BAD_EXPIRY
      end
      now > expires ? KeyValidity::EXPIRED : KeyValidity::VALID
    end

    # Reject an all-zero ECDH output -- the signal a low-order/non-
    # contributory X25519 public key forces regardless of the other party's
    # private key.
    def reject_low_order(shared_secret)
      raise EncryptionFailed, 'non-contributory (low-order) public key rejected' if shared_secret == ("\x00" * 32).b
    end

    def aead_encrypt(suite, key, nonce, aad, plaintext)
      cipher = OpenSSL::Cipher.new(cipher_name_for(suite))
      cipher.encrypt
      cipher.key = key
      cipher.iv = nonce
      cipher.auth_data = aad
      ciphertext = cipher.update(plaintext) + cipher.final
      ciphertext + cipher.auth_tag
    rescue OpenSSL::Cipher::CipherError => e
      raise EncryptionFailed, e.message
    end

    def aead_decrypt(suite, key, nonce, aad, ciphertext)
      raise DecryptionFailed, 'ciphertext too short to contain an AEAD tag' if ciphertext.bytesize < 16

      tag = ciphertext.byteslice(-16, 16)
      body = ciphertext.byteslice(0, ciphertext.bytesize - 16)

      cipher = OpenSSL::Cipher.new(cipher_name_for(suite))
      cipher.decrypt
      cipher.key = key
      cipher.iv = nonce
      cipher.auth_tag = tag
      cipher.auth_data = aad
      cipher.update(body) + cipher.final
    rescue OpenSSL::Cipher::CipherError => e
      raise DecryptionFailed, "AEAD authentication failed: #{e.message}"
    end

    def cipher_name_for(suite)
      case suite
      when AeadSuite::AES_256_GCM then 'aes-256-gcm'
      when AeadSuite::CHACHA20_POLY1305 then 'chacha20-poly1305'
      else raise UnsupportedAlgorithm, suite.to_s
      end
    end
    private_class_method :cipher_name_for

    # Full HKDF-SHA256 (extract-then-expand), no salt. RFC 5869: an absent
    # salt is treated as a string of HashLen zero bytes; HMAC zero-pads a
    # short key up to the block size, so an empty-string salt and a
    # 32-byte-all-zero salt both reduce to the same 64-byte all-zero HMAC
    # key -- OpenSSL::KDF.hkdf(salt: '') therefore reproduces RFC 5869's
    # "no salt" behavior byte-for-byte (verified against
    # sdks/local-rp/conformance/callback_box.json's positive cases for both
    # suites before this module was written out).
    def hkdf_sha256_expand(shared_secret, info, length = 32)
      OpenSSL::KDF.hkdf(shared_secret, salt: '', info: info, length: length, hash: 'SHA256')
    end

    def x25519_diffie_hellman(private_key_bytes, peer_public_key_bytes)
      priv = OpenSSL::PKey.new_raw_private_key('X25519', private_key_bytes)
      pub = OpenSSL::PKey.new_raw_public_key('X25519', peer_public_key_bytes)
      priv.derive(pub)
    rescue OpenSSL::PKey::PKeyError => e
      # OpenSSL itself rejects an all-zero (low-order) peer public key at
      # derive() time on this platform's OpenSSL build -- translate to the
      # same EncryptionFailed a caller-side reject_low_order would raise, so
      # callers get one consistent error regardless of whether OpenSSL or
      # our own explicit zero-check caught it.
      raise EncryptionFailed, "X25519 key exchange failed (likely a low-order point): #{e.message}"
    end

    def x25519_public_from_private(private_key_bytes)
      priv = OpenSSL::PKey.new_raw_private_key('X25519', private_key_bytes)
      priv.raw_public_key
    end
  end
end
