# frozen_string_literal: true

require_relative 'crypto'
require_relative 'local_rp'
require_relative 'timeutil'
require_relative 'dns'
require_relative 'types'

module LinkkeysLocalRp
  # `generate_local_rp_identity` and the raw-byte storage helpers (design
  # doc: "SDK API Shape", "Byte Storage Helpers").
  #
  # A local RP identity is exactly one Ed25519 signing keypair, one X25519
  # encryption keypair, and a self-signed SignedLocalRpDescriptor binding
  # them together. There is no continuity story across rotation --
  # generating a new identity means a new fingerprint, full stop.
  #
  # Security note (design doc, "Byte Storage Helpers"): the private key
  # fields in LocalRpKeyMaterial do not directly identify a user, but they
  # control this app's entire local RP identity -- anyone holding them can
  # sign login requests and redeem claim tickets as this app. Store them
  # with ordinary application-secret care (the same care as a database
  # credential or API key), not merely as configuration.
  module Identity
    # Default local RP key lifetime: 10 years (design doc, "One Signing Key
    # and One Encryption Key").
    DEFAULT_LIFETIME = 3650 * 86_400

    class Error < StandardError; end

    # Input to generate_local_rp_identity. Big-config, single struct, per
    # the design doc's "SDK API Shape".
    GenerateLocalRpIdentityConfig = Struct.new(
      :app_name, :now, :local_domain_hint, :supported_suites, :lifetime,
      keyword_init: true
    )

    # A local RP's full key material: signing keypair, encryption keypair,
    # the self-signed descriptor binding them (which also carries app_name,
    # local_domain_hint, supported_suites, and the created/expires
    # timestamps), and the identity fingerprint.
    #
    # Private key fields are raw 32-byte values -- see the module docs'
    # security note before persisting them.
    LocalRpKeyMaterial = Struct.new(
      :signing_private_key, :signing_public_key,
      :encryption_private_key, :encryption_public_key,
      :descriptor, :fingerprint,
      keyword_init: true
    )

    module_function

    # `generate_local_rp_identity(config) -> LocalRpKeyMaterial` (design
    # doc, "SDK API Shape"). Generates a fresh Ed25519 signing keypair and a
    # SEPARATE X25519 encryption keypair (never algebraically derived --
    # design doc's "Encryption Key Is Separate, Not Derived"), builds and
    # self-signs the SignedLocalRpDescriptor binding them, and returns
    # everything the app needs to persist.
    def generate_local_rp_identity(config)
      raise Error, 'app_name must not be empty' if config.app_name.nil? || config.app_name.strip.empty?

      signing_public_key, signing_private_key = Crypto.generate_ed25519_keypair
      encryption_public_key, encryption_private_key = Crypto.generate_x25519_keypair

      suites = config.supported_suites || Crypto::AeadSuite.all_supported
      raise Error, 'supported_suites must not be empty' if suites.empty?

      lifetime = config.lifetime || DEFAULT_LIFETIME
      created_at = Timeutil.to_rfc3339(config.now)
      expires_at = Timeutil.to_rfc3339(config.now + lifetime)

      descriptor = LocalRp.build_local_rp_descriptor(
        config.app_name, config.local_domain_hint, signing_public_key, encryption_public_key,
        suites.dup, created_at, expires_at
      )
      fingerprint = descriptor.fingerprint
      signed_descriptor = LocalRp.sign_local_rp_descriptor(descriptor, signing_private_key)

      LocalRpKeyMaterial.new(
        signing_private_key: signing_private_key,
        signing_public_key: signing_public_key,
        encryption_private_key: encryption_private_key,
        encryption_public_key: encryption_public_key,
        descriptor: signed_descriptor,
        fingerprint: fingerprint
      )
    end

    # ---------------------------------------------------------------
    # Byte storage helpers (design doc: "Byte Storage Helpers")
    # ---------------------------------------------------------------

    def signing_key_to_bytes(key) = key.dup

    def signing_key_from_bytes(data)
      raise Error, "signing key must be 32 bytes, got #{data.bytesize}" unless data.bytesize == 32

      data.dup
    end

    def encryption_key_to_bytes(key) = key.dup

    def encryption_key_from_bytes(data)
      raise Error, "encryption key must be 32 bytes, got #{data.bytesize}" unless data.bytesize == 32

      data.dup
    end

    # The canonical fingerprint string form -- a pass-through, since in
    # this SDK the fingerprint IS a hex string already.
    def fingerprint_to_string(fp) = fp

    # Parse/validate a fingerprint string: exactly 64 lowercase-normalized
    # hex characters (a SHA-256 digest). Rejects anything else so a
    # malformed value can never silently pass as a pin or an identity.
    def fingerprint_from_string(str)
      return str.downcase if Dns.valid_fingerprint?(str)

      raise Error, "not a valid fingerprint (want 64 hex chars): #{str.inspect}"
    end

    # Magic prefix for the identity-bundle byte format below. This is an
    # SDK-local storage convenience, NOT a protocol wire format -- nothing
    # in the design doc's Wire Precision governs it, and no conformance
    # vector covers it. Versioned so a future incompatible layout change
    # fails loudly instead of silently misparsing.
    IDENTITY_BUNDLE_MAGIC = 'LKI1'.b

    # `local_rp_identity_to_bytes(identity) -> bytes` (design doc, "SDK API
    # Shape" + "Byte Storage Helpers": "identity bundle"). Packs both
    # private keys and the signed descriptor (which already carries both
    # public keys, app_name, local_domain_hint, supported_suites, and the
    # created/expires timestamps) into one opaque blob an app can store as
    # a single secret/config value. Layout: MAGIC(4) ||
    # signing_private_key(32) || encryption_private_key(32) ||
    # descriptor_len(4, BE) || descriptor_cbor.
    def local_rp_identity_to_bytes(identity)
      descriptor_bytes = identity.descriptor.to_cbor
      out = IDENTITY_BUNDLE_MAGIC.dup
      out << identity.signing_private_key
      out << identity.encryption_private_key
      out << [descriptor_bytes.bytesize].pack('N')
      out << descriptor_bytes
      out
    end

    # The inverse of local_rp_identity_to_bytes. Public keys and the
    # fingerprint are read back out of the embedded descriptor rather than
    # re-derived from the private keys, exactly mirroring what was stored;
    # this function does no signature/expiry verification (that is
    # check_expirations's and the protocol verification chain's job).
    def local_rp_identity_from_bytes(data)
      header_len = 4 + 32 + 32 + 4
      raise Error, 'identity bundle too short' if data.bytesize < header_len
      raise Error, 'identity bundle has an unrecognized magic prefix' unless data.byteslice(0, 4) == IDENTITY_BUNDLE_MAGIC

      signing_private_key = data.byteslice(4, 32)
      encryption_private_key = data.byteslice(36, 32)
      descriptor_len = data.byteslice(68, 4).unpack1('N')
      descriptor_bytes = data.byteslice(header_len, descriptor_len)
      if descriptor_bytes.nil? || descriptor_bytes.bytesize != descriptor_len
        raise Error, 'identity bundle descriptor length exceeds available bytes'
      end

      signed_descriptor =
        begin
          Types::SignedLocalRpDescriptor.from_cbor(descriptor_bytes)
        rescue StandardError => e
          raise Error, "identity bundle descriptor: #{e.message}"
        end

      descriptor =
        begin
          Types::LocalRpDescriptor.from_cbor(signed_descriptor.descriptor)
        rescue StandardError => e
          raise Error, "identity bundle descriptor payload: #{e.message}"
        end

      raise Error, 'descriptor signing_public_key was not 32 bytes' unless descriptor.signing_public_key.bytesize == 32
      raise Error, 'descriptor encryption_public_key was not 32 bytes' unless descriptor.encryption_public_key.bytesize == 32

      LocalRpKeyMaterial.new(
        signing_private_key: signing_private_key.dup,
        signing_public_key: descriptor.signing_public_key.dup,
        encryption_private_key: encryption_private_key.dup,
        encryption_public_key: descriptor.encryption_public_key.dup,
        descriptor: signed_descriptor,
        fingerprint: descriptor.fingerprint
      )
    end
  end
end
