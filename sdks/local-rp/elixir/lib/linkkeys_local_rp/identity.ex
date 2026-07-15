defmodule LinkkeysLocalRp.Identity do
  @moduledoc """
  `generate_local_rp_identity` and the raw-byte storage helpers (design
  doc: "SDK API Shape", "Byte Storage Helpers").

  A local RP identity is exactly one Ed25519 signing keypair, one X25519
  encryption keypair, and a self-signed `SignedLocalRpDescriptor` binding
  them together. There is no continuity story across rotation — generating
  a new identity means a new fingerprint, full stop.

  Security note (design doc, "Byte Storage Helpers"): the private key
  fields in `LocalRpKeyMaterial` do not directly identify a user, but they
  control this app's entire local RP identity — anyone holding them can
  sign login requests and redeem claim tickets as this app. Store them
  with ordinary application-secret care (the same care as a database
  credential or API key), not merely as configuration.
  """

  alias LinkkeysLocalRp.Crypto
  alias LinkkeysLocalRp.Dns
  alias LinkkeysLocalRp.LocalRp
  alias LinkkeysLocalRp.Timeutil
  alias LinkkeysLocalRp.Types

  # Default local RP key lifetime: 10 years (design doc, "One Signing Key
  # and One Encryption Key" — "Default lifetime: 10 years. Rotation is a
  # deliberate operator event.").
  @default_lifetime_days 3650
  def default_lifetime_days, do: @default_lifetime_days

  defmodule IdentityError do
    defexception [:message]
  end

  defmodule LocalRpKeyMaterial do
    @moduledoc """
    A local RP's full key material: signing keypair, encryption keypair,
    the self-signed descriptor binding them (which also carries
    `app_name`, `local_domain_hint`, `supported_suites`, and the
    created/expires timestamps), and the identity fingerprint.

    Private key fields are raw 32-byte values — see the module docs'
    security note before persisting them.
    """
    defstruct [
      :signing_private_key,
      :signing_public_key,
      :encryption_private_key,
      :encryption_public_key,
      :descriptor,
      :fingerprint
    ]
  end

  @doc """
  `generate_local_rp_identity(config) -> LocalRpKeyMaterial` (design doc,
  "SDK API Shape"). Generates a fresh Ed25519 signing keypair and a
  *separate* X25519 encryption keypair (never algebraically derived — see
  the design doc's "Encryption Key Is Separate, Not Derived"), builds and
  self-signs the `SignedLocalRpDescriptor` binding them, and returns
  everything the app needs to persist.

  `config` (keyword list or map):
  - `:app_name` (required)
  - `:now` (required, `DateTime.t()`)
  - `:local_domain_hint` (optional)
  - `:supported_suites` (optional, defaults to both registry suites)
  - `:lifetime_days` (optional, defaults to #{@default_lifetime_days})
  """
  def generate_local_rp_identity(config) do
    config = Map.new(config)
    app_name = Map.fetch!(config, :app_name)
    now = Map.fetch!(config, :now)

    if String.trim(app_name) == "" do
      raise IdentityError, message: "app_name must not be empty"
    end

    {signing_public_key, signing_private_key} = Crypto.generate_ed25519_keypair()
    {encryption_public_key, encryption_private_key} = Crypto.generate_x25519_keypair()

    suites = Map.get(config, :supported_suites) || Crypto.all_supported_suites()

    if suites == [] do
      raise IdentityError, message: "supported_suites must not be empty"
    end

    lifetime_days = Map.get(config, :lifetime_days) || @default_lifetime_days
    created_at = Timeutil.to_rfc3339(now)
    expires_at = Timeutil.to_rfc3339(DateTime.add(now, lifetime_days * 86_400, :second))

    descriptor =
      LocalRp.build_local_rp_descriptor(
        app_name,
        Map.get(config, :local_domain_hint),
        signing_public_key,
        encryption_public_key,
        suites,
        created_at,
        expires_at
      )

    fingerprint = descriptor.fingerprint
    signed_descriptor = LocalRp.sign_local_rp_descriptor(descriptor, signing_private_key)

    %LocalRpKeyMaterial{
      signing_private_key: signing_private_key,
      signing_public_key: signing_public_key,
      encryption_private_key: encryption_private_key,
      encryption_public_key: encryption_public_key,
      descriptor: signed_descriptor,
      fingerprint: fingerprint
    }
  end

  # -----------------------------------------------------------------
  # Byte storage helpers (design doc: "Byte Storage Helpers")
  # -----------------------------------------------------------------

  @doc "Raw 32-byte signing key (public or private) -> bytes. Trivial, but provided so callers never invent their own encoding."
  def signing_key_to_bytes(key), do: key

  def signing_key_from_bytes(data) when byte_size(data) == 32, do: data

  def signing_key_from_bytes(data),
    do: raise(IdentityError, message: "signing key must be 32 bytes, got #{byte_size(data)}")

  def encryption_key_to_bytes(key), do: key

  def encryption_key_from_bytes(data) when byte_size(data) == 32, do: data

  def encryption_key_from_bytes(data),
    do: raise(IdentityError, message: "encryption key must be 32 bytes, got #{byte_size(data)}")

  @doc "The canonical fingerprint string form — a pass-through, since in this SDK the fingerprint IS a hex string already."
  def fingerprint_to_string(fp), do: fp

  @doc "Parse/validate a fingerprint string: exactly 64 lowercase-normalized hex characters (a SHA-256 digest). Rejects anything else."
  def fingerprint_from_string(s) do
    if Dns.valid_fingerprint?(s),
      do: String.downcase(s),
      else: raise(IdentityError, message: "not a valid fingerprint (want 64 hex chars): #{inspect(s)}")
  end

  # Magic prefix for the identity-bundle byte format below. This is an
  # SDK-local storage convenience, NOT a protocol wire format — nothing in
  # the design doc's Wire Precision governs it, and no conformance vector
  # covers it. Versioned so a future incompatible layout change fails
  # loudly instead of silently misparsing.
  @identity_bundle_magic "LKI1"

  @doc """
  `local_rp_identity_to_bytes(identity) -> bytes` (design doc, "SDK API
  Shape" + "Byte Storage Helpers": "identity bundle"). Packs both private
  keys and the signed descriptor (which already carries both public keys,
  `app_name`, `local_domain_hint`, `supported_suites`, and the
  created/expires timestamps) into one opaque blob an app can store as a
  single secret/config value. Layout: `MAGIC(4) ||
  signing_private_key(32) || encryption_private_key(32) ||
  descriptor_len(4, BE) || descriptor_cbor`.
  """
  def local_rp_identity_to_bytes(%LocalRpKeyMaterial{} = identity) do
    descriptor_bytes = Types.signed_local_rp_descriptor_to_cbor(identity.descriptor)

    @identity_bundle_magic <>
      identity.signing_private_key <>
      identity.encryption_private_key <>
      <<byte_size(descriptor_bytes)::32>> <>
      descriptor_bytes
  end

  @doc "The inverse of `local_rp_identity_to_bytes/1`. Public keys and the fingerprint are read back out of the embedded descriptor rather than re-derived from the private keys, exactly mirroring what was stored; this function does no signature/expiry verification (that is `check_expirations/2`'s and the protocol verification chain's job)."
  def local_rp_identity_from_bytes(data) do
    header_len = 4 + 32 + 32 + 4

    if byte_size(data) < header_len do
      raise IdentityError, message: "identity bundle too short"
    end

    <<magic::binary-size(4), signing_private_key::binary-size(32), encryption_private_key::binary-size(32),
      descriptor_len::32, rest::binary>> = data

    if magic != @identity_bundle_magic do
      raise IdentityError, message: "identity bundle has an unrecognized magic prefix"
    end

    if byte_size(rest) < descriptor_len do
      raise IdentityError, message: "identity bundle descriptor length exceeds available bytes"
    end

    descriptor_bytes = binary_part(rest, 0, descriptor_len)

    signed_descriptor =
      try do
        Types.signed_local_rp_descriptor_from_cbor(descriptor_bytes)
      rescue
        e -> reraise IdentityError, [message: "identity bundle descriptor: #{Exception.message(e)}"], __STACKTRACE__
      end

    descriptor =
      try do
        Types.local_rp_descriptor_from_cbor(signed_descriptor.descriptor)
      rescue
        e ->
          reraise IdentityError,
                  [message: "identity bundle descriptor payload: #{Exception.message(e)}"],
                  __STACKTRACE__
      end

    if byte_size(descriptor.signing_public_key) != 32 do
      raise IdentityError, message: "descriptor signing_public_key was not 32 bytes"
    end

    if byte_size(descriptor.encryption_public_key) != 32 do
      raise IdentityError, message: "descriptor encryption_public_key was not 32 bytes"
    end

    %LocalRpKeyMaterial{
      signing_private_key: signing_private_key,
      signing_public_key: descriptor.signing_public_key,
      encryption_private_key: encryption_private_key,
      encryption_public_key: descriptor.encryption_public_key,
      descriptor: signed_descriptor,
      fingerprint: descriptor.fingerprint
    }
  end

  @doc """
  `check_expirations(identity, now) -> ExpirationStatus` (design doc,
  "SDK API Shape" / "Expiration Helper"). Thin wrapper taking the
  identity's descriptor `expires_at` directly. The SDK reports facts; the
  app decides whether to warn admins, warn users, block login, renew, or
  ignore.
  """
  def check_expirations(%LocalRpKeyMaterial{} = identity, %DateTime{} = now) do
    descriptor = Types.local_rp_descriptor_from_cbor(identity.descriptor.descriptor)
    {:ok, status} = LocalRp.check_expirations(descriptor.expires_at, now)
    status
  end

  @doc "The descriptor payload (decoded) belonging to `identity` — convenience accessor so callers don't need to know the envelope encoding to read metadata like `app_name`."
  def descriptor(%LocalRpKeyMaterial{} = identity),
    do: Types.local_rp_descriptor_from_cbor(identity.descriptor.descriptor)
end
