defmodule LinkkeysLocalRp.Crypto do
  @moduledoc """
  Ed25519 / X25519 / AEAD / HKDF / fingerprint primitives over Erlang/OTP's
  stdlib `:crypto` — no hex dependency (design doc's Elixir language-matrix
  row: `:eddsa` for Ed25519, `:ecdh` with `:x25519` for X25519,
  `:crypto_one_time_aead` for `aes_256_gcm`/`chacha20_poly1305`, HKDF
  hand-rolled over `:crypto.mac(:hmac, :sha256, ...)`).

  Every call signature here was probed against OTP 29 and cross-checked
  against `sdks/local-rp/conformance/keys.json` / `envelopes.json` /
  `callback_box.json` before being relied on (see the SDK README's "Crypto
  probe results" section). Notably: `:crypto.compute_key(:ecdh, <<0::256>>,
  priv, :x25519)` (the all-zero / low-order public key case) does not
  return an all-zero shared secret on this OTP — it *raises* an
  `ErlangError` from the underlying `EVP_PKEY_derive` call. `x25519_dh/2`
  below normalizes both possible outcomes (a raised error, or — for other
  low-order points OpenSSL might not reject at the EVP layer — an
  all-zero result) into the same `{:error, :low_order_key}` return.
  """

  @aead_suite_aes_256_gcm "aes-256-gcm"
  @aead_suite_chacha20_poly1305 "chacha20-poly1305"
  @algorithm_ed25519 "ed25519"

  def aead_suite_aes_256_gcm, do: @aead_suite_aes_256_gcm
  def aead_suite_chacha20_poly1305, do: @aead_suite_chacha20_poly1305
  def algorithm_ed25519, do: @algorithm_ed25519

  @doc "All AEAD suite ids this SDK supports, in preference order."
  def all_supported_suites, do: [@aead_suite_aes_256_gcm, @aead_suite_chacha20_poly1305]

  @doc "Parse a wire suite id string; returns nil for anything outside the registry (never case-folded, never 'close enough')."
  def parse_suite(@aead_suite_aes_256_gcm), do: @aead_suite_aes_256_gcm
  def parse_suite(@aead_suite_chacha20_poly1305), do: @aead_suite_chacha20_poly1305
  def parse_suite(_), do: nil

  @doc "Pick the first suite in `advertised` (preference order) that is a registry member. Used so a suite outside the advertised list can never be selected."
  def select_supported_suite(advertised) when is_list(advertised) do
    Enum.find_value(advertised, fn s -> parse_suite(s) end)
  end

  @doc "sha256(public_key_bytes) lowercase hex — the canonical LinkKeys fingerprint format."
  def fingerprint(public_key_bytes) when is_binary(public_key_bytes) do
    :crypto.hash(:sha256, public_key_bytes) |> Base.encode16(case: :lower)
  end

  @doc "Generate a fresh Ed25519 keypair. Returns {public_key_32, private_seed_32}."
  def generate_ed25519_keypair do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    {pub, priv}
  end

  @doc "Generate a fresh X25519 keypair. Returns {public_key_32, private_key_32}."
  def generate_x25519_keypair do
    {pub, priv} = :crypto.generate_key(:ecdh, :x25519)
    {pub, priv}
  end

  @doc "Sign `message` with an Ed25519 private key (32-byte seed)."
  def ed25519_sign(message, private_key) when byte_size(private_key) == 32 do
    :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
  end

  @doc "Verify an Ed25519 signature. Returns boolean, never raises."
  def ed25519_verify(message, signature, public_key) when byte_size(public_key) == 32 do
    try do
      :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])
    rescue
      _ -> false
    catch
      _, _ -> false
    end
  end

  def ed25519_verify(_message, _signature, _public_key), do: false

  @doc "Derive an Ed25519 public key from a private key (32-byte seed). Used to reconstruct a keypair from a stored/fixed seed without generating a fresh random one."
  def ed25519_public_from_private(seed) when byte_size(seed) == 32 do
    {pub, _priv} = :crypto.generate_key(:eddsa, :ed25519, seed)
    pub
  end

  @doc "Derive an X25519 public key from a private key."
  def x25519_public_from_private(private_key) when byte_size(private_key) == 32 do
    {pub, _priv} = :crypto.generate_key(:ecdh, :x25519, private_key)
    pub
  end

  @doc """
  X25519 Diffie-Hellman. Returns `{:ok, shared_secret_32}` or
  `{:error, :low_order_key}` for an all-zero / non-contributory peer public
  key — this rejection happens BEFORE any AEAD key derivation, per the
  design doc's Wire Precision ("reject an all-zero shared secret").
  """
  def x25519_dh(private_key, peer_public_key)
      when byte_size(private_key) == 32 and byte_size(peer_public_key) == 32 do
    try do
      case :crypto.compute_key(:ecdh, peer_public_key, private_key, :x25519) do
        <<0::256>> -> {:error, :low_order_key}
        shared -> {:ok, shared}
      end
    rescue
      _ -> {:error, :low_order_key}
    catch
      _, _ -> {:error, :low_order_key}
    end
  end

  @doc "HKDF-SHA256 extract-then-expand, salt = none (RFC 5869 defaults an absent salt to a zero-filled block)."
  def hkdf_sha256_expand(shared_secret, info, length \\ 32) do
    prk = :crypto.mac(:hmac, :sha256, <<>>, shared_secret)
    hkdf_expand(prk, info, length)
  end

  defp hkdf_expand(prk, info, length), do: do_expand(prk, info, length, 1, <<>>, <<>>)

  defp do_expand(_prk, _info, length, _i, _prev, acc) when byte_size(acc) >= length,
    do: binary_part(acc, 0, length)

  defp do_expand(prk, info, length, i, prev, acc) do
    block = :crypto.mac(:hmac, :sha256, prk, prev <> info <> <<i>>)
    do_expand(prk, info, length, i + 1, block, acc <> block)
  end

  @doc """
  AEAD encrypt. `suite` is `"aes-256-gcm"` or `"chacha20-poly1305"`.
  Returns ciphertext with the 16-byte auth tag appended (matching the
  RustCrypto `aes-gcm`/`chacha20poly1305` crates' output shape the
  conformance vectors were generated against).
  """
  def aead_encrypt(suite, key, nonce, aad, plaintext) do
    erlang_cipher = suite_to_erlang_cipher!(suite)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(erlang_cipher, key, nonce, plaintext, aad, true)
    ciphertext <> tag
  end

  @doc "AEAD decrypt. Returns `{:ok, plaintext}` or `{:error, :decryption_failed}` — never raises on a bad tag."
  def aead_decrypt(suite, key, nonce, aad, ciphertext_and_tag) when byte_size(ciphertext_and_tag) >= 16 do
    erlang_cipher = suite_to_erlang_cipher!(suite)
    tag_len = 16
    ct_len = byte_size(ciphertext_and_tag) - tag_len
    <<ct::binary-size(^ct_len), tag::binary-size(^tag_len)>> = ciphertext_and_tag

    case :crypto.crypto_one_time_aead(erlang_cipher, key, nonce, ct, aad, tag, false) do
      :error -> {:error, :decryption_failed}
      plaintext when is_binary(plaintext) -> {:ok, plaintext}
    end
  rescue
    _ -> {:error, :decryption_failed}
  end

  def aead_decrypt(_suite, _key, _nonce, _aad, _too_short), do: {:error, :decryption_failed}

  defp suite_to_erlang_cipher!(@aead_suite_aes_256_gcm), do: :aes_256_gcm
  defp suite_to_erlang_cipher!(@aead_suite_chacha20_poly1305), do: :chacha20_poly1305
  defp suite_to_erlang_cipher!(other), do: raise(ArgumentError, "unsupported AEAD suite: #{inspect(other)}")

  @doc """
  `sha256(bytes)` — used to hash a claim ticket the same way a key is
  fingerprinted (same routine as `fingerprint/1`, kept as a synonym for
  readability at call sites that hash a ticket rather than a key).
  """
  def sha256_hex(bytes), do: fingerprint(bytes)

  @doc """
  Constant-time byte-string equality, hand-rolled over `:erlang`/`Bitwise`
  (this package has zero hex dependencies, so `Plug.Crypto.secure_compare/2`
  isn't available). Used wherever a security-relevant decision compares two
  attacker-influenceable byte strings (e.g. `LocalRp.verify_nonce_state/4`'s
  nonce/state check) so the comparison never leaks, via wall-clock timing,
  how many leading bytes of a guess happened to match.

  Every byte pair is XORed and OR-accumulated across the *entire* length —
  deliberately never a `cond`/`case`/early `{:halt, ...}` that stops as soon
  as a mismatch is found, since that shape is exactly what turns an
  equality check into a timing oracle. Returns `false` immediately for a
  length mismatch: the values this SDK compares this way are always
  fixed-size (32-byte nonce/state), so leaking that a wrong-length value
  was even wrong-length carries no exploitable information.
  """
  @spec constant_time_equal?(binary, binary) :: boolean
  def constant_time_equal?(a, b) when is_binary(a) and is_binary(b) do
    if byte_size(a) != byte_size(b) do
      false
    else
      diff =
        0..(byte_size(a) - 1)
        |> Enum.reduce(0, fn i, acc ->
          Bitwise.bor(acc, Bitwise.bxor(:binary.at(a, i), :binary.at(b, i)))
        end)

      diff == 0
    end
  end
end
