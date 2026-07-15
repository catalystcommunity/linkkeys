defmodule LinkkeysLocalRp.Tls do
  @moduledoc """
  Client-side TLS pinning: verify a peer's certificate by its SPKI public
  key fingerprint against a DNS-published `fp=` set — no CA chain, matching
  the trust model `crates/linkkeys/src/tcp/tls.rs` uses for every LinkKeys
  TCP peer.

  Every LinkKeys domain TLS certificate is generated from an **Ed25519**
  domain signing key, and per RFC 8410 an Ed25519 SubjectPublicKeyInfo's
  `subjectPublicKey` BIT STRING contents ARE exactly the 32 raw public key
  bytes (no ASN.1 padding/framing inside the bit string). This module
  therefore only ever needs to handle Ed25519 leaf certificates.

  OTP's `:ssl` cannot express "verify only by SPKI pin, ignore
  WebPKI/hostname" as a single built-in verification mode, so this module
  connects with `verify: :verify_none` (skip the built-in chain/hostname
  checks entirely) and performs the pin check itself, manually, as a
  **mandatory** post-handshake step — the socket is closed and an error
  raised before a single application byte is trusted if the pin doesn't
  match.

  Certificate DER -> raw Ed25519 public key: `:public_key.der_decode(:Certificate,
  der)` (OTP's own compiled ASN.1 module for `:Certificate`) already
  decodes the `SubjectPublicKeyInfo.subjectPublicKey` BIT STRING straight
  to a 32-byte Erlang binary for a 0-unused-bits BIT STRING like an
  Ed25519 key — verified directly against an openssl-CLI-minted Ed25519
  cert (see the SDK README's "Ed25519-cert-with-:ssl outcome" section)
  rather than assumed.
  """

  alias LinkkeysLocalRp.Crypto

  @ed25519_oid {1, 3, 101, 112}

  defmodule TlsError do
    defexception [:message]
  end

  defmodule PinMismatch do
    defexception [:message]
  end

  defmodule UnsupportedCertificateKeyType do
    defexception [:message]
  end

  @doc "Split `host:port` into just the host part (used as the TLS SNI hostname)."
  def extract_hostname(host_port) do
    case String.split(host_port, ":") do
      [host] -> host
      parts -> parts |> Enum.slice(0..-2//1) |> Enum.join(":")
    end
  end

  @doc """
  Extract the raw 32-byte Ed25519 public key from a DER certificate and
  return its SHA-256 hex fingerprint — the same value
  `crates/linkkeys/src/tcp/tls.rs` computes from
  `spki.subject_public_key.data`. Raises `UnsupportedCertificateKeyType`
  for anything other than an Ed25519 leaf certificate.
  """
  def leaf_public_key_fingerprint(der_bytes) do
    cert = :public_key.der_decode(:Certificate, der_bytes)
    {:Certificate, tbs, _sig_alg, _sig} = cert
    {:TBSCertificate, _v, _serial, _sig, _issuer, _validity, _subject, spki, _iuid, _suid, _ext} = tbs
    {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, oid, _params}, public_key} = spki

    if oid != @ed25519_oid do
      raise UnsupportedCertificateKeyType,
        message: "expected an Ed25519 certificate public key, got OID #{inspect(oid)}"
    end

    if not is_binary(public_key) or byte_size(public_key) != 32 do
      raise UnsupportedCertificateKeyType,
        message: "Ed25519 SubjectPublicKeyInfo did not decode to a 32-byte raw key"
    end

    Crypto.fingerprint(public_key)
  rescue
    e in [UnsupportedCertificateKeyType] -> reraise e, __STACKTRACE__
    e -> reraise TlsError, [message: "peer certificate could not be parsed: #{Exception.message(e)}"], __STACKTRACE__
  end

  @doc """
  Wrap `raw_sock` (an already-connected, passive `:gen_tcp` socket) in a
  TLS client connection pinned to `expected_fingerprints`, presenting no
  client certificate (public domain-key/revocation fetch and ticket
  redemption must not require mutual TLS). Raises `PinMismatch` (and
  closes the socket) if the peer's certificate does not pin to any of
  `expected_fingerprints`.
  """
  def dial_tls_pinned(raw_sock, server_hostname, expected_fingerprints, timeout \\ 10_000) do
    tls_opts = [
      verify: :verify_none,
      server_name_indication: String.to_charlist(server_hostname),
      versions: [:"tlsv1.3", :"tlsv1.2"]
    ]

    case :ssl.connect(raw_sock, tls_opts, timeout) do
      {:ok, tls_sock} ->
        check_pin_and_maybe_close(tls_sock, expected_fingerprints)

      {:error, reason} ->
        :gen_tcp.close(raw_sock)
        raise TlsError, message: "TLS handshake failed: #{inspect(reason)}"
    end
  end

  defp check_pin_and_maybe_close(tls_sock, expected_fingerprints) do
    with {:ok, der} <- :ssl.peercert(tls_sock),
         fp = leaf_public_key_fingerprint(der),
         expected_lower = MapSet.new(Enum.map(expected_fingerprints, &String.downcase/1)),
         true <- MapSet.member?(expected_lower, String.downcase(fp)) do
      tls_sock
    else
      false ->
        :ssl.close(tls_sock)
        raise PinMismatch, message: "certificate fingerprint does not match any expected fingerprint"

      {:error, reason} ->
        :ssl.close(tls_sock)
        raise TlsError, message: "peer presented no usable certificate: #{inspect(reason)}"
    end
  rescue
    e in [UnsupportedCertificateKeyType, TlsError] ->
      :ssl.close(tls_sock)
      reraise e, __STACKTRACE__
  end
end
