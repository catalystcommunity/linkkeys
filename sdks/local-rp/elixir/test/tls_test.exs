defmodule LinkkeysLocalRp.TlsTest do
  @moduledoc """
  Unit tests for `LinkkeysLocalRp.Tls`'s certificate-DER pin-extraction
  logic (`leaf_public_key_fingerprint/1`), directly against real
  `openssl`-minted certificate bytes — independent of `openssl` (or any
  network/TLS handshake) being available at TEST time.

  This file exists to close a coverage gap the security review flagged:
  `test/flow_test.exs` is the only place `LinkkeysLocalRp.Tls`'s pin
  checking was exercised, and that whole file (including its own
  `openssl`-minted fake-IDP certificate) is skipped outright when
  `openssl` isn't on `PATH` — leaving zero coverage of the single most
  pitfall-prone check in this SDK (a wrong TLS pin silently accepting an
  attacker's certificate) on any box without the CLI installed.
  `flow_test.exs`'s own moduledoc has referenced this file (`test/tls_test.exs`)
  since it was written; this is that file.

  Mirrors `sdks/local-rp/dart/test/tls_pinning_test.dart`'s approach (the
  sibling SDK that hit the same "can't drive a live Ed25519 TLS handshake
  in every environment" problem): feed real `openssl`-minted certificate
  DER bytes, captured once and hardcoded below as fixed test-only
  artifacts, directly into the pin-extraction function under test — the
  same function the live handshake path in `LinkkeysLocalRp.Rpc`/`Tls`
  calls post-handshake in production — so the ASN.1 walk and
  SPKI-fingerprint logic are verified against real certificate bytes, not
  synthetic ones, with no live server and no `openssl` invocation at test
  time.

  Fixture provenance (fixed test-only artifacts, not protocol conformance
  vectors — no vector for TLS certificate parsing exists in
  `sdks/local-rp/conformance/`, since certificate minting is outside
  liblinkkeys' scope):

  ```sh
  # Ed25519 key from the fixed 32-byte seed 0x09 repeated (RFC 8410 PKCS8
  # DER wrapper — same construction flow_test.exs uses for its own fake-IDP
  # cert, see its `pkcs8_der_from_seed/1`), then a self-signed cert from it:
  openssl pkey -inform DER -in edkey.der -out edkey.pem
  openssl req -new -x509 -key edkey.pem -days 3650 -subj "/CN=fixture.test" \\
    -outform DER -out edcert.der -set_serial 1234567890

  # An RSA cert, to exercise the "wrong key type" rejection path:
  openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out rsakey.pem
  openssl req -new -x509 -key rsakey.pem -days 3650 -subj "/CN=fixture.test" \\
    -outform DER -out rsacert.der
  ```

  then hex-encoding each DER file's raw bytes.
  """

  use ExUnit.Case, async: true

  alias LinkkeysLocalRp.Crypto
  alias LinkkeysLocalRp.Tls
  alias LinkkeysLocalRp.Tls.TlsError
  alias LinkkeysLocalRp.Tls.UnsupportedCertificateKeyType

  # The fixed 32-byte seed the Ed25519 fixture certificate below was minted
  # from (`0x09` repeated) — kept here so this test can independently
  # derive the expected public key/fingerprint via this SDK's own
  # `:crypto`-backed routines (`Crypto.ed25519_public_from_private/1` +
  # `Crypto.fingerprint/1`), never by trusting a second hardcoded fingerprint
  # constant that could silently drift from the cert fixture.
  @ed25519_seed :binary.copy(<<9>>, 32)

  @ed_cert_der_hex "308201323081e5a0030201020204499602d2300506032b657030173115301306035504030c0c" <>
                     "666978747572652e74657374301e170d3236303731353031343235315a170d3336303731323031" <>
                     "343235315a30173115301306035504030c0c666978747572652e74657374302a300506032b6570" <>
                     "032100fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618a3533051" <>
                     "301d0603551d0e041604145e0745472180b1ac3bff7211f846536ce6c90a94301f0603551d2304" <>
                     "18301680145e0745472180b1ac3bff7211f846536ce6c90a94300f0603551d130101ff04053003" <>
                     "0101ff300506032b65700341007d2a54bfeeff999f2a8d101f1a6c70e661e9bf79d266ea81ada4" <>
                     "fb99de5dc673d22ad6b438f9ee23abd7b4fd91f000451e53077e910f8f5d4e28e5236676730f"

  @rsa_cert_der_hex "3082030f308201f7a00302010202141011b62e2525435ce8abc1b785d9828f8e6bdf66300d06" <>
                      "092a864886f70d01010b050030173115301306035504030c0c666978747572652e7465737430" <>
                      "1e170d3236303731353031343235365a170d3336303731323031343235365a30173115301306" <>
                      "035504030c0c666978747572652e7465737430820122300d06092a864886f70d010101050003" <>
                      "82010f003082010a0282010100a397e02ff26fc6ba25d64c77b7e37e0a9b4666d308472f66f76" <>
                      "c99a6beef321d330400d72aae8bfb667b1740fedb7efe9d0efe102fbeaeb9f399d5619de2873d" <>
                      "3d8c54ce8391119b75fc9ba360062a5e21737b98e9c7e547cc16e7790ecbf1d93b4f8423af40a" <>
                      "5e9e4d1ebb0f198788d25df128a35b0597dcb443b674b31c2082ed3c3defeb9d3bad42505971b" <>
                      "da4b4e08741707fba70dc7156ad958729890d3d4d8a8a924ed7caa191822fb8b428d25b4cf1c7" <>
                      "bd8441b2bb3f0d802c03fc3ffffd18fee530dfb44ab175588740fbc8dba5c9f8bbeff522408f2" <>
                      "676991b960e7c72108d6a5ad7c3d6bacbc6bd113341af00eda6eb032f40c310b22c0921de1f10" <>
                      "203010001a3533051301d0603551d0e041604149dc63a5227b2b9d763255e5bc5ec3cafe48533" <>
                      "77301f0603551d230418301680149dc63a5227b2b9d763255e5bc5ec3cafe4853377300f0603" <>
                      "551d130101ff040530030101ff300d06092a864886f70d01010b050003820101004bdb87097bb" <>
                      "08e6fad82339590196a9c246e58468b0454d52eb3897d53d6a204a8840ceea9e44609700866c5" <>
                      "0877efe2994096e48b6c1739e9ca28bf08aef381ed639601f514453e0f14c81ed616e35136e14" <>
                      "cc17e94a6ad6cb7c9ed09fe7fc43d2ebd6103ad552b39bbd988b7d4a7fc8b944188e861d9e40f1" <>
                      "cf9f12e7f735a6815f15e4cbc646211e0ae422d4626facbba9d9cfb0db8d5d8be384eac57aadca" <>
                      "01bcca573db63eed0121f6212c08c888ff391d4e83a29a11e89aa21fc3f8b9dc0db5eaec70fc1c" <>
                      "538fe781978b05d300f1528c17726ef4adeac3844cc9b30332bcce79b333867f2721d7eca46c8" <>
                      "202051d80addcfe510d6c6f72e4c478c388a"

  defp ed_cert_der, do: Base.decode16!(@ed_cert_der_hex, case: :lower)
  defp rsa_cert_der, do: Base.decode16!(@rsa_cert_der_hex, case: :lower)

  describe "leaf_public_key_fingerprint/1 against a real Ed25519 certificate" do
    test "extracts the fingerprint of the certificate's own signing key" do
      expected_public_key = Crypto.ed25519_public_from_private(@ed25519_seed)
      expected_fingerprint = Crypto.fingerprint(expected_public_key)

      assert Tls.leaf_public_key_fingerprint(ed_cert_der()) == expected_fingerprint
      assert byte_size(expected_fingerprint) == 64
    end

    test "is deterministic across repeated calls" do
      der = ed_cert_der()
      assert Tls.leaf_public_key_fingerprint(der) == Tls.leaf_public_key_fingerprint(der)
    end
  end

  describe "leaf_public_key_fingerprint/1 rejects non-Ed25519 / malformed input" do
    test "raises UnsupportedCertificateKeyType for an RSA certificate" do
      assert_raise UnsupportedCertificateKeyType, fn ->
        Tls.leaf_public_key_fingerprint(rsa_cert_der())
      end
    end

    test "raises TlsError for truncated DER" do
      der = ed_cert_der()
      truncated = binary_part(der, 0, div(byte_size(der), 2))

      assert_raise TlsError, fn ->
        Tls.leaf_public_key_fingerprint(truncated)
      end
    end

    test "raises TlsError for garbage input" do
      assert_raise TlsError, fn ->
        Tls.leaf_public_key_fingerprint(:binary.copy(<<0xFF>>, 64))
      end
    end

    test "raises UnsupportedCertificateKeyType when the BIT STRING unused-bits framing byte is corrupted" do
      # Flips the byte immediately preceding the raw 32-byte Ed25519 key
      # inside the SubjectPublicKeyInfo BIT STRING (its "unused bits count",
      # always 0 for a byte-aligned key) -- this reshapes what OTP's ASN.1
      # decoder returns for that field, and the resulting value is no
      # longer a bare 32-byte binary. Proves the pin-extraction logic
      # actually validates the decoded key's shape rather than assuming it.
      der = ed_cert_der()
      public_key = Crypto.ed25519_public_from_private(@ed25519_seed)
      {key_offset, _len} = :binary.match(der, public_key)
      flip_offset = key_offset - 1

      <<prefix::binary-size(^flip_offset), byte, rest::binary>> = der
      corrupted = <<prefix::binary, Bitwise.bxor(byte, 0xFF), rest::binary>>

      assert_raise UnsupportedCertificateKeyType, fn ->
        Tls.leaf_public_key_fingerprint(corrupted)
      end
    end
  end

  describe "extract_hostname/1" do
    test "splits host:port" do
      assert Tls.extract_hostname("example.test:4987") == "example.test"
    end

    test "splits an IPv4 literal:port" do
      assert Tls.extract_hostname("127.0.0.1:4987") == "127.0.0.1"
    end

    test "passes through a bare host with no port" do
      assert Tls.extract_hostname("example.test") == "example.test"
    end
  end
end
