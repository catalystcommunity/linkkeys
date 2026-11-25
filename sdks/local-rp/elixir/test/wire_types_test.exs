defmodule LinkkeysLocalRp.WireTypesTest do
  @moduledoc """
  CSIL `timestamp` fields are CBOR tag 0 + RFC 3339 UTC text, and closed
  vocabularies are named-number enums (CBOR unsigned integers). The
  conformance vectors cover the positive encodings; these tests cover the
  rejections.
  """
  use ExUnit.Case, async: true

  alias LinkkeysLocalRp.Cbor
  alias LinkkeysLocalRp.Test.Vectors
  alias LinkkeysLocalRp.Timeutil
  alias LinkkeysLocalRp.Types

  @claims Vectors.load("claims.json")

  defp claim_tree do
    @claims["cases"] |> hd() |> Map.fetch!("claim_cbor_hex") |> Vectors.hex() |> Cbor.decode()
  end

  test "a timestamp encodes as tag 0 wrapping UTC text with a Z suffix" do
    {:ok, dt, _} = DateTime.from_iso8601("2026-01-01T02:00:00+02:00")
    assert Cbor.encode(Timeutil.to_wire(dt)) == <<0xC0, 0x74>> <> "2026-01-01T00:00:00Z"
  end

  test "a timestamp without tag 0 is rejected" do
    tree = Map.put(claim_tree(), "attested_at", "2026-01-01T00:00:00Z")
    assert_raise ArgumentError, fn -> Types.claim_from_cbor(Cbor.encode(tree)) end

    tree = Map.put(claim_tree(), "attested_at", %Cbor.Tag{tag: 1, value: 1_767_225_600})
    assert_raise ArgumentError, fn -> Types.claim_from_cbor(Cbor.encode(tree)) end
  end

  test "timestamp decode round-trips the claim vector byte-exact" do
    wire = Cbor.encode(claim_tree())
    assert Types.claim_to_cbor(Types.claim_from_cbor(wire)) == wire
  end

  test "signed seconds refuse a fraction of a second" do
    assert {:ok, 1_767_225_600} == Timeutil.signed_seconds(~U[2026-01-01 00:00:00Z])
    assert :error == Timeutil.signed_seconds(~U[2026-01-01 00:00:00.5Z])
  end

  test "AeadSuite, KeyAlgorithm and KeyUsage are unsigned integers on the wire" do
    assert Types.aead_suite_number("aes-256-gcm") == 1
    assert Types.aead_suite_number("chacha20-poly1305") == 2
    assert Types.aead_suite_from_number!(2) == "chacha20-poly1305"

    key = %Types.DomainPublicKey{
      key_id: "k",
      public_key: <<1::256>>,
      fingerprint: "f",
      algorithm: "ed25519",
      key_usage: "encrypt",
      created_at: ~U[2026-01-01 00:00:00Z],
      expires_at: ~U[2027-01-01 00:00:00Z]
    }

    tree = key |> Types.domain_public_key_to_cbor() |> Cbor.decode()
    assert tree["algorithm"] == 1
    assert tree["key_usage"] == 2
    assert Types.domain_public_key_from_cbor(Cbor.encode(tree)) == key
  end

  test "an enum as text or an unknown enum number is rejected" do
    assert_raise ArgumentError, fn -> Types.aead_suite_from_number!(3) end
    assert_raise ArgumentError, fn -> Types.aead_suite_from_number!("aes-256-gcm") end
    assert_raise ArgumentError, fn -> Types.aead_suite_number("aes-128-gcm") end

    key = %Types.DomainPublicKey{
      key_id: "k",
      public_key: <<1::256>>,
      fingerprint: "f",
      algorithm: "ed25519",
      key_usage: "sign",
      created_at: ~U[2026-01-01 00:00:00Z],
      expires_at: ~U[2027-01-01 00:00:00Z]
    }

    tree = key |> Types.domain_public_key_to_cbor() |> Cbor.decode()

    for {field, bad} <- [{"key_usage", "sign"}, {"key_usage", 99}, {"algorithm", "ed25519"}] do
      assert_raise ArgumentError, fn ->
        Types.domain_public_key_from_cbor(Cbor.encode(Map.put(tree, field, bad)))
      end
    end
  end
end
