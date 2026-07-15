defmodule LinkkeysLocalRp.ConformanceCallbackBoxTest do
  use ExUnit.Case, async: true

  alias LinkkeysLocalRp.Crypto
  alias LinkkeysLocalRp.LocalRp
  alias LinkkeysLocalRp.Test.Vectors
  alias LinkkeysLocalRp.Types
  alias LinkkeysLocalRp.Types.LocalRpEncryptedCallback

  @callback_box Vectors.load("callback_box.json")

  defp allowed_suites(case_) do
    case_["allowed_suites"] |> Enum.map(&Crypto.parse_suite/1) |> Enum.filter(& &1)
  end

  test "positive cases open" do
    cases = @callback_box["positive_cases"]
    assert length(cases) == 2

    for case_ <- cases do
      header_bytes = Vectors.hex(case_["header_cbor_hex"])
      ciphertext = Vectors.hex(case_["ciphertext_hex"])
      decrypt_key = Vectors.hex(case_["decrypt_private_key_hex"])
      allowed = allowed_suites(case_)

      encrypted = %LocalRpEncryptedCallback{header: header_bytes, ciphertext: ciphertext}

      assert {:ok, header, signed_payload} = LocalRp.open_local_rp_callback(encrypted, decrypt_key, allowed)

      assert header.suite == case_["suite"]
      assert header.fingerprint == case_["fingerprint"]
      assert header.nonce == Vectors.hex(case_["nonce_hex"])
      assert header.state == Vectors.hex(case_["state_hex"])
      assert header.issued_at == case_["issued_at"]
      assert header.expires_at == case_["expires_at"]

      plaintext = Types.signed_local_rp_callback_payload_to_cbor(signed_payload)
      assert plaintext == Vectors.hex(case_["plaintext_cbor_hex"])
    end
  end

  test "negative cases fail" do
    cases = @callback_box["negative_cases"]
    assert length(cases) == 13

    for case_ <- cases do
      header_bytes = Vectors.hex(case_["header_cbor_hex"])
      ciphertext = Vectors.hex(case_["ciphertext_hex"])
      decrypt_key = Vectors.hex(case_["decrypt_private_key_hex"])
      allowed = allowed_suites(case_)

      encrypted = %LocalRpEncryptedCallback{header: header_bytes, ciphertext: ciphertext}

      result =
        try do
          LocalRp.open_local_rp_callback(encrypted, decrypt_key, allowed)
        rescue
          _ -> {:error, :raised}
        end

      assert match?({:error, _}, result), case_["name"]
    end
  end
end
