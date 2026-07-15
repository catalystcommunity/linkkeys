defmodule LinkkeysLocalRp.ConformanceEnvelopesTest do
  use ExUnit.Case, async: true

  alias LinkkeysLocalRp.Crypto
  alias LinkkeysLocalRp.LocalRp
  alias LinkkeysLocalRp.Test.Vectors

  @envelopes Vectors.load("envelopes.json")

  defp check_case(%{} = case_) do
    context = case_["context"]
    payload = Vectors.hex(case_["payload_cbor_hex"])
    expected_sig_input = Vectors.hex(case_["signature_input_cbor_hex"])
    signature = Vectors.hex(case_["signature_hex"])
    verify_key = Vectors.hex(case_["verify_key_hex"])
    expected_valid = case_["expected_valid"]

    computed_sig_input = LocalRp.envelope_signature_input(context, payload)
    assert computed_sig_input == expected_sig_input, case_["structure"]

    valid = Crypto.ed25519_verify(computed_sig_input, signature, verify_key)
    assert valid == expected_valid, case_["structure"]
  end

  test "positive cases verify" do
    cases = @envelopes["cases"]
    assert length(cases) == 4

    for case_ <- cases do
      assert case_["expected_valid"] == true
      check_case(case_)
    end
  end

  test "negative cases fail" do
    cases = @envelopes["negative_cases"]
    assert length(cases) == 20

    for case_ <- cases do
      assert case_["expected_valid"] == false
      check_case(case_)
    end
  end
end
