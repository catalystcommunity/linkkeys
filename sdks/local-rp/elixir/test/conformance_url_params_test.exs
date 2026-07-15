defmodule LinkkeysLocalRp.ConformanceUrlParamsTest do
  use ExUnit.Case, async: true

  alias LinkkeysLocalRp.Encoding
  alias LinkkeysLocalRp.Test.Vectors
  alias LinkkeysLocalRp.Types

  @url_params Vectors.load("url_params.json")

  test "cases round trip both directions" do
    for case_ <- @url_params["cases"] do
      cbor = Vectors.hex(case_["cbor_hex"])
      b64 = case_["base64url_unpadded"]

      assert Encoding.b64url_encode(cbor) == b64
      assert Encoding.b64url_decode(b64) == cbor

      case case_["name"] do
        "signed_local_rp_login_request" ->
          typed = Types.signed_local_rp_login_request_from_cbor(cbor)
          assert Encoding.signed_local_rp_login_request_to_url_param(typed) == b64
          round_tripped = Encoding.signed_local_rp_login_request_from_url_param(b64)
          assert round_tripped.request == typed.request
          assert round_tripped.signature == typed.signature

        "local_rp_encrypted_callback" ->
          typed = Types.local_rp_encrypted_callback_from_cbor(cbor)
          assert Encoding.local_rp_encrypted_callback_to_url_param(typed) == b64
          round_tripped = Encoding.local_rp_encrypted_callback_from_url_param(b64)
          assert round_tripped.header == typed.header
          assert round_tripped.ciphertext == typed.ciphertext

        other ->
          flunk("unrecognized url_params.json case name: #{other}")
      end
    end
  end

  test "negative cases rejected" do
    cases = @url_params["negative_cases"]
    assert length(cases) == 2

    for case_ <- cases do
      input = case_["input"]
      assert case_["expected_valid"] == false

      assert_raise Encoding.DecodeError, fn -> Encoding.b64url_decode(input) end
      assert_raise Encoding.DecodeError, fn -> Encoding.local_rp_encrypted_callback_from_url_param(input) end
    end
  end
end
