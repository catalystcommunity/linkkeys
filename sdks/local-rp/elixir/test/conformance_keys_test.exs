defmodule LinkkeysLocalRp.ConformanceKeysTest do
  use ExUnit.Case, async: true

  alias LinkkeysLocalRp.Crypto
  alias LinkkeysLocalRp.Identity
  alias LinkkeysLocalRp.Test.Vectors

  @keys Vectors.load("keys.json")

  test "fingerprints match and round trip through SDK helpers" do
    for path <- [@keys["local_rp"]["signing"], @keys["domain_signing_key"]] do
      public = Vectors.hex(path["public_key_hex"])
      expected_fp = path["fingerprint_hex"]

      computed = Crypto.fingerprint(public)
      assert computed == expected_fp

      s = Identity.fingerprint_to_string(computed)
      assert Identity.fingerprint_from_string(s) == expected_fp
    end
  end

  test "fingerprint_from_string rejects non-fingerprint" do
    assert_raise Identity.IdentityError, fn -> Identity.fingerprint_from_string("deadbeef") end
  end
end
