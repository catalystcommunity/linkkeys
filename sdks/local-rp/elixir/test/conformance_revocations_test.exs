defmodule LinkkeysLocalRp.ConformanceRevocationsTest do
  use ExUnit.Case, async: true

  alias LinkkeysLocalRp.LocalRp
  alias LinkkeysLocalRp.Revocation
  alias LinkkeysLocalRp.Test.Vectors
  alias LinkkeysLocalRp.Timeutil
  alias LinkkeysLocalRp.Types.{ClaimSignature, DomainPublicKey, RevocationCertificate, SignedLocalRpCallbackPayload}

  @revocations Vectors.load("revocations.json")

  defp domain_keys do
    Enum.map(@revocations["domain_keys"], fn k ->
      %DomainPublicKey{
        key_id: k["key_id"],
        public_key: Vectors.hex(k["public_key_hex"]),
        fingerprint: k["fingerprint_hex"],
        algorithm: k["algorithm"],
        key_usage: k["key_usage"],
        created_at: k["created_at"],
        expires_at: k["expires_at"],
        revoked_at: k["revoked_at"],
        signed_by_key_id: nil,
        key_signature: nil
      }
    end)
  end

  defp certificate(case_) do
    c = case_["certificate"]

    %RevocationCertificate{
      target_key_id: c["target_key_id"],
      target_fingerprint: c["target_fingerprint"],
      revoked_at: c["revoked_at"],
      signatures:
        Enum.map(c["signatures"], fn s ->
          %ClaimSignature{
            domain: s["domain"],
            signed_by_key_id: s["signed_by_key_id"],
            signature: Vectors.hex(s["signature_hex"])
          }
        end)
    }
  end

  test "registry constants" do
    assert @revocations["quorum"] == Revocation.revocation_quorum()
    assert @revocations["tag"] == "linkkeys-key-revocation-v1"
  end

  test "certificate CBOR round trips" do
    for case_ <- @revocations["certificate_cases"] do
      wire = Vectors.hex(case_["certificate_cbor_hex"])
      decoded = LinkkeysLocalRp.Types.revocation_certificate_from_cbor(wire)
      expected = certificate(case_)
      assert decoded == expected, case_["name"]
      assert LinkkeysLocalRp.Types.revocation_certificate_to_cbor(decoded) == wire, case_["name"]
    end
  end

  test "revocation payload matches vectors" do
    case_ = Enum.find(@revocations["certificate_cases"], fn c -> c["name"] == "valid_quorum_two_siblings" end)
    cert = case_["certificate"]

    for sig <- cert["signatures"] do
      computed =
        Revocation.revocation_payload(
          cert["target_key_id"],
          cert["target_fingerprint"],
          cert["revoked_at"],
          sig["domain"]
        )

      assert computed == Vectors.hex(sig["signed_payload_cbor_hex"])
    end
  end

  test "all certificate cases" do
    keys = domain_keys()
    cases = @revocations["certificate_cases"]
    assert length(cases) == 9

    for case_ <- cases do
      cert = certificate(case_)
      domain = case_["verify_domain"]

      counted = Revocation.count_valid_signers(cert, keys, domain)
      assert counted == case_["expected_counted_signers"], case_["name"]

      valid = match?(:ok, Revocation.verify_revocation_certificate(cert, keys, domain))
      assert valid == case_["expected_valid"], case_["name"]
    end
  end

  test "application case: certificates are applied, not just verified" do
    keys = domain_keys()
    app = @revocations["application_case"]
    env = app["envelope"]
    assert env["structure"] == "callback_payload"

    signed = %SignedLocalRpCallbackPayload{
      payload: Vectors.hex(env["payload_cbor_hex"]),
      signing_key_id: env["signing_key_id"],
      signature: Vectors.hex(env["signature_hex"])
    }

    verify_now = Timeutil.parse_rfc3339(app["verify_now"])
    skew = app["clock_skew_seconds"]

    # Before applying the revocation certificate: the envelope verifies,
    # because the fetched key list shows the target with NO revoked_at.
    assert app["expected_valid_before_revocation"] == true
    assert {:ok, payload} = LocalRp.verify_local_rp_callback_payload(signed, keys, verify_now, skew)
    assert payload.user_domain == @revocations["domain"]

    # Apply the referenced certificate (valid_quorum_two_siblings) exactly
    # the way Rpc.fetch_domain_keys does, then re-verify: must now fail.
    cert_case = Enum.find(@revocations["certificate_cases"], fn c -> c["name"] == "valid_quorum_two_siblings" end)
    cert = certificate(cert_case)
    applied = Revocation.apply_revocations(keys, [cert], @revocations["domain"])
    assert Enum.all?(applied, fn k -> k.key_id != cert.target_key_id end)

    assert app["expected_valid_after_revocation"] == false
    assert {:error, _} = LocalRp.verify_local_rp_callback_payload(signed, applied, verify_now, skew)
  end
end
