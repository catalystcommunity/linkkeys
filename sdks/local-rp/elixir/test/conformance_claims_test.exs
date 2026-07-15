defmodule LinkkeysLocalRp.ConformanceClaimsTest do
  use ExUnit.Case, async: true

  alias LinkkeysLocalRp.Cbor
  alias LinkkeysLocalRp.Claims
  alias LinkkeysLocalRp.Claims.DomainKeySet
  alias LinkkeysLocalRp.Crypto
  alias LinkkeysLocalRp.Test.Vectors
  alias LinkkeysLocalRp.Timeutil
  alias LinkkeysLocalRp.Types
  alias LinkkeysLocalRp.Types.{Claim, ClaimSignature}

  @claims Vectors.load("claims.json")

  # Any instant between the fixture's attested_at (2026-01-01) and the
  # far-future expires_at (2126-01-01) / key expires_at (2126-01-01), and
  # after the null-expiry cases' attested_at. Deliberately not the system
  # clock -- every check here takes `now` explicitly.
  @now Timeutil.parse_rfc3339("2026-06-01T00:00:00Z")

  # -- fixture builders ----------------------------------------------------

  defp claim_signature_from_json(s) do
    %ClaimSignature{
      domain: s["domain"],
      signed_by_key_id: s["signed_by_key_id"],
      signature: Vectors.hex(s["signature_hex"])
    }
  end

  defp claim_from_json(c) do
    %Claim{
      claim_id: c["claim_id"],
      user_id: c["user_id"],
      claim_type: c["claim_type"],
      claim_value: Vectors.hex(c["claim_value_hex"]),
      signatures: Enum.map(c["signatures"], &claim_signature_from_json/1),
      attested_at: c["attested_at"],
      created_at: c["created_at"],
      expires_at: c["expires_at"],
      revoked_at: c["revoked_at"]
    }
  end

  defp key_entry_from_json(k) do
    %{
      key_id: k["key_id"],
      public_key: Vectors.hex(k["public_key_hex"]),
      key_usage: k["key_usage"],
      expires_at: k["expires_at"],
      revoked_at: k["revoked_at"]
    }
  end

  defp domain_key_set(domain, keys_json) do
    %DomainKeySet{domain: domain, keys: Enum.map(keys_json, &key_entry_from_json/1)}
  end

  defp default_domain_keys do
    [domain_key_set("conformance.example", @claims["domain_keys"])]
  end

  defp domain_keys_for(case_) do
    case case_["domain_keys"] do
      nil -> default_domain_keys()
      override -> [domain_key_set("conformance.example", override)]
    end
  end

  # Recomputes the claim-signature payload directly from the README /
  # design-doc layout (CBOR([tag, claim_id, claim_type, claim_value(bstr),
  # "user_id@subject_domain", signing_domain, expires_at_or_null,
  # attested_at]) -- an 8-element array, tag first), independent of
  # `LinkkeysLocalRp.Claims`'s own (private) payload builder. This is what
  # actually audits the SDK's wire construction against the spec rather
  # than just re-running the SDK's own logic against itself.
  defp manual_claim_sign_payload(%Claim{} = claim, subject_domain, signing_domain) do
    subject = "#{claim.user_id}@#{subject_domain}"

    Cbor.encode([
      "linkkeys-claim-v2",
      claim.claim_id,
      claim.claim_type,
      Cbor.bytes(claim.claim_value),
      subject,
      signing_domain,
      claim.expires_at,
      claim.attested_at
    ])
  end

  defp pubkey_for(key_id) do
    entry = Enum.find(@claims["domain_keys"], fn k -> k["key_id"] == key_id end)
    Vectors.hex(entry["public_key_hex"])
  end

  # -- positive cases: wire round-trip -------------------------------------

  test "positive cases: claim CBOR round-trips byte-exact" do
    cases = @claims["cases"]
    assert length(cases) == 3

    for case_ <- cases do
      wire = Vectors.hex(case_["claim_cbor_hex"])
      decoded = Types.claim_from_cbor(wire)
      expected = claim_from_json(case_["claim"])

      assert decoded == expected, case_["name"]
      assert Types.claim_to_cbor(decoded) == wire, case_["name"]
    end
  end

  # -- positive cases: independent Ed25519 verification --------------------

  test "positive cases: every signed_payload_cbor_hex/signature independently verifies via :crypto" do
    for case_ <- @claims["cases"] do
      claim = case_["claim"]

      for sig <- claim["signatures"] do
        payload = Vectors.hex(sig["signed_payload_cbor_hex"])
        signature = Vectors.hex(sig["signature_hex"])
        public_key = pubkey_for(sig["signed_by_key_id"])

        assert Crypto.ed25519_verify(payload, signature, public_key),
               "#{case_["name"]} / #{sig["signed_by_key_id"]}: signature did not verify"
      end
    end
  end

  test "positive cases: signed payload bytes match the README's 8-element tag-first layout" do
    for case_ <- @claims["cases"] do
      claim = claim_from_json(case_["claim"])
      subject_domain = case_["subject_domain"]

      for sig <- case_["claim"]["signatures"] do
        expected = Vectors.hex(sig["signed_payload_cbor_hex"])
        computed = manual_claim_sign_payload(claim, subject_domain, sig["domain"])

        assert computed == expected,
               "#{case_["name"]} / #{sig["signed_by_key_id"]}: recomputed payload bytes mismatch"
      end
    end
  end

  # -- positive cases: through the SDK's own verification path -------------

  test "positive cases verify through Claims.verify_claim/4 (the complete_local_login path)" do
    for case_ <- @claims["cases"] do
      claim = claim_from_json(case_["claim"])
      subject_domain = case_["subject_domain"]

      assert :ok == Claims.verify_claim_signatures(claim, subject_domain, default_domain_keys(), @now),
             case_["name"]

      assert :ok == Claims.verify_claim(claim, subject_domain, default_domain_keys(), @now),
             case_["name"]
    end
  end

  # -- decode-negative case: the tstr/bstr trap -----------------------------

  test "claim_value encoded as CBOR text (major type 3) is REJECTED at decode, not silently accepted" do
    cases = @claims["decode_negative_cases"]
    assert length(cases) == 1

    for case_ <- cases do
      refute case_["expected_decode_ok"], case_["name"]
      wire = Vectors.hex(case_["claim_cbor_hex"])

      assert_raise ArgumentError, fn ->
        Types.claim_from_cbor(wire)
      end
    end
  end

  # -- verification negatives -----------------------------------------------

  defp assert_expected_error(result, expected_error, name) do
    case {result, expected_error} do
      {{:error, :signature_invalid}, "signature_invalid"} ->
        :ok

      {{:error, {:key_not_found, _}}, "key_not_found"} ->
        :ok

      other ->
        flunk("#{name}: expected error kind #{inspect(expected_error)}, got #{inspect(other)}")
    end
  end

  test "all 4 verification negatives fail with the expected error kind" do
    cases = @claims["negative_cases"]
    assert length(cases) == 4

    for case_ <- cases do
      wire = Vectors.hex(case_["claim_cbor_hex"])
      # These are all signature-verification negatives, not decode
      # negatives -- the wire bytes must decode fine (claim_value is
      # still a valid bstr in every one of them); only verification
      # must fail.
      claim = Types.claim_from_cbor(wire)

      result =
        Claims.verify_claim_signatures(claim, case_["subject_domain"], domain_keys_for(case_), @now)

      assert match?({:error, _}, result), case_["name"]
      assert_expected_error(result, case_["expected_error"], case_["name"])
    end
  end

  # -- LocalRpTicketRedemptionResponse: the actual wire message SDKs consume

  test "LocalRpTicketRedemptionResponse round-trips byte-exact and its embedded claims verify" do
    response = @claims["ticket_redemption_response"]
    wire = Vectors.hex(response["response_cbor_hex"])

    decoded = Types.local_rp_ticket_redemption_response_from_cbor(wire)

    assert decoded.user_id == response["user_id"]
    assert decoded.user_domain == response["user_domain"]
    assert decoded.ticket_expires_at == response["ticket_expires_at"]
    assert length(decoded.claims) == 3

    expected_claims = Enum.map(@claims["cases"], fn c -> claim_from_json(c["claim"]) end)
    assert decoded.claims == expected_claims

    # Decoding without verifying fails the point (README's own words) --
    # verify every embedded claim's signatures through the SDK's real
    # verification path, exactly as complete_local_login must.
    for claim <- decoded.claims do
      assert :ok == Claims.verify_claim(claim, decoded.user_domain, default_domain_keys(), @now),
             claim.claim_id
    end

    # Byte-exact re-encode.
    assert Types.local_rp_ticket_redemption_response_to_cbor(decoded) == wire
  end
end
