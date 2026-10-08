defmodule LinkkeysLocalRp.ActAsTest do
  @moduledoc """
  Act-as grantee side: byte-exact conformance against
  `sdks/regular-rp/conformance/act_as_grantee_signing.json` (case
  `local_rp_grantee`), the begin redirect with a fake DNS resolver, and the
  callback nonce check. The refresh call over the pinned transport is covered
  in `flow_test.exs`, next to the fake IDP.
  """

  use ExUnit.Case, async: true

  alias LinkkeysLocalRp.ActAs
  alias LinkkeysLocalRp.ActAs.{ActAsError, PendingActAs}
  alias LinkkeysLocalRp.Crypto
  alias LinkkeysLocalRp.Encoding
  alias LinkkeysLocalRp.Identity.LocalRpKeyMaterial
  alias LinkkeysLocalRp.LocalRp
  alias LinkkeysLocalRp.Test.Vectors
  alias LinkkeysLocalRp.Timeutil
  alias LinkkeysLocalRp.Types
  alias LinkkeysLocalRp.Types.{ActAsGrantRequest, ActAsRefreshRequest, ApplicationRef}

  import Vectors, only: [hex: 1, unhex: 1]

  @vectors Vectors.load_regular_rp("act_as_grantee_signing.json")

  defp local_case, do: Enum.find(@vectors["cases"], &(&1["name"] == "local_rp_grantee"))

  defp vector_key_material do
    g = @vectors["local_rp_grantee"]

    %LocalRpKeyMaterial{
      signing_private_key: hex(g["signing_private_key_hex"]),
      descriptor: Types.signed_local_rp_descriptor_from_cbor(hex(g["signed_descriptor_cbor_hex"])),
      fingerprint: g["fingerprint"]
    }
  end

  describe "local_rp_grantee conformance vector" do
    test "tags match" do
      assert ActAs.grant_request_tag() == @vectors["tags"]["grant_request"]
      assert ActAs.refresh_request_tag() == @vectors["tags"]["refresh_request"]
      assert ActAs.presentation_tag() == @vectors["tags"]["presentation"]
    end

    test "descriptor re-encodes byte-identically" do
      km = vector_key_material()

      assert unhex(Types.signed_local_rp_descriptor_to_cbor(km.descriptor)) ==
               @vectors["local_rp_grantee"]["signed_descriptor_cbor_hex"]

      assert local_case()["grantee"]["local_rp_descriptor_fingerprint"] == km.fingerprint
    end

    test "grant request is byte-exact" do
      km = vector_key_material()
      v = local_case()["grant_request"]
      i = v["inputs"]

      request = %ActAsGrantRequest{
        grantee: ActAs.grantee_ref(km),
        scope_set: Types.signed_act_as_scope_set_from_cbor(hex(i["scope_set_signed_cbor_hex"])),
        requested_lifetime_seconds: i["requested_lifetime_seconds"],
        requested_renewal_window_seconds: i["requested_renewal_window_seconds"],
        callback_url: i["callback_url"],
        nonce: i["nonce"],
        requested_at: i["requested_at"],
        expires_at: i["expires_at"]
      }

      assert unhex(Types.act_as_grant_request_to_cbor(request)) == v["request_cbor_hex"]

      signed = ActAs.sign_grant_request(request, km)
      assert unhex(signed.request) == v["request_cbor_hex"]

      assert unhex(LocalRp.envelope_signature_input(ActAs.grant_request_tag(), signed.request)) ==
               v["signature_input_cbor_hex"]

      assert unhex(Types.signed_act_as_grant_request_to_cbor(signed)) == v["signed_cbor_hex"]
      assert ActAs.signed_grant_request_to_url_param(signed) == v["url_param"]
    end

    test "refresh request is byte-exact" do
      km = vector_key_material()
      v = local_case()["refresh_request"]
      i = v["inputs"]

      signed =
        ActAs.sign_refresh_request(
          %ActAsRefreshRequest{
            grant_id: i["grant_id"],
            grantee: ActAs.grantee_ref(km),
            requested_at: i["requested_at"],
            expires_at: i["expires_at"],
            nonce: i["nonce"]
          },
          km
        )

      assert unhex(signed.request) == v["request_cbor_hex"]
      assert unhex(Types.signed_act_as_refresh_request_to_cbor(signed)) == v["signed_cbor_hex"]
    end

    test "credential is byte-exact" do
      km = vector_key_material()
      v = local_case()["presentation"]
      i = v["inputs"]
      a = i["audience"]

      grant = Types.signed_act_as_grant_from_cbor(hex(i["grant_signed_cbor_hex"]))
      assert unhex(ActAs.grant_hash(grant.grant)) == v["grant_hash_hex"]

      {credential, bytes} =
        ActAs.present(
          grant: grant,
          audience: %ApplicationRef{
            subject_user_id: a["subject_user_id"],
            subject_domain: a["subject_domain"],
            application_id: a["application_id"]
          },
          request_digest: hex(i["request_digest_hex"]),
          now: Timeutil.parse_rfc3339(i["presented_at"]),
          nonce: hex(i["nonce_hex"]),
          key_material: km
        )

      assert unhex(credential.presentation.presentation) == v["presentation_cbor_hex"]
      assert unhex(bytes) == v["credential_cbor_hex"]
    end
  end

  describe "begin_act_as/1" do
    setup do
      now = ~U[2026-10-06 11:59:00Z]
      material = LinkkeysLocalRp.generate_local_rp_identity(app_name: "Act-As Test", now: now)
      scope_set_hex = local_case()["grant_request"]["inputs"]["scope_set_signed_cbor_hex"]
      %{now: now, material: material, scope_set: hex(scope_set_hex)}
    end

    defp begin(ctx, overrides) do
      [
        key_material: ctx.material,
        user_domain: "alice@ID.Example.TEST",
        scope_set: ctx.scope_set,
        callback_url: "http://app.lan:8080/act-as/callback",
        now: ctx.now,
        dns: fn _ -> {:error, :no_fake_record} end
      ]
      |> Keyword.merge(overrides)
      |> ActAs.begin_act_as()
    end

    defp signed_request_param(url) do
      %URI{query: q} = URI.parse(url)
      Map.fetch!(URI.decode_query(q), "signed_request")
    end

    test "uses the discovered browser host and signs a verifiable request", ctx do
      dns = fn
        "_linkkeys_apis.id.example.test" -> {:ok, ["v=lk1 https=login.example.test/lk tcp=x.example.test:1"]}
        _ -> {:error, :nx}
      end

      {redirect, pending} = begin(ctx, dns: dns, requested_lifetime_seconds: 600)

      assert String.starts_with?(redirect.redirect_url, "https://login.example.test/lk/auth/act-as?signed_request=")
      refute String.contains?(redirect.redirect_url, "username=")

      assert %PendingActAs{user_domain: "id.example.test", callback_url: "http://app.lan:8080/act-as/callback"} =
               pending

      signed =
        redirect.redirect_url
        |> signed_request_param()
        |> Encoding.b64url_decode()
        |> Types.signed_act_as_grant_request_from_cbor()

      request = Types.act_as_grant_request_from_cbor(signed.request)
      assert request.nonce == pending.nonce
      assert byte_size(Encoding.b64url_decode(pending.nonce)) == 32
      assert request.grantee.local_rp_descriptor_fingerprint == ctx.material.fingerprint
      assert request.grantee.application == nil
      assert Types.signed_act_as_scope_set_to_cbor(request.scope_set) == ctx.scope_set
      assert request.requested_lifetime_seconds == 600
      assert request.requested_renewal_window_seconds == nil
      assert request.requested_at == "2026-10-06T11:59:00Z"
      assert request.expires_at == "2026-10-06T12:04:00Z"

      assert signed.proof.local_rp_descriptor == ctx.material.descriptor
      assert signed.proof.signature.signed_by_key_id == ctx.material.fingerprint

      assert Crypto.ed25519_verify(
               LocalRp.envelope_signature_input(ActAs.grant_request_tag(), signed.request),
               signed.proof.signature.signature,
               ctx.material.signing_public_key
             )
    end

    test "falls back to https://<domain> when discovery fails", ctx do
      {redirect, _} = begin(ctx, [])
      assert String.starts_with?(redirect.redirect_url, "https://id.example.test/auth/act-as?signed_request=")
    end

    test "each call uses a fresh nonce", ctx do
      {_, a} = begin(ctx, [])
      {_, b} = begin(ctx, [])
      refute a.nonce == b.nonce
    end

    test "refuses bad input", ctx do
      for overrides <- [
            [request_window_seconds: 901],
            [request_window_seconds: 0],
            [requested_lifetime_seconds: 0],
            [requested_renewal_window_seconds: -1],
            [scope_set: <<1, 2, 3>>],
            [callback_url: "ftp://app.lan/cb"],
            [user_domain: "not a domain"]
          ] do
        assert_raise ActAsError, fn -> begin(ctx, overrides) end
      end
    end
  end

  describe "complete_act_as/2" do
    @pending %PendingActAs{nonce: "n0nce-value", user_domain: "example.test", callback_url: "http://app.lan/cb"}

    test "returns the grant id when the nonce matches" do
      assert {:ok, "grant 1"} =
               ActAs.complete_act_as(@pending, "http://app.lan/cb?act_as_grant_id=grant%201&nonce=n0nce-value")

      assert {:ok, "g2"} = ActAs.complete_act_as(@pending, %{"act_as_grant_id" => "g2", "nonce" => "n0nce-value"})
      assert {:ok, "g3"} = ActAs.complete_act_as(@pending, "act_as_grant_id=g3&nonce=n0nce-value")
    end

    test "refuses a nonce mismatch or a missing parameter" do
      assert {:error, :nonce_mismatch} =
               ActAs.complete_act_as(@pending, "http://app.lan/cb?act_as_grant_id=g&nonce=n0nce-valuf")

      assert {:error, :nonce_mismatch} = ActAs.complete_act_as(@pending, "http://app.lan/cb?act_as_grant_id=g&nonce=x")

      assert {:error, {:missing_param, "nonce"}} =
               ActAs.complete_act_as(@pending, "http://app.lan/cb?act_as_grant_id=g")

      assert {:error, {:missing_param, "act_as_grant_id"}} =
               ActAs.complete_act_as(@pending, "http://app.lan/cb?nonce=n0nce-value")
    end

    test "refuses a repeated parameter, even when one value is correct" do
      assert {:error, :repeated_param} =
               ActAs.complete_act_as(
                 @pending,
                 "http://app.lan/cb?act_as_grant_id=evil&act_as_grant_id=g&nonce=n0nce-value"
               )

      assert {:error, :repeated_param} =
               ActAs.complete_act_as(@pending, "http://app.lan/cb?act_as_grant_id=g&nonce=n0nce-value&nonce=x")
    end
  end
end
