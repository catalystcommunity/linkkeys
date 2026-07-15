defmodule LinkkeysLocalRp.FlowTest do
  @moduledoc """
  Flow tests: `complete_local_login/1`'s full verification chain, end to
  end, against a real (but locally spun up, fake-identity) LinkKeys IDP —
  DNS-pinned TLS, CSIL-RPC framing, and all. Only two things are faked:
  the DNS TXT answers (a plain function, so no real network/DNS is
  touched) and the IDP's identity itself (a throwaway domain signing key
  generated for this test, not a real LinkKeys deployment). Mirrors
  `sdks/local-rp/rust/tests/flow.rs` / `sdks/local-rp/python/tests/test_flow.py`
  (happy path + one test per verification-chain failure).

  Canned callback/ticket-redemption/domain-keys responses are built with
  `LinkkeysLocalRp.LocalRp`/`.Claims` directly (the same pure protocol
  layer `complete_local_login/1` itself calls), using the same fixed,
  publicly-known test key seeds as `sdks/local-rp/conformance/keys.json`
  (`local_rp.signing` = 0x01 repeated, `local_rp.encryption` = 0x02
  repeated, `domain_signing_key` = 0x03 repeated) so this test suite and
  the conformance vectors describe the same identities.

  The fake IDP's TLS certificate is minted with the `openssl` CLI (see
  the SDK README's "Ed25519-cert-with-:ssl outcome" section for why: OTP's
  `:public_key` has no single-call "build and self-sign an X.509
  certificate" helper the way `openssl req -x509` does, so — like the
  sibling TypeScript/Java SDKs — this test shells out to mint one
  deterministically from the fixed domain seed). If `openssl` isn't on
  `PATH`, every test in this module is skipped with a clear reason rather
  than failing; `LinkkeysLocalRp.Tls`'s pin-extraction logic is still
  covered directly against a real Ed25519 certificate fixture in
  `test/tls_test.exs`, independent of `openssl` availability.
  """

  use ExUnit.Case, async: false

  alias LinkkeysLocalRp.Begin
  alias LinkkeysLocalRp.Cbor
  alias LinkkeysLocalRp.Cbor.Tag
  alias LinkkeysLocalRp.Claims
  alias LinkkeysLocalRp.Claims.{ClaimSigner, ClaimSpec}
  alias LinkkeysLocalRp.Complete
  alias LinkkeysLocalRp.Complete.VerifiedLocalLogin
  alias LinkkeysLocalRp.Crypto
  alias LinkkeysLocalRp.Encoding
  alias LinkkeysLocalRp.Identity.LocalRpKeyMaterial
  alias LinkkeysLocalRp.LocalRp
  alias LinkkeysLocalRp.Timeutil
  alias LinkkeysLocalRp.Transport
  alias LinkkeysLocalRp.Types

  alias LinkkeysLocalRp.Types.{
    DomainPublicKey,
    GetDomainKeysResponse,
    GetRevocationsResponse,
    LocalRpTicketRedemptionResponse
  }

  @local_rp_signing_seed :binary.copy(<<1>>, 32)
  @local_rp_encryption_private :binary.copy(<<2>>, 32)
  @domain_signing_seed :binary.copy(<<3>>, 32)
  @domain_key_id "test-domain-key-1"
  @user_domain "example.test"
  @callback_url "http://localhost/callback"

  @openssl_available System.find_executable("openssl") != nil

  @moduletag skip:
               if(@openssl_available,
                 do: false,
                 else: "openssl CLI not found on PATH; skipping TLS fake-IDP flow tests"
               )

  # ---------------------------------------------------------------------
  # Test doubles / fake IDP
  # ---------------------------------------------------------------------

  # Fixed 16-byte RFC 8410 PKCS8 prefix for an unencrypted Ed25519 private
  # key, verified byte-for-byte against `openssl genpkey -algorithm
  # ed25519`'s own DER output (see the SDK README's crypto-probe section):
  # `SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING {
  # OCTET STRING <32-byte-seed> } }`.
  @pkcs8_ed25519_prefix Base.decode16!("302E020100300506032B657004220420", case: :mixed)

  defp pkcs8_der_from_seed(seed) when byte_size(seed) == 32, do: @pkcs8_ed25519_prefix <> seed

  defp pem_wrap(der, label) do
    body =
      der
      |> Base.encode64()
      |> String.codepoints()
      |> Enum.chunk_every(64)
      |> Enum.map(&Enum.join/1)
      |> Enum.join("\n")

    "-----BEGIN #{label}-----\n#{body}\n-----END #{label}-----\n"
  end

  defp generate_domain_tls_cert(domain_name, seed) do
    key_der = pkcs8_der_from_seed(seed)
    key_pem = pem_wrap(key_der, "PRIVATE KEY")

    tmp = Path.join(System.tmp_dir!(), "linkkeys-local-rp-elixir-test-#{:erlang.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    keyfile = Path.join(tmp, "domain.key.pem")
    certfile = Path.join(tmp, "domain.cert.der")

    try do
      File.write!(keyfile, key_pem)

      {_out, 0} =
        System.cmd("openssl", [
          "req",
          "-new",
          "-x509",
          "-key",
          keyfile,
          "-days",
          "3650",
          "-subj",
          "/CN=#{domain_name}",
          "-outform",
          "DER",
          "-out",
          certfile
        ])

      cert_der = File.read!(certfile)
      {cert_der, key_der}
    after
      File.rm_rf!(tmp)
    end
  end

  defp decode_request_envelope(data) do
    %{"service" => service, "op" => op} = tree = Cbor.decode(data)

    payload =
      case Map.get(tree, "payload") do
        %Tag{tag: 24, value: v} -> Cbor.bytes!(v)
        _ -> <<>>
      end

    {service, op, payload}
  end

  defp encode_ok_response(payload) do
    Cbor.encode(%{"v" => 1, "status" => 0, "payload" => %Tag{tag: 24, value: Cbor.bytes(payload)}})
  end

  defp encode_error_response(status, message) do
    Cbor.encode(%{
      "v" => 1,
      "status" => status,
      "error" => message,
      "payload" => %Tag{tag: 24, value: Cbor.bytes(<<>>)}
    })
  end

  defp ssl_send_frame(sock, data) do
    :ok = :ssl.send(sock, <<byte_size(data)::32>>)
    :ok = :ssl.send(sock, data)
  end

  defp ssl_recv_exact(sock, n) do
    case :ssl.recv(sock, n, 5000) do
      {:ok, data} -> data
      {:error, _} -> nil
    end
  end

  defp ssl_recv_frame(sock) do
    case ssl_recv_exact(sock, 4) do
      nil ->
        nil

      <<len::32>> ->
        ssl_recv_exact(sock, len)
    end
  end

  # Spawns a background process that accepts up to `expected_requests` TLS
  # connections on a fresh loopback port, presenting a certificate derived
  # from `domain_seed` (so its SPKI fingerprint is whatever the test's DNS
  # answer pins to), and answers each with `dispatch.(service, op,
  # payload)`. Returns `"host:port"`.
  defp spawn_fake_idp(domain_seed, expected_requests, dispatch) do
    {cert_der, key_der} = generate_domain_tls_cert(@user_domain, domain_seed)

    {:ok, listen} =
      :ssl.listen(0, [:binary, active: false, cert: cert_der, key: {:PrivateKeyInfo, key_der}, reuseaddr: true])

    {:ok, {_, port}} = :ssl.sockname(listen)

    spawn(fn -> serve(listen, expected_requests, dispatch) end)

    "127.0.0.1:#{port}"
  end

  defp serve(_listen, 0, _dispatch), do: :ok

  defp serve(listen, remaining, dispatch) do
    case :ssl.transport_accept(listen, 10_000) do
      {:ok, tsock} ->
        case :ssl.handshake(tsock, 5000) do
          {:ok, ssock} ->
            handle_one(ssock, dispatch)
            :ssl.close(ssock)

          {:error, _reason} ->
            :ok
        end

      {:error, _reason} ->
        :ok
    end

    serve(listen, remaining - 1, dispatch)
  end

  defp handle_one(ssock, dispatch) do
    case ssl_recv_frame(ssock) do
      nil ->
        :ok

      request_bytes ->
        {service, op, payload} = decode_request_envelope(request_bytes)

        case dispatch.(service, op, payload) do
          # Simulates a peer that accepts the connection but never answers
          # (or drops mid-response) — the client must observe this as a
          # failure, never as a silent "nothing to report".
          :no_response -> :ok
          resp -> ssl_send_frame(ssock, resp)
        end
    end
  end

  # ---------------------------------------------------------------------
  # Scenario construction
  # ---------------------------------------------------------------------

  defp fixed_key_material(now) do
    signing_public_key = Crypto.ed25519_public_from_private(@local_rp_signing_seed)
    encryption_public_key = Crypto.x25519_public_from_private(@local_rp_encryption_private)

    created_at = Timeutil.to_rfc3339(DateTime.add(now, -86_400, :second))
    expires_at = Timeutil.to_rfc3339(DateTime.add(now, 3650 * 86_400, :second))

    descriptor =
      LocalRp.build_local_rp_descriptor(
        "Flow Test App",
        nil,
        signing_public_key,
        encryption_public_key,
        ["aes-256-gcm", "chacha20-poly1305"],
        created_at,
        expires_at
      )

    fingerprint = descriptor.fingerprint
    signed_descriptor = LocalRp.sign_local_rp_descriptor(descriptor, @local_rp_signing_seed)

    %LocalRpKeyMaterial{
      signing_private_key: @local_rp_signing_seed,
      signing_public_key: signing_public_key,
      encryption_private_key: @local_rp_encryption_private,
      encryption_public_key: encryption_public_key,
      descriptor: signed_descriptor,
      fingerprint: fingerprint
    }
  end

  defp sibling_key(seed, key_id, now) do
    pk = Crypto.ed25519_public_from_private(seed)

    %DomainPublicKey{
      key_id: key_id,
      public_key: pk,
      fingerprint: Crypto.fingerprint(pk),
      algorithm: "ed25519",
      key_usage: "sign",
      signed_by_key_id: nil,
      key_signature: nil,
      created_at: Timeutil.to_rfc3339(DateTime.add(now, -30 * 86_400, :second)),
      expires_at: Timeutil.to_rfc3339(DateTime.add(now, 365 * 86_400, :second)),
      revoked_at: nil
    }
  end

  defp domain_public_key(now), do: sibling_key(@domain_signing_seed, @domain_key_id, now)

  defp default_scenario do
    %{
      mutate_payload: fn p -> p end,
      mutate_domain_key: fn k -> k end,
      mutate_claim: fn c -> c end,
      mutate_redemption: fn r -> r end,
      dns_fingerprint_override: nil,
      extra_domain_keys: [],
      revocation_certs: [],
      revocations_response_override: nil,
      claim_type_override: nil,
      # get-domain-keys + get-revocations (ALWAYS fetched now, regardless
      # of recent_revocations_available — SEC fix B) + redeem-claim-ticket.
      expected_requests: 3
    }
  end

  defp run_scenario(overrides) do
    scenario = Map.merge(default_scenario(), overrides)
    now = DateTime.utc_now()
    key_material = fixed_key_material(now)

    {_redirect, pending} =
      Begin.begin_local_login(
        key_material: key_material,
        callback_url: @callback_url,
        user_domain: @user_domain,
        now: now
      )

    domain_key = scenario.mutate_domain_key.(domain_public_key(now))

    claim_ticket = :binary.copy(<<7>>, 32)

    payload =
      LocalRp.build_local_rp_callback_payload(
        "user-1",
        @user_domain,
        claim_ticket,
        key_material.fingerprint,
        @callback_url,
        pending.nonce,
        pending.state,
        Timeutil.to_rfc3339(now),
        Timeutil.to_rfc3339(DateTime.add(now, 300, :second))
      )
      |> scenario.mutate_payload.()

    signed_payload = LocalRp.sign_local_rp_callback_payload(payload, @domain_key_id, @domain_signing_seed)

    {:ok, encrypted} =
      LocalRp.seal_local_rp_callback(
        signed_payload,
        "aes-256-gcm",
        key_material.encryption_public_key,
        payload.audience_fingerprint,
        payload.nonce,
        payload.state,
        payload.issued_at,
        payload.expires_at
      )

    encrypted_token = Encoding.local_rp_encrypted_callback_to_url_param(encrypted)
    arrived_url = "#{@callback_url}?encrypted_token=#{encrypted_token}"

    claim =
      Claims.sign_claim(
        %ClaimSpec{
          claim_id: "claim-1",
          claim_type: scenario.claim_type_override || "handle",
          claim_value: "flowtestuser",
          user_id: "user-1",
          subject_domain: @user_domain,
          attested_at: Timeutil.to_rfc3339(now)
        },
        [%ClaimSigner{domain: @user_domain, key_id: @domain_key_id, private_key: @domain_signing_seed}]
      )
      |> scenario.mutate_claim.()

    ticket_expires_at = Timeutil.to_rfc3339(DateTime.add(now, 3600, :second))

    redemption_response =
      %LocalRpTicketRedemptionResponse{
        user_id: "user-1",
        user_domain: @user_domain,
        claims: [claim],
        ticket_expires_at: ticket_expires_at
      }
      |> scenario.mutate_redemption.()

    served_keys = [domain_key | scenario.extra_domain_keys]
    # Purely informational now (SEC fix B): fetch_domain_keys/3 ALWAYS
    # fetches get-revocations regardless of this flag, so a malicious/
    # compromised IDP can no longer suppress revocation delivery by
    # clearing it.
    revocations_available = if scenario.revocation_certs != [], do: true

    dispatch = fn service, op, _payload ->
      case {service, op} do
        {"DomainKeys", "get-domain-keys"} ->
          resp = %GetDomainKeysResponse{
            domain: @user_domain,
            keys: served_keys,
            recent_revocations_available: revocations_available
          }

          encode_ok_response(Types.get_domain_keys_response_to_cbor(resp))

        {"DomainKeys", "get-revocations"} ->
          case scenario.revocations_response_override do
            nil ->
              resp = %GetRevocationsResponse{revocations: scenario.revocation_certs}
              encode_ok_response(Types.get_revocations_response_to_cbor(resp))

            :no_response ->
              # Simulates a dropped connection / server that never answers
              # — the client must fail closed (SEC fix B), not treat a
              # missing answer as "nothing revoked".
              :no_response

            {:error, status, message} ->
              encode_error_response(status, message)
          end

        {"LocalRp", "redeem-claim-ticket"} ->
          encode_ok_response(Types.local_rp_ticket_redemption_response_to_cbor(redemption_response))

        _ ->
          encode_error_response(2, "fake IDP has no handler for #{service}/#{op}")
      end
    end

    tcp_addr = spawn_fake_idp(@domain_signing_seed, scenario.expected_requests, dispatch)

    real_fingerprint = Crypto.fingerprint(domain_key.public_key)
    pinned_fingerprint = scenario.dns_fingerprint_override || real_fingerprint
    pinned = [pinned_fingerprint | Enum.map(scenario.extra_domain_keys, fn k -> Crypto.fingerprint(k.public_key) end)]

    linkkeys_txt = "v=lk1 " <> Enum.map_join(pinned, " ", fn fp -> "fp=#{fp}" end)
    apis_txt = "v=lk1 tcp=#{tcp_addr}"

    dns = fn name ->
      cond do
        name == "_linkkeys.#{@user_domain}" -> {:ok, [linkkeys_txt]}
        name == "_linkkeys_apis.#{@user_domain}" -> {:ok, [apis_txt]}
        true -> {:error, {:no_fake_record, name}}
      end
    end

    transport = &Transport.dial/1

    Complete.complete_local_login(
      key_material: key_material,
      pending: pending,
      encrypted_token: encrypted_token,
      arrived_url: arrived_url,
      now: now,
      transport: transport,
      dns: dns
    )
  end

  # ---------------------------------------------------------------------
  # Tests
  # ---------------------------------------------------------------------

  test "happy path returns verified login" do
    assert {:ok, %VerifiedLocalLogin{} = verified} = run_scenario(%{})
    assert verified.user_id == "user-1"
    assert verified.user_domain == @user_domain
    assert length(verified.claims) == 1
    assert hd(verified.claims).claim_type == "handle"
    assert byte_size(verified.local_rp_fingerprint) == 64
    assert length(verified.domain_public_keys) == 1
  end

  test "wrong audience fingerprint is rejected" do
    mutate = fn p -> %{p | audience_fingerprint: String.duplicate("b", 64)} end
    # get-domain-keys + get-revocations (always fetched, SEC fix B) both
    # succeed; envelope/audience verification fails after that.
    assert {:error, _} = run_scenario(%{mutate_payload: mutate, expected_requests: 2})
  end

  test "wrong issuer domain is rejected" do
    mutate = fn p -> %{p | user_domain: "attacker.test"} end
    assert {:error, _} = run_scenario(%{mutate_payload: mutate, expected_requests: 2})
  end

  test "nonce mismatch is rejected" do
    mutate = fn p -> %{p | nonce: :binary.copy(<<0xEE>>, 32)} end
    assert {:error, :nonce_mismatch} = run_scenario(%{mutate_payload: mutate, expected_requests: 2})
  end

  test "expired callback payload is rejected" do
    mutate = fn p ->
      n = DateTime.utc_now()

      %{
        p
        | issued_at: Timeutil.to_rfc3339(DateTime.add(n, -7200, :second)),
          expires_at: Timeutil.to_rfc3339(DateTime.add(n, -3600, :second))
      }
    end

    assert {:error, _} = run_scenario(%{mutate_payload: mutate, expected_requests: 2})
  end

  test "dns fingerprint pin mismatch is rejected" do
    # Fails during the TLS pin check (the fake IDP's real cert fingerprint
    # no longer matches the pinned set) on the very first connection
    # attempt (get-domain-keys) — must never reach a verified result, and
    # never even reach get-revocations.
    assert {:error, _} = run_scenario(%{dns_fingerprint_override: String.duplicate("c", 64), expected_requests: 1})
  end

  test "revoked signing key is rejected" do
    mutate = fn k -> %{k | revoked_at: Timeutil.to_rfc3339(DateTime.utc_now())} end
    # The revoked key entry is still returned by get-domain-keys (trust_keys
    # doesn't itself filter revoked_at — that's checked later, during
    # envelope verification), so get-revocations is still fetched (SEC fix
    # B) before the revoked-key check fails envelope verification.
    assert {:error, _} = run_scenario(%{mutate_domain_key: mutate, expected_requests: 2})
  end

  test "tampered claim signature is rejected" do
    mutate = fn c ->
      case c.signatures do
        [first | rest] ->
          <<byte0, tail::binary>> = first.signature
          tampered = %{first | signature: <<Bitwise.bxor(byte0, 0xFF), tail::binary>>}
          %{c | signatures: [tampered | rest]}

        [] ->
          c
      end
    end

    # get-domain-keys + get-revocations + redeem-claim-ticket, then claim
    # signature verification fails.
    assert {:error, _} = run_scenario(%{mutate_claim: mutate, expected_requests: 3})
  end

  # -----------------------------------------------------------------------
  # Hostile-IDP tests (SEC fixes A/B): the fake IDP in each of these
  # scenarios behaves like a compromised/malicious home domain — an
  # otherwise perfectly valid, correctly-signed callback envelope, but the
  # UNAUTHENTICATED ticket-redemption/revocation responses disagree with,
  # or refuse to answer about, what was actually cryptographically
  # attested. Every one of these must fail closed (never `{:ok, _}`), and
  # the exact rejection point is asserted via `CompleteLoginError.reason`
  # (or the underlying protocol atom) — a generic `{:error, _}` isn't
  # enough evidence the RIGHT check caught it.
  # -----------------------------------------------------------------------

  test "ticket redemption identity mismatch is rejected (never succeeds)" do
    # The redemption response answers for a DIFFERENT user than the one the
    # domain-signed callback payload actually vouched for -- e.g. a
    # compromised/malicious IDP laundering an approval given to user A onto
    # user B's claims. The redemption response carries no signature of its
    # own, so this can only be caught by cross-checking it against the
    # signed payload.
    mutate = fn r -> %{r | user_id: "attacker-user"} end

    assert {:error, %LinkkeysLocalRp.Complete.CompleteLoginError{reason: :redemption_identity_mismatch}} =
             run_scenario(%{mutate_redemption: mutate, expected_requests: 3})
  end

  test "ticket redemption domain mismatch is rejected (never succeeds)" do
    mutate = fn r -> %{r | user_domain: "attacker.test"} end

    assert {:error, %LinkkeysLocalRp.Complete.CompleteLoginError{reason: :redemption_identity_mismatch}} =
             run_scenario(%{mutate_redemption: mutate, expected_requests: 3})
  end

  test "claim naming a different user_id than the signed payload is rejected (never succeeds)" do
    # The claim's OWN signature is valid (signed by the real domain key for
    # this claim_id/value) -- only its user_id disagrees with the
    # signature-verified callback payload's subject. A signature-valid
    # claim for the wrong user must still be rejected.
    mutate = fn c -> %{c | user_id: "someone-else"} end

    assert {:error, %LinkkeysLocalRp.Complete.CompleteLoginError{reason: :claim_user_id_mismatch}} =
             run_scenario(%{mutate_claim: mutate, expected_requests: 3})
  end

  test "empty claim set fails required_claims enforcement (never succeeds)" do
    # The default PendingLogin.required_claims (["handle"]) demands a
    # "handle" claim; the redemption response answers with NO claims at
    # all. Before SEC fix A, an empty claims list trivially passed the
    # per-claim verification loop with :ok and nothing downstream ever
    # checked required_claims against it -- this is the exact gap the
    # security review flagged.
    mutate = fn r -> %{r | claims: []} end

    assert {:error, %LinkkeysLocalRp.Complete.CompleteLoginError{reason: {:required_claims_missing, missing}}} =
             run_scenario(%{mutate_redemption: mutate, expected_requests: 3})

    assert "handle" in missing
  end

  test "claim set missing a required claim type fails required_claims enforcement (never succeeds)" do
    # A claim IS present and fully, genuinely verifies (claim_type is
    # changed BEFORE signing, so its signature is valid over "email") --
    # but its type is not among the required types ("handle"): insufficient,
    # not merely empty.
    assert {:error, %LinkkeysLocalRp.Complete.CompleteLoginError{reason: {:required_claims_missing, ["handle"]}}} =
             run_scenario(%{claim_type_override: "email", expected_requests: 3})
  end

  test "get-revocations server error fails closed (never succeeds)" do
    # The domain answers get-domain-keys normally but returns a server
    # error for get-revocations. Before SEC fix B this was swallowed as
    # best-effort ("we simply haven't learned of a revocation yet") and the
    # login would proceed; it must now be fatal.
    assert {:error, %LinkkeysLocalRp.Rpc.ServerError{}} =
             run_scenario(%{
               revocations_response_override: {:error, 3, "revocation service unavailable"},
               expected_requests: 2
             })
  end

  test "get-revocations dropped connection fails closed (never succeeds)" do
    # The domain accepts the get-revocations connection but never answers
    # (simulating a network drop) -- also must be fatal, not silently
    # treated as "nothing revoked". The connection closing mid-recv surfaces
    # as a Rpc.ProtocolError (the frame read never completed) rather than a
    # server-signaled ServerError -- still fatal either way, but pinned
    # down explicitly so this test can't quietly regress into passing for
    # the wrong reason.
    assert {:error, %LinkkeysLocalRp.Rpc.ProtocolError{}} =
             run_scenario(%{revocations_response_override: :no_response, expected_requests: 2})
  end

  test "certificate-revoked signing key fails completion" do
    # The fetched key entry for the callback-signing key carries NO
    # revoked_at of its own -- only the sibling-signed revocation
    # certificate (fetched via DomainKeys/get-revocations and APPLIED to
    # the trusted set) reveals it is dead. An SDK that skips the fetch, or
    # verifies the certificate without applying it, would incorrectly
    # complete this login.
    now = DateTime.utc_now()
    sibling_seeds = [:binary.copy(<<0x0E>>, 32), :binary.copy(<<0x0F>>, 32)]

    siblings =
      sibling_seeds
      |> Enum.with_index(1)
      |> Enum.map(fn {seed, i} -> sibling_key(seed, "sibling-key-#{i}", now) end)

    target = domain_public_key(now)
    revoked_at = Timeutil.to_rfc3339(now)

    signatures =
      Enum.zip(sibling_seeds, siblings)
      |> Enum.map(fn {seed, key} ->
        payload =
          LinkkeysLocalRp.Revocation.revocation_payload(target.key_id, target.fingerprint, revoked_at, @user_domain)

        sig = Crypto.ed25519_sign(payload, seed)
        %Types.ClaimSignature{domain: @user_domain, signed_by_key_id: key.key_id, signature: sig}
      end)

    cert = %Types.RevocationCertificate{
      target_key_id: target.key_id,
      target_fingerprint: target.fingerprint,
      revoked_at: revoked_at,
      signatures: signatures
    }

    result =
      run_scenario(%{
        extra_domain_keys: siblings,
        revocation_certs: [cert],
        # get-domain-keys + get-revocations, then envelope verification
        # fails (the callback-signing key has been dropped from the
        # trusted set) before ticket redemption is ever attempted.
        expected_requests: 2
      })

    # The revocation certificate removes the callback-signing key from the
    # trusted set entirely (Revocation.apply_revocations/4 rejects it, it
    # doesn't merely flag it), so envelope verification's key lookup itself
    # fails to find it -- proof the certificate was actually fetched,
    # quorum-verified, AND applied before the key was ever consulted.
    assert {:error, {:key_not_found, @domain_key_id}} = result
  end
end
