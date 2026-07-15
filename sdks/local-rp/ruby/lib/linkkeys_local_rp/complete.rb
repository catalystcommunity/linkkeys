# frozen_string_literal: true

require_relative 'claims'
require_relative 'url_params'
require_relative 'local_rp'
require_relative 'rpc'
require_relative 'crypto'
require_relative 'dns'
require_relative 'timeutil'
require_relative 'transport'
require_relative 'types'

module LinkkeysLocalRp
  # `complete_local_login` (design doc: "SDK API Shape", "Flow" steps
  # 12-13).
  #
  # This is the SDK's full verification chain, run in the exact order the
  # pure LocalRp helpers require:
  #
  # 1. decode the callback ciphertext from its URL-param encoding
  # 2. open it (decrypt) -- only with a suite this identity's own
  #    descriptor advertises
  # 3. fetch the pending domain's public keys, DNS-`fp=`-pinned, over TCP
  #    CSIL-RPC
  # 4. verify the domain-signed envelope (key lookup, revocation/expiry,
  #    signature, payload timestamp bounds) -- only now is anything inside
  #    the payload trusted
  # 5. cross-check the cleartext header's routing fields against the
  #    now-verified payload
  # 6. audience / issuer / callback-URL / nonce-state checks
  # 7. redeem the claim ticket over TCP CSIL-RPC (signed with the local
  #    RP's own key -- the possession proof)
  # 7b. bind the redemption response to the VERIFIED payload identity:
  #    redemption.user_id/redemption.user_domain must equal
  #    payload.user_id/payload.user_domain -- the redemption response is
  #    just an unsigned RPC reply, so it is never itself a trust root
  # 8. verify every returned claim's signatures against ITS signer
  #    domain's keys (fetched the same pinned way), which also checks the
  #    claim's own revocation/expiry, AND that claim.user_id ==
  #    payload.user_id
  # 9. enforce pending.required_claims: every required claim type must be
  #    present among the claims that passed step 8
  #
  # The identity this function returns (user_id/user_domain) is always
  # sourced from the SIGNED, domain-verified payload -- never from the
  # unsigned ticket-redemption response -- because step 7b already proved
  # they agree, and the payload is the only one of the two that is
  # cryptographically bound to the domain's signing key.
  module Complete
    # Bound on the number of distinct claim-signer domains
    # complete_local_login will fetch keys for per completion -- see the
    # comment at its use site for why this exists.
    MAX_CLAIM_SIGNER_DOMAINS = 8

    class Error < StandardError; end

    # The ticket-redemption response, or a redeemed claim, names a
    # different user_id/user_domain than the signed callback payload
    # already proved. Always fatal -- never partially trust either side.
    class IdentityMismatch < Error; end

    # One or more of pending.required_claims has no corresponding verified
    # claim in the redemption response (missing entirely, or present but
    # failed signature/revocation/expiry verification).
    class RequiredClaimsNotSatisfied < Error; end

    # What complete_local_login returns to app code (design doc: "SDKs ...
    # should either return verified results or call registered callbacks
    # with:" -- this package returns rather than calling back).
    VerifiedLocalLogin = Struct.new(
      :user_id, :user_domain, :claims, :domain_public_keys,
      :local_rp_fingerprint, :issued_at, :expires_at, :ticket_expires_at,
      keyword_init: true
    )

    module_function

    # Undo the exact `?`/`&` + `encrypted_token=` suffix construction the
    # IDP uses to deliver the callback, so the recovered value can be
    # compared against the signed payload's callback_url. If the arrived
    # URL doesn't end with that exact suffix, returns it unchanged -- the
    # subsequent verify_callback_url equality check then correctly fails
    # closed rather than this function guessing.
    def strip_encrypted_token_param(arrived_url)
      %w[? &].each do |sep|
        marker = "#{sep}encrypted_token="
        idx = arrived_url.rindex(marker)
        return arrived_url[0...idx] unless idx.nil?
      end
      arrived_url
    end
    private_class_method :strip_encrypted_token_param

    # `complete_local_login(config) -> VerifiedLocalLogin` (design doc,
    # "SDK API Shape"). Every argument is load-bearing:
    #
    # - key_material: the same identity begin_local_login used.
    # - pending: the pending-login state begin_local_login returned,
    #   exactly as the app persisted it. Treat as single-use.
    # - encrypted_token: the `encrypted_token` query-parameter's raw
    #   value.
    # - arrived_url: the full URL the callback actually arrived at.
    # - now: the current time (never read from the system clock
    #   internally).
    # - transport / dns: the network seams. Default to
    #   Transport::StdTransport.new / Dns::SystemDnsResolver.new when
    #   omitted.
    def complete_local_login(
      key_material, pending, encrypted_token, arrived_url, now,
      clock_skew_seconds: LocalRp::DEFAULT_CLOCK_SKEW_SECONDS,
      transport: nil, dns: nil
    )
      transport ||= Transport::StdTransport.new
      dns ||= Dns::SystemDnsResolver.new

      # 1. Decode the callback's URL-param encoding.
      encrypted = UrlParams.local_rp_encrypted_callback_from_url_param(encrypted_token)

      # 2. Open it, restricted to suites THIS identity's own descriptor
      # advertises (Wire Precision: "The SDK must decrypt only with a
      # suite listed in its own descriptor").
      own_descriptor = Types::LocalRpDescriptor.from_cbor(key_material.descriptor.descriptor)
      allowed_suites = own_descriptor.supported_suites.filter_map { |s| Crypto::AeadSuite.parse_str(s) }
      header, signed_payload = LocalRp.open_local_rp_callback(encrypted, key_material.encryption_private_key, allowed_suites)

      # 3. Fetch the PENDING state's domain's keys, DNS-pinned, over TCP
      # CSIL-RPC (design doc: "fetches domain public keys ... for the
      # domain the login was begun with").
      user_domain_keys = Rpc.fetch_domain_keys(transport, dns, pending.user_domain)

      # 4. Verify the domain-signed envelope against those keys (key
      # lookup, revocation/expiry, signature, payload timestamp bounds).
      # Nothing inside `payload` is trusted before this succeeds.
      payload = LocalRp.verify_local_rp_callback_payload(signed_payload, user_domain_keys, now, clock_skew_seconds)

      # 5. Cross-check the cleartext header's routing twins against the
      # now-verified payload.
      LocalRp.check_callback_header_matches_payload(header, payload)

      # 6a. Audience: the callback names THIS local RP.
      LocalRp.verify_audience(payload.audience_fingerprint, key_material.fingerprint)

      # 6b. Issuer binding: the payload's user_domain must be the domain
      # the login was BEGUN with, not merely whichever domain's keys
      # happened to verify.
      LocalRp.verify_issuer(payload.user_domain, pending.user_domain)

      # 6c. Callback URL binding against the URL the callback actually
      # arrived at (not merely the URL originally requested).
      arrived_base_url = strip_encrypted_token_param(arrived_url)
      LocalRp.verify_callback_url(payload.callback_url, arrived_base_url)

      # 6d. Nonce/state equality against the pending state. Single-use
      # replay protection at the app boundary is the app's job.
      LocalRp.verify_nonce_state(pending.nonce, pending.state, payload.nonce, payload.state)

      # 7. Redeem the claim ticket over TCP CSIL-RPC, signed with the
      # local RP's own key (the possession proof a stolen ticket can't
      # satisfy).
      redemption_request = LocalRp.build_local_rp_ticket_redemption_request(
        payload.claim_ticket, key_material.fingerprint, Timeutil.to_rfc3339(now)
      )
      signed_redemption = LocalRp.sign_local_rp_ticket_redemption_request(
        redemption_request, key_material.signing_private_key
      )
      redemption = Rpc.redeem_claim_ticket(transport, dns, pending.user_domain, signed_redemption)

      # 7b. The ticket-redemption response is an UNSIGNED RPC reply --
      # nothing about it is cryptographically bound to the domain's
      # signing key. The only identity this function may trust is the one
      # the SIGNED callback payload already proved (step 4). A
      # malicious/compromised IDP (or a compromise of only the
      # unauthenticated ticket-redemption RPC leg) could otherwise redeem
      # a ticket and hand back claims for a completely different user than
      # the one the browser actually authenticated as. Cross-check and
      # abort fatally on any mismatch -- never proceed with either side's
      # identity alone.
      if redemption.user_id != payload.user_id || redemption.user_domain != payload.user_domain
        raise IdentityMismatch, 'ticket redemption identity does not match the signed callback payload'
      end

      # 8. Verify every returned claim's signatures against ITS signer
      # domain's keys, fetched the same pinned way (a claim may be
      # attested by a domain other than the user's home domain). Reuse the
      # home domain's already-fetched keys; fetch any additional signer
      # domains on demand.
      #
      # The redemption response's claim signatures name their signing
      # domains as plain, not-yet-verified strings -- a malicious/
      # compromised home IDP could otherwise list an unbounded number of
      # distinct "signer domains" purely to make this SDK perform many
      # outbound DNS/TCP calls to attacker-chosen targets before any
      # signature is actually checked (an SSRF/DoS amplification vector
      # against the app's own process). Cap the number of distinct signer
      # domains this SDK will fetch keys for per completion; a legitimate
      # claim set names very few (typically one: the home domain).
      domain_key_sets = [Claims::DomainKeySet.new(domain: pending.user_domain, keys: user_domain_keys)]
      redemption.claims.each do |claim|
        claim.signatures.each do |sig|
          next if domain_key_sets.any? { |s| s.domain == sig.domain }

          if domain_key_sets.size >= MAX_CLAIM_SIGNER_DOMAINS
            raise Error, "claim set names more than #{MAX_CLAIM_SIGNER_DOMAINS} distinct signer domains; " \
                         'refusing to fetch further keys'
          end

          keys = Rpc.fetch_domain_keys(transport, dns, sig.domain)
          domain_key_sets << Claims::DomainKeySet.new(domain: sig.domain, keys: keys)
        end
      end

      # Verify every claim against the VERIFIED payload's user_domain (not
      # redemption.user_domain -- equal per the 7b check above, but the
      # payload's copy is the one that's actually signature-bound), and
      # cross-check each claim's own user_id against the payload's before
      # trusting it: a claim naming a different user_id is never partially
      # accepted, it aborts the whole completion. Track which claim types
      # survive full verification so pending.required_claims can be
      # enforced against only the claims actually proven good.
      verified_claim_types = []
      redemption.claims.each do |claim|
        if claim.user_id != payload.user_id
          raise IdentityMismatch, 'claim user_id does not match the signed callback payload'
        end

        Claims.verify_claim(claim, payload.user_domain, domain_key_sets, now)
        verified_claim_types << claim.claim_type
      end

      # 9. Enforce pending.required_claims: this is what the login
      # actually demanded at begin_local_login time. Missing or
      # insufficient (including an entirely empty claim set) is fatal --
      # an IDP cannot silently drop a required claim and still have the
      # login succeed.
      missing_required = (pending.required_claims - verified_claim_types).uniq.sort
      unless missing_required.empty?
        raise RequiredClaimsNotSatisfied,
              "required claim types not satisfied by verified claims: #{missing_required.join(', ')}"
      end

      VerifiedLocalLogin.new(
        user_id: payload.user_id,
        user_domain: payload.user_domain,
        claims: redemption.claims,
        domain_public_keys: user_domain_keys,
        local_rp_fingerprint: key_material.fingerprint,
        issued_at: Timeutil.parse_rfc3339(payload.issued_at),
        expires_at: Timeutil.parse_rfc3339(payload.expires_at),
        ticket_expires_at: Timeutil.parse_rfc3339(redemption.ticket_expires_at)
      )
    end
  end
end
