# frozen_string_literal: true

require 'securerandom'
require_relative 'url_params'
require_relative 'local_rp'
require_relative 'timeutil'

module LinkkeysLocalRp
  # `begin_local_login` (design doc: "SDK API Shape", "Flow" steps 4-6).
  #
  # Pure/offline: no network access happens here. It generates a fresh
  # nonce/state, builds and signs a LocalRpLoginRequest around the
  # identity's already-signed descriptor, and returns a redirect URL plus
  # the pending-login state the app must persist and treat as single-use.
  module Begin
    # Default requested claims when the caller doesn't specify any (design
    # doc, "Default Claim Set"): a usable "identity" out of the box with
    # zero claim configuration.
    DEFAULT_REQUESTED_CLAIMS = %w[display_name email handle].freeze
    # Default required claims (design doc, "Default Claim Set").
    DEFAULT_REQUIRED_CLAIMS = ['handle'].freeze
    # Default login-request lifetime: short-lived, matching the callback's
    # own short default lifetime (design doc: "callback lifetime is short,
    # default 5 minutes").
    DEFAULT_LOGIN_REQUEST_LIFETIME = 5 * 60

    class Error < StandardError; end

    # Input to begin_local_login. Big-config, single struct.
    BeginLocalLoginConfig = Struct.new(
      :key_material, :callback_url, :user_domain, :now,
      :requested_claims, :required_claims, :request_lifetime,
      keyword_init: true
    )

    # The redirect URL the app should send the user's browser to. The SDK
    # never performs the redirect itself (design doc: "Browser-only Flow").
    LocalLoginRedirect = Struct.new(:redirect_url, keyword_init: true)

    # The state begin_local_login returns for the app to persist (e.g. in
    # a server-side session tied to the browser) and pass unchanged to
    # complete_local_login. SINGLE-USE: the app must discard it after one
    # completion attempt -- this package owns no storage and cannot enforce
    # that itself.
    #
    # `required_claims` is retained (not just nonce/state/user_domain/
    # callback_url) so complete_local_login can enforce, against the
    # REDEEMED claims, exactly the claim types this login actually
    # demanded -- an IDP that omits a required claim (or returns none at
    # all) must not be able to complete the login just because the caller
    # forgot to re-check.
    PendingLogin = Struct.new(:nonce, :state, :user_domain, :callback_url, :required_claims, keyword_init: true) do
      # JSON-safe serialization helper (bytes -> hex) so apps can persist
      # this in an ordinary JSON session store without inventing their own
      # encoding.
      def to_h
        {
          'nonce' => nonce.unpack1('H*'),
          'state' => state.unpack1('H*'),
          'user_domain' => user_domain,
          'callback_url' => callback_url,
          'required_claims' => required_claims
        }
      end

      def self.from_h(data)
        new(
          nonce: [data['nonce']].pack('H*'),
          state: [data['state']].pack('H*'),
          user_domain: data['user_domain'],
          callback_url: data['callback_url'],
          required_claims: data['required_claims'] || []
        )
      end
    end

    module_function

    def validate_callback_scheme!(url)
      return if url.start_with?('http://') || url.start_with?('https://')

      raise Error, "callback_url must be http:// or https://, got: #{url.inspect}"
    end
    private_class_method :validate_callback_scheme!

    # `begin_local_login(config) -> [LocalLoginRedirect, PendingLogin]`
    # (design doc, "SDK API Shape"). Generates a fresh nonce/state, builds
    # and signs a LocalRpLoginRequest (envelope +
    # linkkeys-local-rp-login-request context) around the identity's
    # descriptor, and returns the full redirect URL for the user's LinkKeys
    # domain plus the pending-login state.
    def begin_local_login(config)
      validate_callback_scheme!(config.callback_url)
      raise Error, 'user_domain must not be empty' if config.user_domain.nil? || config.user_domain.strip.empty?

      nonce = SecureRandom.random_bytes(32)
      state = SecureRandom.random_bytes(32)

      requested_claims = config.requested_claims || DEFAULT_REQUESTED_CLAIMS.dup
      required_claims = config.required_claims || DEFAULT_REQUIRED_CLAIMS.dup
      lifetime = config.request_lifetime || DEFAULT_LOGIN_REQUEST_LIFETIME
      issued_at = Timeutil.to_rfc3339(config.now)
      expires_at = Timeutil.to_rfc3339(config.now + lifetime)

      request = LocalRp.build_local_rp_login_request(
        config.key_material.descriptor, config.callback_url, nonce, state,
        requested_claims, required_claims, issued_at, expires_at
      )
      signed = LocalRp.sign_local_rp_login_request(request, config.key_material.signing_private_key)

      encoded = UrlParams.signed_local_rp_login_request_to_url_param(signed)

      # Wire Precision: "Begin route: GET /auth/local-rp?signed_request=<...>"
      # -- mirrors the existing GET /auth/authorize?signed_request=... route
      # shape.
      redirect_url = "https://#{config.user_domain}/auth/local-rp?signed_request=#{encoded}"

      [
        LocalLoginRedirect.new(redirect_url: redirect_url),
        PendingLogin.new(
          nonce: nonce, state: state, user_domain: config.user_domain, callback_url: config.callback_url,
          required_claims: required_claims
        )
      ]
    end
  end
end
