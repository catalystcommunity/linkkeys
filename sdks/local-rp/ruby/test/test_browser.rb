# frozen_string_literal: true

# Browser endpoint discovery tests, ported from
# `sdks/local-rp/go/browser_test.go`. Every resolver here is a hermetic
# fake with canned TXT answers -- no test in this file performs a live DNS
# request.

require_relative 'test_helper'

class TestBrowser < Minitest::Test
  # A hermetic DNS resolver with canned TXT answers per name.
  class MapDnsResolver
    def initialize(records, error: nil)
      @records = records
      @error = error
    end

    def txt_lookup(name)
      raise @error if @error
      return @records[name] if @records.key?(name)

      raise "no fake record for #{name}"
    end
  end

  BROWSER_TEST_DOMAIN = 'ident.example.test'
  CALLBACK_URL = 'http://app.lan:8080/cb'
  NOW = Time.utc(2026, 8, 17, 12, 0, 0)
  KEY_MATERIAL = LinkkeysLocalRp.generate_local_rp_identity(
    LinkkeysLocalRp::Identity::GenerateLocalRpIdentityConfig.new(app_name: 'browser-test', now: NOW)
  )

  def apis_resolver(*txts)
    MapDnsResolver.new({ "_linkkeys_apis.#{BROWSER_TEST_DOMAIN}" => txts })
  end

  def failing_resolver
    MapDnsResolver.new({}, error: RuntimeError.new('SERVFAIL'))
  end

  def begin_with(dns)
    config = LinkkeysLocalRp::Begin::BeginLocalLoginConfig.new(
      key_material: KEY_MATERIAL, callback_url: CALLBACK_URL, user_domain: BROWSER_TEST_DOMAIN, now: NOW, dns: dns
    )
    redirect, pending = LinkkeysLocalRp.begin_local_login(config)
    [redirect, pending, config]
  end

  # Case 1: a valid https= host is used for the redirect instead of the
  # identity domain. Case 8: PendingLogin#user_domain stays the identity
  # domain -- verification stays bound to it, not to the service host.
  def test_begin_uses_discovered_https_host
    redirect, pending, = begin_with(
      apis_resolver('v=lk1 tcp=linkkeys.ident.example.test https=linkkeys.ident.example.test')
    )
    assert redirect.redirect_url.start_with?('https://linkkeys.ident.example.test/auth/local-rp?signed_request='),
           redirect.redirect_url
    refute redirect.redirect_url.start_with?("https://#{BROWSER_TEST_DOMAIN}/"), redirect.redirect_url
    assert_equal BROWSER_TEST_DOMAIN, pending.user_domain
  end

  # Case 2: an https= value with a path prefix preserves that prefix.
  def test_begin_preserves_https_path_prefix
    redirect, = begin_with(apis_resolver('v=lk1 https=login.example.test/linkkeys'))
    assert redirect.redirect_url.start_with?('https://login.example.test/linkkeys/auth/local-rp?signed_request='),
           redirect.redirect_url
  end

  # Case 3: a record with only tcp= falls back to the identity domain.
  def test_begin_tcp_only_record_falls_back_to_identity_domain
    redirect, = begin_with(apis_resolver('v=lk1 tcp=linkkeys.ident.example.test'))
    assert redirect.redirect_url.start_with?("https://#{BROWSER_TEST_DOMAIN}/auth/local-rp?signed_request="),
           redirect.redirect_url
  end

  # Case 4: a DNS lookup error falls back to the identity domain.
  def test_begin_dns_error_falls_back_to_identity_domain
    redirect, = begin_with(failing_resolver)
    assert redirect.redirect_url.start_with?("https://#{BROWSER_TEST_DOMAIN}/auth/local-rp?signed_request="),
           redirect.redirect_url
  end

  # Cases 5 + 6: invalid TXT records are ignored, and across several
  # records the FIRST valid record with https= is selected.
  def test_begin_selects_first_valid_https_across_records
    redirect, = begin_with(apis_resolver(
                             'not a linkkeys record',
                             'v=lk2 https=wrong-version.example.test',
                             'v=lk1 tcp=tcp-only.example.test',
                             'v=lk1 https=first.example.test',
                             'v=lk1 https=second.example.test'
                           ))
    assert redirect.redirect_url.start_with?('https://first.example.test/auth/local-rp?signed_request='),
           redirect.redirect_url
  end

  # Case 7: signed_request rides the discovered URL unchanged -- it decodes
  # to the signed login request whose fields match this login.
  def test_begin_signed_request_survives_discovered_url
    redirect, pending, config = begin_with(apis_resolver('v=lk1 https=login.example.test/linkkeys'))
    query = URI.decode_www_form(URI.parse(redirect.redirect_url).query).to_h
    param = query['signed_request']
    refute_nil param, 'signed_request query parameter missing'
    signed = LinkkeysLocalRp::UrlParams.signed_local_rp_login_request_from_url_param(param)
    request = LinkkeysLocalRp::Types::LocalRpLoginRequest.from_cbor(signed.request)
    assert_equal config.callback_url, request.callback_url
    assert_equal pending.nonce, request.nonce
  end

  # Case 9: a config without `dns` still constructs (this test is that
  # caller) and the default is the system resolver. The default path is not
  # executed here -- that would be a live DNS request.
  def test_begin_config_without_resolver_still_constructs
    config = LinkkeysLocalRp::Begin::BeginLocalLoginConfig.new(
      key_material: KEY_MATERIAL, callback_url: CALLBACK_URL, user_domain: BROWSER_TEST_DOMAIN, now: NOW
    )
    assert_nil config.dns
    assert_respond_to LinkkeysLocalRp::Dns::SystemDnsResolver.new, :txt_lookup
  end

  # ---------------------------------------------------------------
  # Direct tests for the exported helpers
  # ---------------------------------------------------------------

  def test_resolve_browser_base
    base = LinkkeysLocalRp.resolve_browser_base(
      apis_resolver('v=lk1 tcp=x.example.test https=login.example.test:8443/linkkeys'), BROWSER_TEST_DOMAIN
    )
    assert_equal 'https://login.example.test:8443/linkkeys', base

    # A record whose https= value smuggles URL structure is skipped; with
    # no other candidate, resolution raises so the caller can fall back.
    [
      'v=lk1 https=user@evil.example.test',
      'v=lk1 https=evil.example.test/x?y=1',
      'v=lk1 https=evil.example.test/x#frag',
      'v=lk1 tcp=only.example.test'
    ].each do |hostile|
      assert_raises(LinkkeysLocalRp::Browser::Error, hostile) do
        LinkkeysLocalRp.resolve_browser_base(apis_resolver(hostile), BROWSER_TEST_DOMAIN)
      end
    end

    assert_raises(RuntimeError) { LinkkeysLocalRp.resolve_browser_base(failing_resolver, BROWSER_TEST_DOMAIN) }
  end

  def test_build_browser_endpoint
    assert_equal 'https://h.example.test/auth/local-rp?signed_request=PAYLOAD-123_abc',
                 LinkkeysLocalRp.build_browser_endpoint('https://h.example.test',
                                                        LinkkeysLocalRp::Browser::BROWSER_ROUTE_LOCAL_RP, 'PAYLOAD-123_abc')

    # Path prefix, with and without a trailing slash, and the regular-RP
    # route -- the same helper serves /auth/authorize glue.
    ['https://h.example.test/pfx', 'https://h.example.test/pfx/'].each do |base|
      assert_equal 'https://h.example.test/pfx/auth/authorize?signed_request=s',
                   LinkkeysLocalRp.build_browser_endpoint(base, LinkkeysLocalRp::Browser::BROWSER_ROUTE_AUTHORIZE, 's')
    end

    # A non-HTTPS scheme must never be selectable.
    ['http://h.example.test', 'ftp://h.example.test', 'https://', 'https://u:p@h.example.test'].each do |bad|
      assert_raises(LinkkeysLocalRp::Browser::Error, bad) do
        LinkkeysLocalRp.build_browser_endpoint(bad, LinkkeysLocalRp::Browser::BROWSER_ROUTE_LOCAL_RP, 's')
      end
    end
    assert_raises(LinkkeysLocalRp::Browser::Error) do
      LinkkeysLocalRp.build_browser_endpoint('https://h.example.test', 'auth/no-leading-slash', 's')
    end
  end
end
