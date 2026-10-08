# frozen_string_literal: true

require 'uri'
require_relative 'dns'

module LinkkeysLocalRp
  # Browser endpoint discovery: resolve an identity domain's browser-facing
  # HTTPS base from its `_linkkeys_apis` TXT record, and build browser
  # route URLs against it. Mirrors `sdks/local-rp/go/browser.go`.
  #
  # The identity domain (the domain the user selected, e.g.
  # `todandlorna.com`) is a trust and discovery domain. It is not
  # necessarily the host that serves the browser login routes -- the
  # `https=` endpoint of `_linkkeys_apis.<identity-domain>` is
  # (docs/spec/trust-and-anchors.md: "`https=` is the browser-facing
  # endpoint"). These helpers are shared by `begin_local_login` (route
  # BROWSER_ROUTE_LOCAL_RP) and by regular-RP application glue (route
  # BROWSER_ROUTE_AUTHORIZE), so discovery is implemented once.
  module Browser
    # The browser route for the DNS-less local-RP login flow.
    BROWSER_ROUTE_LOCAL_RP = '/auth/local-rp'

    # The browser route for the regular (domain-keyed) RP login flow.
    BROWSER_ROUTE_AUTHORIZE = '/auth/authorize'

    # The browser route where a grantee asks the user for an act-as grant.
    BROWSER_ROUTE_ACT_AS = '/auth/act-as'

    # A browser base or route is not usable, or no `_linkkeys_apis` record
    # yields a valid `https=` base.
    class Error < StandardError; end

    module_function

    # Check that `base` is a usable https browser base URL: parseable,
    # https scheme, a host, an optional path prefix, and nothing else. A
    # TXT record value must never smuggle in userinfo, a query, a
    # fragment, or (via Dns.parse_linkkeys_apis_txt's unconditional
    # `https://` prefix plus this check) a non-HTTPS scheme.
    def validate_browser_base!(base)
      uri = begin
        URI.parse(base)
      rescue URI::InvalidURIError => e
        raise Error, "browser base #{base.inspect} is not a valid URL: #{e.message}"
      end
      raise Error, "browser base #{base.inspect} must use https" unless uri.scheme == 'https'
      raise Error, "browser base #{base.inspect} has no host" if uri.host.nil? || uri.host.empty?
      if uri.userinfo || uri.query || uri.fragment || base.include?('?') || base.include?('#')
        raise Error, "browser base #{base.inspect} must be host[:port][/path] only"
      end

      uri
    end
    private_class_method :validate_browser_base!

    # Resolve identity_domain's browser-facing HTTPS base URL (e.g.
    # `https://linkkeys.todandlorna.com` or
    # `https://login.example.com/linkkeys`) from its
    # `_linkkeys_apis.<identity_domain>` TXT record.
    #
    # Selects the first LinkKeys v1 record whose `https=` endpoint is a
    # valid browser base; invalid TXT records and records without `https=`
    # are skipped. Raises when the lookup fails (the resolver's own error
    # propagates) or when no record yields a valid base (Browser::Error)
    # -- the caller decides the fallback (begin_local_login falls back to
    # `https://<identity_domain>`).
    #
    # The resolved base is a service location only. Identity verification
    # stays bound to the identity domain -- never bind trust decisions to
    # the host this returns.
    def resolve_browser_base(dns, identity_domain)
      name = Dns.linkkeys_apis_dns_name(identity_domain)
      dns.txt_lookup(name).each do |txt|
        https_base = begin
          Dns.parse_linkkeys_apis_txt(txt).https_base
        rescue Dns::DnsParseError
          next
        end
        next if https_base.nil?

        begin
          validate_browser_base!(https_base)
        rescue Error
          next
        end
        return https_base
      end
      raise Error, "no usable #{name} TXT record with an https= endpoint"
    end

    # Build the full browser URL for `route` (e.g. BROWSER_ROUTE_LOCAL_RP)
    # under `browser_base`, carrying `signed_request` as the
    # `signed_request` query parameter. A path prefix in the base is
    # preserved: base `https://login.example.com/linkkeys` and route
    # `/auth/local-rp` produce
    # `https://login.example.com/linkkeys/auth/local-rp?...`.
    #
    # The URL is assembled with stdlib URI. `signed_request` values are
    # URL-param-encoded (unpadded base64url) by construction, so query
    # encoding passes them through byte-identically.
    def build_browser_endpoint(browser_base, route, signed_request)
      uri = validate_browser_base!(browser_base)
      raise Error, "route #{route.inspect} must start with /" unless route.start_with?('/')

      uri.path = uri.path.sub(%r{/+\z}, '') + route
      uri.query = URI.encode_www_form('signed_request' => signed_request)
      uri.to_s
    end

    # The begin-flow composition: discover the identity domain's browser
    # base and build the route URL, falling back to
    # `https://<identity_domain>` when DNS lookup fails, no valid record
    # carries `https=`, or the discovered base is invalid. The fallback
    # preserves the pre-discovery behavior, so a domain that serves its
    # browser routes at the apex keeps working without a `_linkkeys_apis`
    # record.
    def resolve_browser_endpoint(dns, identity_domain, route, signed_request)
      base = begin
        resolve_browser_base(dns, identity_domain)
      rescue StandardError
        # Any lookup/selection failure falls back, as in Go.
        "https://#{identity_domain}"
      end
      build_browser_endpoint(base, route, signed_request)
    end
  end
end
