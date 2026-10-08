// Browser endpoint discovery: resolve an identity domain's browser-facing
// HTTPS base from its `_linkkeys_apis` TXT record, and build browser route
// URLs against it. Mirrors `sdks/local-rp/go/browser.go`.
//
// The identity domain (the domain the user selected, e.g. `todandlorna.com`)
// is a trust and discovery domain. It is not necessarily the host that
// serves the browser login routes -- the `https=` endpoint of
// `_linkkeys_apis.<identity-domain>` is (`docs/spec/trust-and-anchors.md`:
// "`https=` is the browser-facing endpoint"). These helpers are shared by
// [beginLocalLogin] (route [browserRouteLocalRp]) and by regular-RP
// application glue (route [browserRouteAuthorize]), so discovery is
// implemented once.
//
// The resolved base is a service location only. Identity verification stays
// bound to the identity domain -- never bind trust decisions to the host
// these helpers return.
library;

import 'dns/dns.dart' as dnsproto;
import 'dns/dns_resolver.dart';
import 'errors.dart';

/// The browser route for the DNS-less local-RP login flow.
const String browserRouteLocalRp = '/auth/local-rp';

/// The browser route for the regular (domain-keyed) RP login flow.
const String browserRouteAuthorize = '/auth/authorize';

/// Check that [base] is a usable https browser base URL: parseable, `https`
/// scheme, a host, an optional path prefix, and nothing else. A TXT record
/// value must never smuggle in userinfo, a query, a fragment, or (via
/// [dnsproto.parseLinkKeysApisTxt]'s unconditional `https://` prefix plus
/// this check) a non-HTTPS scheme. Throws [SdkException] with kind
/// [SdkExceptionKind.invalidInput] otherwise.
Uri validateBrowserBase(String base) {
  final Uri u;
  try {
    u = Uri.parse(base);
  } on FormatException catch (e) {
    throw SdkException(
        SdkExceptionKind.invalidInput, 'browser base is not a valid URL',
        cause: e);
  }
  if (u.scheme != 'https') {
    throw SdkException(
        SdkExceptionKind.invalidInput, 'browser base must use https');
  }
  if (u.host.isEmpty) {
    throw SdkException(
        SdkExceptionKind.invalidInput, 'browser base has no host');
  }
  if (u.userInfo.isNotEmpty || u.hasQuery || u.hasFragment) {
    throw SdkException(SdkExceptionKind.invalidInput,
        'browser base must be host[:port][/path] only');
  }
  if (u.hasPort && (u.port < 1 || u.port > 65535)) {
    throw SdkException(
        SdkExceptionKind.invalidInput, 'browser base has an invalid port');
  }
  return u;
}

/// Resolve [identityDomain]'s browser-facing HTTPS base URL (e.g.
/// `https://linkkeys.todandlorna.com` or
/// `https://login.example.com/linkkeys`) from its
/// `_linkkeys_apis.<identityDomain>` TXT record, via the injected [dns]
/// resolver.
///
/// It selects the first LinkKeys v1 record whose `https=` endpoint is a
/// valid browser base ([validateBrowserBase]); invalid TXT records and
/// records without `https=` are skipped. It throws when the lookup fails
/// (whatever [dns] throws) or when no record yields a valid base
/// ([SdkException] with kind [SdkExceptionKind.dns]) -- the caller decides
/// the fallback ([beginLocalLogin] falls back to `https://<identityDomain>`).
Future<String> resolveBrowserBase(
    DnsResolver dns, String identityDomain) async {
  final name = dnsproto.linkkeysApisDnsName(identityDomain);
  final txts = await dns.txtLookup(name);
  for (final txt in txts) {
    final String? base;
    try {
      base = dnsproto.parseLinkKeysApisTxt(txt).httpsBase;
    } on DnsParseError {
      continue;
    }
    if (base == null) continue;
    try {
      validateBrowserBase(base);
    } on SdkException {
      continue;
    }
    return base;
  }
  throw SdkException(SdkExceptionKind.dns,
      'no usable $name TXT record with an https= endpoint');
}

/// Build the full browser URL for [route] (e.g. [browserRouteLocalRp]) under
/// [browserBase], carrying [signedRequest] as the `signed_request` query
/// parameter. A path prefix in the base is preserved: base
/// `https://login.example.com/linkkeys` and route `/auth/local-rp` produce
/// `https://login.example.com/linkkeys/auth/local-rp?...`.
///
/// The URL is assembled with [Uri]. `signed_request` values are
/// URL-param-encoded (unpadded base64url) by construction, so query encoding
/// passes them through byte-identically.
String buildBrowserEndpoint(
    String browserBase, String route, String signedRequest) {
  final base = validateBrowserBase(browserBase);
  if (!route.startsWith('/') || route.contains('?') || route.contains('#')) {
    throw SdkException(SdkExceptionKind.invalidInput,
        'route must start with / and carry no query or fragment');
  }
  final prefix = base.path.endsWith('/')
      ? base.path.substring(0, base.path.length - 1)
      : base.path;
  return base.replace(path: '$prefix$route', queryParameters: <String, String>{
    'signed_request': signedRequest
  }).toString();
}

/// The begin-flow composition: discover the identity domain's browser base
/// and build the route URL, falling back to `https://<identityDomain>` when
/// DNS lookup fails, no valid record carries `https=`, or the discovered
/// base is invalid. The fallback preserves the pre-discovery behavior, so a
/// domain that serves its browser routes at the apex keeps working without
/// a `_linkkeys_apis` record.
Future<String> resolveBrowserEndpoint(DnsResolver dns, String identityDomain,
    String route, String signedRequest) async {
  String base;
  try {
    base = await resolveBrowserBase(dns, identityDomain);
  } on Exception {
    base = 'https://$identityDomain';
  }
  return buildBrowserEndpoint(base, route, signedRequest);
}
