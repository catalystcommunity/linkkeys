// `beginLocalLogin` (design doc: "SDK API Shape", "Flow" steps 4-6).
//
// Pure/offline: no network access happens here. It generates a fresh
// nonce/state, builds and signs a `LocalRpLoginRequest` around the
// identity's already-signed descriptor, and returns a redirect URL plus the
// pending-login state the app must persist and treat as single-use.
library;

import 'dart:typed_data';

import 'crypto/crypto.dart';
import 'encoding.dart';
import 'errors.dart';
import 'identity.dart';
import 'local_rp.dart';
import 'rfc3339.dart';

/// Default requested claims when the caller doesn't specify any (design
/// doc, "Default Claim Set").
const List<String> defaultRequestedClaims = ['display_name', 'email', 'handle'];

/// Default required claims (design doc, "Default Claim Set").
const List<String> defaultRequiredClaims = ['handle'];

/// Default login-request lifetime: short-lived, matching the callback's own
/// short default lifetime.
const Duration defaultLoginRequestLifetime = Duration(minutes: 5);

/// Input to [beginLocalLogin]. Big-config, single class.
class BeginLocalLoginConfig {
  final LocalRpKeyMaterial keyMaterial;
  final String callbackUrl;
  final String userDomain;
  final List<String>? requestedClaims;
  final List<String>? requiredClaims;
  final Duration? requestLifetime;
  final DateTime now;

  const BeginLocalLoginConfig({
    required this.keyMaterial,
    required this.callbackUrl,
    required this.userDomain,
    this.requestedClaims,
    this.requiredClaims,
    this.requestLifetime,
    required this.now,
  });
}

/// The redirect URL the app should send the user's browser to. This SDK
/// never performs the redirect itself.
class LocalLoginRedirect {
  final String redirectUrl;
  const LocalLoginRedirect(this.redirectUrl);
}

/// The state [beginLocalLogin] returns for the app to persist (e.g. in a
/// server-side session tied to the browser) and pass unchanged to
/// `completeLocalLogin`. **Single-use**: the app must discard it after one
/// completion attempt.
class PendingLogin {
  final Uint8List nonce;
  final Uint8List state;
  final String userDomain;
  final String callbackUrl;

  /// The claim types this login required. `completeLocalLogin` re-checks
  /// this set against the redemption's verified claims -- it must
  /// round-trip through whatever storage the app persists [PendingLogin]
  /// in, so a login that began requiring e.g. `handle` can't complete
  /// without it just because the requirement was forgotten between `begin`
  /// and `complete`.
  final List<String> requiredClaims;

  const PendingLogin({
    required this.nonce,
    required this.state,
    required this.userDomain,
    required this.callbackUrl,
    required this.requiredClaims,
  });
}

class BeginResult {
  final LocalLoginRedirect redirect;
  final PendingLogin pending;
  const BeginResult(this.redirect, this.pending);
}

void _validateCallbackScheme(String url) {
  if (!(url.startsWith('http://') || url.startsWith('https://'))) {
    throw SdkException(SdkExceptionKind.invalidInput,
        'callback_url must be http:// or https://, got: $url');
  }
}

/// `begin_local_login(config) -> (LocalLoginRedirect, PendingLogin)` (design
/// doc, "SDK API Shape"). Generates a fresh nonce/state, builds and signs a
/// `LocalRpLoginRequest` around the identity's descriptor, and returns the
/// full redirect URL plus the pending-login state.
Future<BeginResult> beginLocalLogin(BeginLocalLoginConfig config) async {
  _validateCallbackScheme(config.callbackUrl);
  if (config.userDomain.trim().isEmpty) {
    throw SdkException(
        SdkExceptionKind.invalidInput, 'user_domain must not be empty');
  }

  final nonce = Crypto.randomBytes(32);
  final state = Crypto.randomBytes(32);

  final requestedClaims = config.requestedClaims ?? defaultRequestedClaims;
  final requiredClaims = config.requiredClaims ?? defaultRequiredClaims;
  final lifetime = config.requestLifetime ?? defaultLoginRequestLifetime;
  final issuedAt = Rfc3339.format(config.now);
  final expiresAt = Rfc3339.format(config.now.add(lifetime));

  final request = LocalRp.buildLocalRpLoginRequest(
    config.keyMaterial.descriptor,
    config.callbackUrl,
    nonce,
    state,
    requestedClaims,
    requiredClaims,
    issuedAt,
    expiresAt,
  );
  final signed = await LocalRp.signLocalRpLoginRequest(
      request, config.keyMaterial.signingPrivateKey);

  final encoded = signedLocalRpLoginRequestToUrlParam(signed);

  // Wire Precision: "Begin route: GET /auth/local-rp?signed_request=<...>".
  final redirectUrl =
      'https://${config.userDomain}/auth/local-rp?signed_request=$encoded';

  return BeginResult(
    LocalLoginRedirect(redirectUrl),
    PendingLogin(
      nonce: nonce,
      state: state,
      userDomain: config.userDomain,
      callbackUrl: config.callbackUrl,
      requiredClaims: requiredClaims,
    ),
  );
}
