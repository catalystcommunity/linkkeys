// URL parameter encoding helpers -- mirrors
// `crates/liblinkkeys/src/encoding.rs` / the Rust/Go/Java reference SDKs'
// own `encoding` modules. All CBOR-in-URL values are base64url-encoded,
// unpadded (RFC 4648 section 5), matching `base64ct::Base64UrlUnpadded`
// exactly: no standard-alphabet (`+`/`/`) characters, no `=` padding.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'errors.dart';
import 'wire/codec.dart';
import 'wire/types.dart';

String encodeUrlParam(List<int> b) => base64Url.encode(b).replaceAll('=', '');

Uint8List decodeUrlParam(String s) {
  if (s.contains('=')) {
    throw SdkException(SdkExceptionKind.invalidInput,
        'padded base64 is not accepted (expected unpadded base64url)');
  }
  if (s.contains('+') || s.contains('/')) {
    throw SdkException(SdkExceptionKind.invalidInput,
        'standard base64 alphabet is not accepted (expected base64url)');
  }
  try {
    final padded = _addPadding(s);
    return base64Url.decode(padded);
  } on FormatException catch (e) {
    throw SdkException(
        SdkExceptionKind.invalidInput, 'base64url decode failed: ${e.message}',
        cause: e);
  }
}

String _addPadding(String s) {
  final mod = s.length % 4;
  if (mod == 0) return s;
  return s + ('=' * (4 - mod));
}

/// Encode for the begin route's `?signed_request=<...>` query parameter.
String signedLocalRpLoginRequestToUrlParam(SignedLocalRpLoginRequest signed) =>
    encodeUrlParam(Codec.encodeSignedLocalRpLoginRequest(signed));

SignedLocalRpLoginRequest signedLocalRpLoginRequestFromUrlParam(String param) =>
    Codec.decodeSignedLocalRpLoginRequest(decodeUrlParam(param));

/// Encode for the callback redirect's `&encrypted_token=<...>` query
/// parameter.
String localRpEncryptedCallbackToUrlParam(LocalRpEncryptedCallback callback) =>
    encodeUrlParam(Codec.encodeLocalRpEncryptedCallback(callback));

LocalRpEncryptedCallback localRpEncryptedCallbackFromUrlParam(String param) =>
    Codec.decodeLocalRpEncryptedCallback(decodeUrlParam(param));
