// Base64url (unpadded) URL-param encode/decode helpers, mirroring
// `crates/liblinkkeys/src/encoding.rs`'s local-RP subset. Wire Precision:
// "All CBOR-in-URL values are base64url-encoded, unpadded" — Node's
// `Buffer` `"base64url"` encoding already omits padding, so no extra
// stripping step is needed on encode; on decode we explicitly reject
// standard-alphabet and padded input rather than silently tolerating it
// (Node's base64url decoder is otherwise lenient about mixed input).

import * as generated from "./generated/codec.gen.ts";
import type { LocalRpEncryptedCallback, SignedLocalRpLoginRequest } from "./generated/types.gen.ts";

export class DecodeError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "DecodeError";
  }
}

const BASE64URL_UNPADDED_RE = /^[A-Za-z0-9_-]*$/;

function base64UrlUnpaddedEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/**
 * Strict base64url decode: rejects standard-alphabet characters (`+`/`/`)
 * and padding (`=`) rather than tolerating them, so a malformed/adversarial
 * URL parameter can never silently pass as a valid one (see
 * `sdks/local-rp/conformance/url_params.json`'s `padded_base64_rejected` and
 * `standard_alphabet_rejected` negative cases).
 */
function base64UrlUnpaddedDecode(param: string): Uint8Array {
  if (!BASE64URL_UNPADDED_RE.test(param)) {
    throw new DecodeError(`not valid unpadded base64url: ${JSON.stringify(param)}`);
  }
  return new Uint8Array(Buffer.from(param, "base64url"));
}

/**
 * Encode a `SignedLocalRpLoginRequest` to a URL-safe string, for the
 * `GET /auth/local-rp?signed_request=<...>` begin route.
 */
export function signedLocalRpLoginRequestToUrlParam(signed: SignedLocalRpLoginRequest): string {
  return base64UrlUnpaddedEncode(generated.toSignedLocalRpLoginRequestCbor(signed));
}

export function signedLocalRpLoginRequestFromUrlParam(param: string): SignedLocalRpLoginRequest {
  const cborBytes = base64UrlUnpaddedDecode(param);
  try {
    return generated.fromSignedLocalRpLoginRequestCbor(cborBytes);
  } catch (e) {
    throw new DecodeError(`CBOR decode failed: ${e}`, { cause: e });
  }
}

/**
 * Encode a `LocalRpEncryptedCallback` to a URL-safe string, for the
 * `encrypted_token=<...>` callback-delivery query parameter.
 */
export function localRpEncryptedCallbackToUrlParam(callback: LocalRpEncryptedCallback): string {
  return base64UrlUnpaddedEncode(generated.toLocalRpEncryptedCallbackCbor(callback));
}

export function localRpEncryptedCallbackFromUrlParam(param: string): LocalRpEncryptedCallback {
  const cborBytes = base64UrlUnpaddedDecode(param);
  try {
    return generated.fromLocalRpEncryptedCallbackCbor(cborBytes);
  } catch (e) {
    throw new DecodeError(`CBOR decode failed: ${e}`, { cause: e });
  }
}
