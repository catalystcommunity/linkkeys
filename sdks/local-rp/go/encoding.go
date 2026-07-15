package localrp

import (
	"encoding/base64"

	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

// URL parameter encoding helpers — mirrors crates/liblinkkeys/src/encoding.rs.
// All CBOR-in-URL values are base64url-encoded, unpadded (RFC 4648 §5,
// "URL and Filename Safe Alphabet", no `=` padding), matching
// `base64ct::Base64UrlUnpadded` exactly.

func encodeURLParam(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeURLParam(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, &DecodeError{Detail: "base64url decode failed: " + err.Error()}
	}
	return b, nil
}

// SignedLocalRpLoginRequestToURLParam encodes a SignedLocalRpLoginRequest
// for the begin route's `?signed_request=<...>` query parameter (Wire
// Precision: "URL and parameter conventions").
func SignedLocalRpLoginRequestToURLParam(signed api.SignedLocalRpLoginRequest) string {
	return encodeURLParam(api.EncodeSignedLocalRpLoginRequest(signed))
}

// SignedLocalRpLoginRequestFromURLParam decodes a SignedLocalRpLoginRequest
// from its URL-safe string form.
func SignedLocalRpLoginRequestFromURLParam(param string) (*api.SignedLocalRpLoginRequest, error) {
	b, err := decodeURLParam(param)
	if err != nil {
		return nil, err
	}
	v, err := api.DecodeSignedLocalRpLoginRequest(b)
	if err != nil {
		return nil, &DecodeError{Detail: "CBOR decode failed: " + err.Error()}
	}
	return &v, nil
}

// LocalRpEncryptedCallbackToURLParam encodes a LocalRpEncryptedCallback for
// the callback redirect's `&encrypted_token=<...>` query parameter (same
// name/mechanics as the existing DNS-pinned flow's `encrypted_token`
// parameter).
func LocalRpEncryptedCallbackToURLParam(cb api.LocalRpEncryptedCallback) string {
	return encodeURLParam(api.EncodeLocalRpEncryptedCallback(cb))
}

// LocalRpEncryptedCallbackFromURLParam decodes a LocalRpEncryptedCallback
// from its URL-safe string form.
func LocalRpEncryptedCallbackFromURLParam(param string) (*api.LocalRpEncryptedCallback, error) {
	b, err := decodeURLParam(param)
	if err != nil {
		return nil, err
	}
	v, err := api.DecodeLocalRpEncryptedCallback(b)
	if err != nil {
		return nil, &DecodeError{Detail: "CBOR decode failed: " + err.Error()}
	}
	return &v, nil
}
