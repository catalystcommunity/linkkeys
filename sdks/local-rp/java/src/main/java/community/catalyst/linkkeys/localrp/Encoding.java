package community.catalyst.linkkeys.localrp;

import java.util.Base64;

import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpEncryptedCallback;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpLoginRequest;

/**
 * URL parameter encoding helpers &mdash; mirrors
 * {@code crates/liblinkkeys/src/encoding.rs} / {@code sdks/local-rp/go/encoding.go}.
 * All CBOR-in-URL values are base64url-encoded, unpadded (RFC 4648
 * &sect;5), matching {@code base64ct::Base64UrlUnpadded} exactly: no
 * standard-alphabet ({@code +}/{@code /}) characters, no {@code =} padding.
 */
public final class Encoding {
    private Encoding() {}

    static String encodeUrlParam(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static byte[] decodeUrlParam(String s) {
        if (s.indexOf('=') >= 0) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "padded base64 is not accepted (expected unpadded base64url)");
        }
        if (s.indexOf('+') >= 0 || s.indexOf('/') >= 0) {
            throw new SdkException(
                    SdkException.Kind.INVALID_INPUT, "standard base64 alphabet is not accepted (expected base64url)");
        }
        try {
            return Base64.getUrlDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw new SdkException(SdkException.Kind.INVALID_INPUT, "base64url decode failed: " + e.getMessage(), e);
        }
    }

    /** Encode for the begin route's {@code ?signed_request=<...>} query parameter. */
    public static String signedLocalRpLoginRequestToUrlParam(SignedLocalRpLoginRequest signed) {
        return encodeUrlParam(Codec.encodeSignedLocalRpLoginRequest(signed));
    }

    public static SignedLocalRpLoginRequest signedLocalRpLoginRequestFromUrlParam(String param) {
        return Codec.decodeSignedLocalRpLoginRequest(decodeUrlParam(param));
    }

    /** Encode for the callback redirect's {@code &encrypted_token=<...>} query parameter. */
    public static String localRpEncryptedCallbackToUrlParam(LocalRpEncryptedCallback callback) {
        return encodeUrlParam(Codec.encodeLocalRpEncryptedCallback(callback));
    }

    public static LocalRpEncryptedCallback localRpEncryptedCallbackFromUrlParam(String param) {
        return Codec.decodeLocalRpEncryptedCallback(decodeUrlParam(param));
    }
}
