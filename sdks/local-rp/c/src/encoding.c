#include "encoding.h"

#include <stdlib.h>
#include <string.h>

#include "error.h"

static const char B64URL_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int lrp_base64url_encode(const uint8_t *data, size_t len, lrp_str *out, lrp_error *err) {
    size_t out_len = (len + 2) / 3 * 4;
    char *buf = (char *)malloc(out_len + 1);
    if (buf == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    size_t oi = 0;
    size_t i = 0;
    while (i + 3 <= len) {
        uint32_t n = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | data[i + 2];
        buf[oi++] = B64URL_ALPHABET[(n >> 18) & 0x3f];
        buf[oi++] = B64URL_ALPHABET[(n >> 12) & 0x3f];
        buf[oi++] = B64URL_ALPHABET[(n >> 6) & 0x3f];
        buf[oi++] = B64URL_ALPHABET[n & 0x3f];
        i += 3;
    }
    size_t rem = len - i;
    if (rem == 1) {
        uint32_t n = (uint32_t)data[i] << 16;
        buf[oi++] = B64URL_ALPHABET[(n >> 18) & 0x3f];
        buf[oi++] = B64URL_ALPHABET[(n >> 12) & 0x3f];
    } else if (rem == 2) {
        uint32_t n = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8);
        buf[oi++] = B64URL_ALPHABET[(n >> 18) & 0x3f];
        buf[oi++] = B64URL_ALPHABET[(n >> 12) & 0x3f];
        buf[oi++] = B64URL_ALPHABET[(n >> 6) & 0x3f];
    }
    buf[oi] = '\0';
    out->data = buf;
    return 0;
}

static int b64url_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1; /* includes '+' , '/' , '=' , and anything else */
}

int lrp_base64url_decode(const char *s, lrp_bytes *out, lrp_error *err) {
    size_t len = strlen(s);
    if (len % 4 == 1) {
        return lrp_fail(err, LRP_ERR_DECODE, "base64url: invalid length");
    }
    size_t out_cap = (len / 4 + 1) * 3;
    uint8_t *buf = (uint8_t *)malloc(out_cap > 0 ? out_cap : 1);
    if (buf == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    size_t oi = 0;
    int vals[4];
    size_t group = 0;
    for (size_t i = 0; i < len; i++) {
        int v = b64url_val(s[i]);
        if (v < 0) {
            free(buf);
            return lrp_fail(err, LRP_ERR_DECODE,
                             "base64url: invalid character (standard alphabet or padding not accepted)");
        }
        vals[group++] = v;
        if (group == 4) {
            uint32_t n = ((uint32_t)vals[0] << 18) | ((uint32_t)vals[1] << 12) |
                         ((uint32_t)vals[2] << 6) | (uint32_t)vals[3];
            buf[oi++] = (uint8_t)(n >> 16);
            buf[oi++] = (uint8_t)(n >> 8);
            buf[oi++] = (uint8_t)n;
            group = 0;
        }
    }
    if (group == 2) {
        uint32_t n = ((uint32_t)vals[0] << 18) | ((uint32_t)vals[1] << 12);
        buf[oi++] = (uint8_t)(n >> 16);
    } else if (group == 3) {
        uint32_t n = ((uint32_t)vals[0] << 18) | ((uint32_t)vals[1] << 12) | ((uint32_t)vals[2] << 6);
        buf[oi++] = (uint8_t)(n >> 16);
        buf[oi++] = (uint8_t)(n >> 8);
    } else if (group == 1) {
        free(buf);
        return lrp_fail(err, LRP_ERR_DECODE, "base64url: invalid trailing group length");
    }
    out->data = buf;
    out->len = oi;
    return 0;
}
