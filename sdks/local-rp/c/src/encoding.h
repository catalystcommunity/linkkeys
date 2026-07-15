/* Base64url (unpadded) helpers, matching
 * `crates/liblinkkeys/src/encoding.rs`'s `Base64UrlUnpadded` exactly: the
 * URL-safe alphabet (`-`/`_` in place of `+`/`/`), no padding. Decoding
 * rejects standard-alphabet characters and padding outright (see
 * `url_params.json`'s `padded_base64_rejected` / `standard_alphabet_rejected`
 * negative cases) rather than tolerating them. */
#ifndef LRP_INTERNAL_ENCODING_H
#define LRP_INTERNAL_ENCODING_H

#include "linkkeys_local_rp.h"

int lrp_base64url_encode(const uint8_t *data, size_t len, lrp_str *out, lrp_error *err);
int lrp_base64url_decode(const char *s, lrp_bytes *out, lrp_error *err);

#endif
