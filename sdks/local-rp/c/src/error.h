/* Internal error-setting helper shared by every module. See the public
 * header's ownership/error-handling notes: never format key material,
 * nonces, tokens, tickets, or claim values into an error message. */
#ifndef LRP_INTERNAL_ERROR_H
#define LRP_INTERNAL_ERROR_H

#include "linkkeys_local_rp.h"

/* Sets *err (if non-NULL) to code + a printf-style message, truncated to
 * fit LRP_ERROR_MESSAGE_LEN. Always returns -1, so call sites can
 * `return lrp_fail(err, CODE, "...");`. */
int lrp_fail(lrp_error *err, lrp_error_code code, const char *fmt, ...);

/* Clears *err to LRP_OK/"" (if non-NULL). */
void lrp_clear_error(lrp_error *err);

#endif
