/* Minimal RFC3339 <-> unix-seconds conversion. The wire protocol's
 * timestamp fields are RFC3339 text (matching liblinkkeys); this SDK's
 * public API works in int64_t unix seconds for C ergonomics, converting at
 * the boundary. Whole-second precision only (matches claims.rs's own
 * "normalized to whole seconds" discipline) — no fractional seconds are
 * produced, and any fractional seconds on input are truncated. */
#ifndef LRP_INTERNAL_TIME_UTIL_H
#define LRP_INTERNAL_TIME_UTIL_H

#include <stddef.h>
#include <stdint.h>

#include "linkkeys_local_rp.h"

/* Days since 1970-01-01 for a given proleptic-Gregorian civil date
 * (Howard Hinnant's days_from_civil algorithm). Exposed for tests. */
int64_t lrp_days_from_civil(int64_t y, unsigned m, unsigned d);

/* Parse an RFC3339 timestamp (e.g. "2026-01-01T00:00:00+00:00" or
 * "...Z" or with fractional seconds) into unix seconds (UTC). */
int lrp_parse_rfc3339(const char *s, int64_t *out_unix, lrp_error *err);

/* Format unix seconds (UTC) as "YYYY-MM-DDTHH:MM:SS+00:00" into a
 * caller-supplied buffer of at least 32 bytes. */
void lrp_format_rfc3339(int64_t unix_seconds, char out[32]);

#endif
