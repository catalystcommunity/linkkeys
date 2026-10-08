/* Browser endpoint discovery — internal composition and helpers shared by
 * begin.c. The exported API (lrp_resolve_browser_base,
 * lrp_build_browser_endpoint, LRP_BROWSER_ROUTE_*) lives in the public
 * header; see src/browser.c for the design notes. */
#ifndef LRP_INTERNAL_BROWSER_H
#define LRP_INTERNAL_BROWSER_H

#include "linkkeys_local_rp.h"

/* The begin-flow composition: discover identity_domain's browser base and
 * build the route URL, falling back to `https://<identity_domain>` when DNS
 * lookup fails, no valid record carries https=, or the discovered base is
 * invalid. `dns` must be non-NULL (begin.c substitutes the default
 * resolver). */
int lrp_resolve_browser_endpoint(lrp_dns_resolver *dns, const char *identity_domain,
                                 const char *route, const char *signed_request, lrp_str *out,
                                 lrp_error *err);

/* Percent-encode one query-parameter VALUE with the RFC 3986 unreserved set
 * (ALPHA / DIGIT / "-" / "." / "_" / "~" pass through; everything else
 * becomes %XX). Heap-allocated; free with lrp_str_free. Base64url (the
 * signed_request encoding) is entirely unreserved, so it passes through
 * byte-identically. */
int lrp_percent_encode_query_value(const char *value, lrp_str *out, lrp_error *err);

#endif
