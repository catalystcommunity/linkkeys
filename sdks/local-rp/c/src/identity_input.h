/* Identity input parsing ("user@domain" or "domain"), shared by
 * begin_local_login (begin.c) and the act-as grantee calls (act_as.c), so
 * both accept exactly the same input. */
#ifndef LRP_INTERNAL_IDENTITY_INPUT_H
#define LRP_INTERNAL_IDENTITY_INPUT_H

#include "linkkeys_local_rp.h"

typedef struct {
    char username[65];
    char domain[260]; /* lowercased identity domain */
    int has_username;
} lrp_parsed_identity_input;

/* Parse and validate a LinkKeys login ("username@domain") or a bare
 * domain. Fails with LRP_ERR_INVALID_INPUT. */
int lrp_parse_identity_input(const char *value, lrp_parsed_identity_input *out, lrp_error *err);

#endif
