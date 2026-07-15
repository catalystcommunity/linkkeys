/* Public byte/string buffer ownership helpers (declared in the public
 * header). Kept in their own translation unit since every module touches
 * them. */
#include <openssl/crypto.h> /* OPENSSL_cleanse */
#include <stdlib.h>

#include "linkkeys_local_rp.h"

void lrp_bytes_free(lrp_bytes *b) {
    if (b == NULL) return;
    free(b->data);
    b->data = NULL;
    b->len = 0;
}

void lrp_bytes_free_sensitive(lrp_bytes *b) {
    if (b == NULL) return;
    if (b->data != NULL && b->len > 0) {
        OPENSSL_cleanse(b->data, b->len);
    }
    free(b->data);
    b->data = NULL;
    b->len = 0;
}

void lrp_str_free(lrp_str *s) {
    if (s == NULL) return;
    free(s->data);
    s->data = NULL;
}

void lrp_txt_records_free(lrp_txt_records *r) {
    if (r == NULL) return;
    for (size_t i = 0; i < r->count; i++) free(r->entries[i]);
    free(r->entries);
    r->entries = NULL;
    r->count = 0;
}
