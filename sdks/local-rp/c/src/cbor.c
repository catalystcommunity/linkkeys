#include "cbor.h"

#include <stdlib.h>
#include <string.h>

#include "error.h"

/* --------------------------------------------------------------------- */
/* Writer                                                                 */
/* --------------------------------------------------------------------- */

void cbor_buf_init(cbor_buf *b) {
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void cbor_buf_free(cbor_buf *b) {
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

lrp_bytes cbor_buf_release(cbor_buf *b) {
    lrp_bytes out;
    out.data = b->data;
    out.len = b->len;
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
    return out;
}

static int buf_reserve(cbor_buf *b, size_t extra) {
    if (b->len + extra <= b->cap) return 0;
    size_t new_cap = b->cap == 0 ? 64 : b->cap * 2;
    while (new_cap < b->len + extra) new_cap *= 2;
    uint8_t *n = (uint8_t *)realloc(b->data, new_cap);
    if (n == NULL) return -1;
    b->data = n;
    b->cap = new_cap;
    return 0;
}

int cbor_write_raw(cbor_buf *b, const uint8_t *data, size_t len) {
    if (buf_reserve(b, len) != 0) return -1;
    if (len > 0) memcpy(b->data + b->len, data, len);
    b->len += len;
    return 0;
}

static int write_head(cbor_buf *b, uint8_t major, uint64_t n) {
    uint8_t m = (uint8_t)(major << 5);
    if (n < 24) {
        uint8_t byte = (uint8_t)(m | (uint8_t)n);
        return cbor_write_raw(b, &byte, 1);
    } else if (n <= 0xffULL) {
        uint8_t tmp[2] = {(uint8_t)(m | 24), (uint8_t)n};
        return cbor_write_raw(b, tmp, 2);
    } else if (n <= 0xffffULL) {
        uint8_t tmp[3];
        tmp[0] = (uint8_t)(m | 25);
        tmp[1] = (uint8_t)(n >> 8);
        tmp[2] = (uint8_t)n;
        return cbor_write_raw(b, tmp, 3);
    } else if (n <= 0xffffffffULL) {
        uint8_t tmp[5];
        tmp[0] = (uint8_t)(m | 26);
        tmp[1] = (uint8_t)(n >> 24);
        tmp[2] = (uint8_t)(n >> 16);
        tmp[3] = (uint8_t)(n >> 8);
        tmp[4] = (uint8_t)n;
        return cbor_write_raw(b, tmp, 5);
    } else {
        uint8_t tmp[9];
        tmp[0] = (uint8_t)(m | 27);
        for (int i = 0; i < 8; i++) tmp[1 + i] = (uint8_t)(n >> (56 - 8 * i));
        return cbor_write_raw(b, tmp, 9);
    }
}

int cbor_write_uint(cbor_buf *b, uint64_t v) { return write_head(b, 0, v); }

int cbor_write_text(cbor_buf *b, const char *s, size_t len) {
    if (write_head(b, 3, len) != 0) return -1;
    return cbor_write_raw(b, (const uint8_t *)s, len);
}

int cbor_write_text_cstr(cbor_buf *b, const char *s) { return cbor_write_text(b, s, strlen(s)); }

int cbor_write_opt_text_cstr(cbor_buf *b, const char *s) {
    if (s == NULL) return cbor_write_null(b);
    return cbor_write_text_cstr(b, s);
}

int cbor_write_bytes(cbor_buf *b, const uint8_t *data, size_t len) {
    if (write_head(b, 2, len) != 0) return -1;
    return cbor_write_raw(b, data, len);
}

int cbor_write_opt_bytes(cbor_buf *b, const uint8_t *data, size_t len, int present) {
    if (!present) return cbor_write_null(b);
    return cbor_write_bytes(b, data, len);
}

int cbor_write_array_header(cbor_buf *b, size_t n) { return write_head(b, 4, n); }
int cbor_write_map_header(cbor_buf *b, size_t n) { return write_head(b, 5, n); }

int cbor_write_bool(cbor_buf *b, int v) {
    uint8_t byte = v ? 0xf5 : 0xf4;
    return cbor_write_raw(b, &byte, 1);
}

int cbor_write_null(cbor_buf *b) {
    uint8_t byte = 0xf6;
    return cbor_write_raw(b, &byte, 1);
}

int cbor_write_tag_head(cbor_buf *b, uint64_t tag) { return write_head(b, 6, tag); }

int cbor_write_tag24(cbor_buf *b, const uint8_t *payload, size_t len) {
    if (cbor_write_tag_head(b, 24) != 0) return -1;
    return cbor_write_bytes(b, payload, len);
}

static int compare_encoded_keys(const void *pa, const void *pb) {
    const cbor_map_entry *const *a = (const cbor_map_entry *const *)pa;
    const cbor_map_entry *const *b = (const cbor_map_entry *const *)pb;
    cbor_buf ka, kb;
    cbor_buf_init(&ka);
    cbor_buf_init(&kb);
    cbor_write_text_cstr(&ka, (*a)->key);
    cbor_write_text_cstr(&kb, (*b)->key);
    size_t min_len = ka.len < kb.len ? ka.len : kb.len;
    int cmp = memcmp(ka.data, kb.data, min_len);
    if (cmp == 0) {
        if (ka.len < kb.len) cmp = -1;
        else if (ka.len > kb.len) cmp = 1;
    }
    cbor_buf_free(&ka);
    cbor_buf_free(&kb);
    return cmp;
}

int cbor_write_canon_map(cbor_buf *out, cbor_map_entry *entries, size_t n) {
    if (n == 0) return cbor_write_map_header(out, 0);
    const cbor_map_entry **order = (const cbor_map_entry **)malloc(n * sizeof(*order));
    if (order == NULL) return -1;
    for (size_t i = 0; i < n; i++) order[i] = &entries[i];
    qsort(order, n, sizeof(*order), compare_encoded_keys);

    int rc = cbor_write_map_header(out, n);
    for (size_t i = 0; rc == 0 && i < n; i++) {
        rc = cbor_write_text_cstr(out, order[i]->key);
        if (rc == 0) rc = cbor_write_raw(out, order[i]->value_data, order[i]->value_len);
    }
    free(order);
    return rc;
}

/* --------------------------------------------------------------------- */
/* Decoder                                                                */
/* --------------------------------------------------------------------- */

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} cursor;

static int cur_need(cursor *c, size_t n, lrp_error *err) {
    if ((size_t)(c->end - c->p) < n) {
        return lrp_fail(err, LRP_ERR_DECODE, "CBOR: unexpected end of input");
    }
    return 0;
}

static int read_arg(cursor *c, uint8_t info, uint64_t *out, lrp_error *err) {
    if (info < 24) {
        *out = info;
        return 0;
    }
    switch (info) {
        case 24: {
            if (cur_need(c, 1, err) != 0) return -1;
            *out = c->p[0];
            c->p += 1;
            return 0;
        }
        case 25: {
            if (cur_need(c, 2, err) != 0) return -1;
            *out = ((uint64_t)c->p[0] << 8) | c->p[1];
            c->p += 2;
            return 0;
        }
        case 26: {
            if (cur_need(c, 4, err) != 0) return -1;
            *out = ((uint64_t)c->p[0] << 24) | ((uint64_t)c->p[1] << 16) |
                   ((uint64_t)c->p[2] << 8) | c->p[3];
            c->p += 4;
            return 0;
        }
        case 27: {
            if (cur_need(c, 8, err) != 0) return -1;
            uint64_t v = 0;
            for (int i = 0; i < 8; i++) v = (v << 8) | c->p[i];
            c->p += 8;
            *out = v;
            return 0;
        }
        default:
            return lrp_fail(err, LRP_ERR_DECODE, "CBOR: indefinite-length or reserved item unsupported");
    }
}

static int decode_item(cursor *c, cbor_value *out, lrp_error *err, int depth);

static void value_init_zero(cbor_value *v) { memset(v, 0, sizeof(*v)); }

/* Bounds a declared array/map element COUNT against what could possibly
 * still fit in the remaining input, BEFORE that count is used to size an
 * allocation (SEC fix, DoS/SF-5/M2): a definite-length array/map header can
 * declare up to 2^64-1 items while the actual buffer backing it might be a
 * handful of bytes, so trusting the declared count directly (as
 * `calloc(n, sizeof(cbor_value))` did) lets a tiny malicious/corrupt input
 * drive a multi-exabyte allocation attempt. Every array item takes at least
 * 1 encoded byte and every map entry (key + value) takes at least 2, so
 * `remaining / min_bytes_per_item` is a safe upper bound on how many items
 * could possibly be present — exactly mirroring the check the byte/text
 * string cases already get for free from `cur_need`. */
static int declared_count_fits_remaining(const cursor *c, uint64_t n, size_t min_bytes_per_item) {
    size_t remaining = (size_t)(c->end - c->p);
    return n <= (uint64_t)(remaining / min_bytes_per_item);
}

static int decode_array_items(cursor *c, size_t n, cbor_value **items, lrp_error *err, int depth) {
    if (n == 0) {
        *items = NULL;
        return 0;
    }
    cbor_value *arr = (cbor_value *)calloc(n, sizeof(cbor_value));
    if (arr == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
    for (size_t i = 0; i < n; i++) {
        if (decode_item(c, &arr[i], err, depth + 1) != 0) {
            /* free the entries successfully built before this failure */
            cbor_value tmp;
            tmp.type = CBOR_T_ARRAY;
            tmp.items = arr;
            tmp.items_len = i;
            cbor_value_free(&tmp);
            return -1;
        }
    }
    *items = arr;
    return 0;
}

static int decode_item(cursor *c, cbor_value *out, lrp_error *err, int depth) {
    if (depth > 64) return lrp_fail(err, LRP_ERR_DECODE, "CBOR: nesting too deep");
    if (cur_need(c, 1, err) != 0) return -1;
    uint8_t first = c->p[0];
    c->p += 1;
    uint8_t major = (uint8_t)(first >> 5);
    uint8_t info = (uint8_t)(first & 0x1f);
    value_init_zero(out);

    uint64_t n;
    switch (major) {
        case 0: /* unsigned int */
            if (read_arg(c, info, &n, err) != 0) return -1;
            out->type = CBOR_T_UINT;
            out->uint_val = n;
            return 0;
        case 1: /* negative int */
            if (read_arg(c, info, &n, err) != 0) return -1;
            out->type = CBOR_T_NEGINT;
            out->uint_val = n;
            return 0;
        case 2: /* byte string */
            if (read_arg(c, info, &n, err) != 0) return -1;
            if (cur_need(c, (size_t)n, err) != 0) return -1;
            out->type = CBOR_T_BYTES;
            out->bytes_len = (size_t)n;
            out->bytes = (uint8_t *)malloc(n > 0 ? (size_t)n : 1);
            if (out->bytes == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
            if (n > 0) memcpy(out->bytes, c->p, (size_t)n);
            c->p += n;
            return 0;
        case 3: /* text string */
            if (read_arg(c, info, &n, err) != 0) return -1;
            if (cur_need(c, (size_t)n, err) != 0) return -1;
            out->type = CBOR_T_TEXT;
            out->bytes_len = (size_t)n;
            out->bytes = (uint8_t *)malloc((size_t)n + 1);
            if (out->bytes == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
            if (n > 0) memcpy(out->bytes, c->p, (size_t)n);
            out->bytes[n] = '\0';
            c->p += n;
            return 0;
        case 4: /* array */
            if (read_arg(c, info, &n, err) != 0) return -1;
            if (!declared_count_fits_remaining(c, n, 1)) {
                return lrp_fail(err, LRP_ERR_DECODE,
                                 "CBOR: array declares %llu items, more than the remaining input "
                                 "could possibly hold",
                                 (unsigned long long)n);
            }
            out->type = CBOR_T_ARRAY;
            out->items_len = (size_t)n;
            if (decode_array_items(c, (size_t)n, &out->items, err, depth) != 0) return -1;
            return 0;
        case 5: { /* map */
            if (read_arg(c, info, &n, err) != 0) return -1;
            if (!declared_count_fits_remaining(c, n, 2)) {
                return lrp_fail(err, LRP_ERR_DECODE,
                                 "CBOR: map declares %llu entries, more than the remaining input "
                                 "could possibly hold",
                                 (unsigned long long)n);
            }
            out->type = CBOR_T_MAP;
            out->map_len = (size_t)n;
            if (n == 0) {
                out->map_keys = NULL;
                out->map_vals = NULL;
                return 0;
            }
            out->map_keys = (cbor_value *)calloc((size_t)n, sizeof(cbor_value));
            out->map_vals = (cbor_value *)calloc((size_t)n, sizeof(cbor_value));
            if (out->map_keys == NULL || out->map_vals == NULL) {
                /* M2 fix: one calloc can succeed while the other fails —
                 * free whichever succeeded instead of leaking it. */
                free(out->map_keys);
                free(out->map_vals);
                out->map_keys = NULL;
                out->map_vals = NULL;
                out->map_len = 0;
                return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
            }
            for (size_t i = 0; i < n; i++) {
                if (decode_item(c, &out->map_keys[i], err, depth + 1) != 0) {
                    out->map_len = i;
                    cbor_value_free(out);
                    value_init_zero(out);
                    return -1;
                }
                if (decode_item(c, &out->map_vals[i], err, depth + 1) != 0) {
                    /* key i decoded, value i not: free key i manually, then
                     * treat as if only i entries were built */
                    cbor_value_free(&out->map_keys[i]);
                    out->map_len = i;
                    cbor_value_free(out);
                    value_init_zero(out);
                    return -1;
                }
            }
            return 0;
        }
        case 6: { /* tag */
            if (read_arg(c, info, &n, err) != 0) return -1;
            out->type = CBOR_T_TAG;
            out->tag = n;
            out->tag_inner = (cbor_value *)calloc(1, sizeof(cbor_value));
            if (out->tag_inner == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
            if (decode_item(c, out->tag_inner, err, depth + 1) != 0) {
                free(out->tag_inner);
                out->tag_inner = NULL;
                return -1;
            }
            return 0;
        }
        case 7: { /* simple/float */
            switch (info) {
                case 20:
                    out->type = CBOR_T_BOOL;
                    out->bool_val = 0;
                    return 0;
                case 21:
                    out->type = CBOR_T_BOOL;
                    out->bool_val = 1;
                    return 0;
                case 22:
                case 23:
                    out->type = CBOR_T_NULL;
                    return 0;
                default:
                    return lrp_fail(err, LRP_ERR_DECODE,
                                     "CBOR: unsupported simple/float value (info=%u)", info);
            }
        }
        default:
            return lrp_fail(err, LRP_ERR_DECODE, "CBOR: unreachable major type");
    }
}

int cbor_decode(const uint8_t *data, size_t len, cbor_value **out, lrp_error *err) {
    cursor c;
    c.p = data;
    c.end = data + len;
    cbor_value *root = (cbor_value *)calloc(1, sizeof(cbor_value));
    if (root == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
    if (decode_item(&c, root, err, 0) != 0) {
        free(root);
        return -1;
    }
    if (c.p != c.end) {
        cbor_value_free(root);
        free(root);
        return lrp_fail(err, LRP_ERR_DECODE, "CBOR: trailing bytes after item");
    }
    *out = root;
    return 0;
}

void cbor_value_free(cbor_value *v) {
    if (v == NULL) return;
    switch (v->type) {
        case CBOR_T_BYTES:
        case CBOR_T_TEXT:
            free(v->bytes);
            v->bytes = NULL;
            break;
        case CBOR_T_ARRAY:
            for (size_t i = 0; i < v->items_len; i++) cbor_value_free(&v->items[i]);
            free(v->items);
            v->items = NULL;
            break;
        case CBOR_T_MAP:
            for (size_t i = 0; i < v->map_len; i++) {
                cbor_value_free(&v->map_keys[i]);
                cbor_value_free(&v->map_vals[i]);
            }
            free(v->map_keys);
            free(v->map_vals);
            v->map_keys = NULL;
            v->map_vals = NULL;
            break;
        case CBOR_T_TAG:
            cbor_value_free(v->tag_inner);
            free(v->tag_inner);
            v->tag_inner = NULL;
            break;
        default:
            break;
    }
}

const cbor_value *cbor_map_get(const cbor_value *map, const char *key) {
    if (map == NULL || map->type != CBOR_T_MAP) return NULL;
    size_t klen = strlen(key);
    for (size_t i = 0; i < map->map_len; i++) {
        const cbor_value *k = &map->map_keys[i];
        if (k->type == CBOR_T_TEXT && k->bytes_len == klen && memcmp(k->bytes, key, klen) == 0) {
            return &map->map_vals[i];
        }
    }
    return NULL;
}

int cbor_as_text(const cbor_value *v, lrp_str *out, lrp_error *err) {
    if (v == NULL || v->type != CBOR_T_TEXT) {
        return lrp_fail(err, LRP_ERR_DECODE, "CBOR: expected text string");
    }
    out->data = (char *)malloc(v->bytes_len + 1);
    if (out->data == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
    memcpy(out->data, v->bytes, v->bytes_len);
    out->data[v->bytes_len] = '\0';
    return 0;
}

int cbor_as_bytes(const cbor_value *v, lrp_bytes *out, lrp_error *err) {
    if (v == NULL || v->type != CBOR_T_BYTES) {
        return lrp_fail(err, LRP_ERR_DECODE, "CBOR: expected byte string");
    }
    if (v->bytes_len == 0) {
        out->data = NULL;
        out->len = 0;
        return 0;
    }
    out->data = (uint8_t *)malloc(v->bytes_len);
    if (out->data == NULL) return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "CBOR: out of memory");
    memcpy(out->data, v->bytes, v->bytes_len);
    out->len = v->bytes_len;
    return 0;
}

int cbor_get_text(const cbor_value *map, const char *key, lrp_str *out, lrp_error *err) {
    const cbor_value *v = cbor_map_get(map, key);
    if (v == NULL) return lrp_fail(err, LRP_ERR_DECODE, "CBOR: missing required field '%s'", key);
    return cbor_as_text(v, out, err);
}

int cbor_get_bytes(const cbor_value *map, const char *key, lrp_bytes *out, lrp_error *err) {
    const cbor_value *v = cbor_map_get(map, key);
    if (v == NULL) return lrp_fail(err, LRP_ERR_DECODE, "CBOR: missing required field '%s'", key);
    return cbor_as_bytes(v, out, err);
}

int cbor_get_uint(const cbor_value *map, const char *key, uint64_t *out, lrp_error *err) {
    const cbor_value *v = cbor_map_get(map, key);
    if (v == NULL || v->type != CBOR_T_UINT) {
        return lrp_fail(err, LRP_ERR_DECODE, "CBOR: missing or non-integer field '%s'", key);
    }
    *out = v->uint_val;
    return 0;
}

int cbor_get_array(const cbor_value *map, const char *key, const cbor_value **out, lrp_error *err) {
    const cbor_value *v = cbor_map_get(map, key);
    if (v == NULL || v->type != CBOR_T_ARRAY) {
        return lrp_fail(err, LRP_ERR_DECODE, "CBOR: missing or non-array field '%s'", key);
    }
    *out = v;
    return 0;
}

void cbor_get_text_opt(const cbor_value *map, const char *key, lrp_str *out) {
    out->data = NULL;
    const cbor_value *v = cbor_map_get(map, key);
    if (v == NULL || v->type != CBOR_T_TEXT) return;
    lrp_error tmp = {0};
    (void)cbor_as_text(v, out, &tmp);
}

void cbor_get_bytes_opt(const cbor_value *map, const char *key, lrp_bytes *out) {
    out->data = NULL;
    out->len = 0;
    const cbor_value *v = cbor_map_get(map, key);
    if (v == NULL || v->type != CBOR_T_BYTES) return;
    lrp_error tmp = {0};
    (void)cbor_as_bytes(v, out, &tmp);
}

void cbor_get_bool_opt(const cbor_value *map, const char *key, int *present, int *value) {
    *present = 0;
    const cbor_value *v = cbor_map_get(map, key);
    if (v == NULL || v->type != CBOR_T_BOOL) return;
    *present = 1;
    *value = v->bool_val;
}
