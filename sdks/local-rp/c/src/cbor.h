/* Minimal CBOR support for this SDK: a growable-buffer WRITER (used to
 * encode CSIL types and the small tuple/array signature-input
 * constructions) and a generic value-tree DECODER (used to parse
 * CSIL-type maps, RPC responses, and conformance vectors, all of which may
 * have arbitrary/unknown field order).
 *
 * This deliberately does NOT attempt to be a general-purpose CBOR library:
 * only definite-length arrays/maps, byte/text strings, unsigned/negative
 * integers, simple bool/null, and tag 24 (encoded-CBOR) are supported —
 * exactly what CSIL's generated codec and the CSIL-RPC transport envelope
 * use (see csilgen's `codec.gen.rs`/`csil-rpc-transport.md`). Encoding uses
 * RFC 8949's shortest-form (preferred) length encoding throughout, matching
 * `ciborium`'s own output.
 *
 * Field-order note: the generated Rust codec decodes CSIL type maps by KEY
 * LOOKUP (`cbor_require`/`cbor_map_get` by string, not position), so this
 * SDK's own encoder is free to choose any field order for structures it
 * builds and signs (descriptor, login request, ticket redemption) — see
 * `types.c`. The CSIL-RPC envelope is the one place a SPECIFIC (sorted)
 * key order is required by spec (`csil-rpc-transport.md` /
 * `csilgen-transport::conventions::canon_map`); `cbor_write_canon_map`
 * implements that.
 */
#ifndef LRP_INTERNAL_CBOR_H
#define LRP_INTERNAL_CBOR_H

#include <stddef.h>
#include <stdint.h>

#include "linkkeys_local_rp.h"

/* --------------------------------------------------------------------- */
/* Writer                                                                 */
/* --------------------------------------------------------------------- */

typedef struct cbor_buf {
    uint8_t *data;
    size_t len;
    size_t cap;
} cbor_buf;

void cbor_buf_init(cbor_buf *b);
/* Frees the buffer without handing ownership anywhere (use when abandoning
 * a partially-built encode on an error path). */
void cbor_buf_free(cbor_buf *b);
/* Hands ownership of the accumulated bytes to the caller as lrp_bytes,
 * resetting *b to empty. */
lrp_bytes cbor_buf_release(cbor_buf *b);

int cbor_write_raw(cbor_buf *b, const uint8_t *data, size_t len);
int cbor_write_uint(cbor_buf *b, uint64_t v);
int cbor_write_text(cbor_buf *b, const char *s, size_t len);
int cbor_write_text_cstr(cbor_buf *b, const char *s);
/* Writes `s` as text if non-NULL, else CBOR null (mirrors an Option<&str>
 * field inside a struct, e.g. local_domain_hint). */
int cbor_write_opt_text_cstr(cbor_buf *b, const char *s);
int cbor_write_bytes(cbor_buf *b, const uint8_t *data, size_t len);
/* Writes `data`/`len` as a byte string if data non-NULL (len may be 0 for
 * an explicit empty byte string), else CBOR null. */
int cbor_write_opt_bytes(cbor_buf *b, const uint8_t *data, size_t len, int present);
int cbor_write_array_header(cbor_buf *b, size_t n);
int cbor_write_map_header(cbor_buf *b, size_t n);
int cbor_write_bool(cbor_buf *b, int v);
int cbor_write_null(cbor_buf *b);
int cbor_write_tag_head(cbor_buf *b, uint64_t tag);
/* Tag 24 (encoded-CBOR item): tag head + byte string of `payload`. */
int cbor_write_tag24(cbor_buf *b, const uint8_t *payload, size_t len);

/* One entry for `cbor_write_canon_map`: `key` and the ALREADY-ENCODED CBOR
 * bytes of the value (build with the writer functions above into a
 * temporary cbor_buf, then pass buf.data/buf.len here). */
typedef struct cbor_map_entry {
    const char *key;
    const uint8_t *value_data;
    size_t value_len;
} cbor_map_entry;

/* Writes a definite-length map whose entries are sorted by the bytewise
 * lexicographic order of their ENCODED keys (RFC 8949 core deterministic
 * encoding) — the CSIL-RPC envelope's required canonical form. Does not
 * take ownership of `entries[i].value_data`. */
int cbor_write_canon_map(cbor_buf *out, cbor_map_entry *entries, size_t n);

/* --------------------------------------------------------------------- */
/* Decoder (generic value tree)                                          */
/* --------------------------------------------------------------------- */

typedef enum cbor_type {
    CBOR_T_UINT,
    CBOR_T_NEGINT, /* real value == -1 - uint_val */
    CBOR_T_BYTES,
    CBOR_T_TEXT,
    CBOR_T_ARRAY,
    CBOR_T_MAP,
    CBOR_T_BOOL,
    CBOR_T_NULL,
    CBOR_T_TAG,
} cbor_type;

typedef struct cbor_value cbor_value;
struct cbor_value {
    cbor_type type;
    uint64_t uint_val;
    uint8_t *bytes;     /* CBOR_T_BYTES / CBOR_T_TEXT; NUL-terminated when TEXT */
    size_t bytes_len;
    cbor_value *items;  /* CBOR_T_ARRAY */
    size_t items_len;
    cbor_value *map_keys; /* CBOR_T_MAP, parallel to map_vals */
    cbor_value *map_vals;
    size_t map_len;
    int bool_val;
    uint64_t tag;
    cbor_value *tag_inner; /* CBOR_T_TAG */
};

/* Decode exactly one CBOR item from data[0..len). Rejects trailing bytes
 * after the item, matching the house convention that an envelope/payload
 * is a single self-contained CBOR item. On success *out is heap-allocated;
 * free with cbor_value_free. */
int cbor_decode(const uint8_t *data, size_t len, cbor_value **out, lrp_error *err);
void cbor_value_free(cbor_value *v);

/* Look up a text key in a CBOR_T_MAP value. Returns NULL if not a map or
 * key absent. */
const cbor_value *cbor_map_get(const cbor_value *map, const char *key);

/* Required-field accessors: fail with LRP_ERR_DECODE if the key is absent
 * or the wrong type. */
int cbor_get_text(const cbor_value *map, const char *key, lrp_str *out, lrp_error *err);
int cbor_get_bytes(const cbor_value *map, const char *key, lrp_bytes *out, lrp_error *err);
int cbor_get_uint(const cbor_value *map, const char *key, uint64_t *out, lrp_error *err);
int cbor_get_array(const cbor_value *map, const char *key, const cbor_value **out, lrp_error *err);

/* Optional-field accessors: leave *out unset (NULL data / 0 len) and
 * return 0 when the key is absent OR present with the wrong type (mirrors
 * the generated Rust codec's get_text_opt/get_uint_opt, which do the
 * same). Never fail. */
void cbor_get_text_opt(const cbor_value *map, const char *key, lrp_str *out);
void cbor_get_bytes_opt(const cbor_value *map, const char *key, lrp_bytes *out);
void cbor_get_bool_opt(const cbor_value *map, const char *key, int *present, int *value);

/* Direct value accessors (for array elements, not map fields). */
int cbor_as_text(const cbor_value *v, lrp_str *out, lrp_error *err);
int cbor_as_bytes(const cbor_value *v, lrp_bytes *out, lrp_error *err);

#endif
