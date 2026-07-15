#include "test_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

long g_test_pass = 0;
long g_test_fail = 0;

void t_check_impl(int cond, const char *desc, const char *file, int line) {
    if (cond) {
        g_test_pass++;
    } else {
        g_test_fail++;
        fprintf(stderr, "FAIL: %s (%s:%d)\n", desc, file, line);
    }
}

lrp_bytes t_hex_field(const json_value *obj, const char *key) {
    const char *hex = json_str(json_get(obj, key));
    if (hex == NULL) {
        fprintf(stderr, "fixture error: missing/non-string hex field '%s'\n", key);
        exit(2);
    }
    lrp_bytes out = {0};
    lrp_error err = {0};
    if (lrp_hex_to_bytes(hex, &out, &err) != 0) {
        fprintf(stderr, "fixture error: field '%s' is not valid hex: %s\n", key, err.message);
        exit(2);
    }
    return out;
}

void t_hex_field_fixed(const json_value *obj, const char *key, uint8_t *out, size_t want_len) {
    lrp_bytes b = t_hex_field(obj, key);
    if (b.len != want_len) {
        fprintf(stderr, "fixture error: field '%s' expected %zu bytes, got %zu\n", key, want_len,
                b.len);
        exit(2);
    }
    memcpy(out, b.data, want_len);
    lrp_bytes_free(&b);
}
