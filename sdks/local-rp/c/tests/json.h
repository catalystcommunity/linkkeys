/* A minimal, hand-written JSON parser for the TEST harness only — the
 * library itself never needs JSON (see the task brief: "the library
 * itself must not need JSON"). This is not a vendored third-party file;
 * it is scoped exactly to what sdks/local-rp/conformance/ (*.json) needs:
 * objects, arrays, strings (with `\"`, `\\`, `\/`, `\n` etc. and `\uXXXX`
 * escapes, including surrogate pairs), numbers, booleans, and null. No
 * external dependency is introduced. */
#ifndef LRP_TEST_JSON_H
#define LRP_TEST_JSON_H

#include <stddef.h>

typedef enum json_type {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT,
} json_type;

typedef struct json_value json_value;
struct json_value {
    json_type type;
    int bool_val;
    double num_val;
    char *str_val; /* JSON_STRING, NUL-terminated UTF-8 */
    json_value *items;
    size_t items_len; /* JSON_ARRAY */
    char **keys;
    json_value *objs;
    size_t obj_len; /* JSON_OBJECT, parallel arrays */
};

/* Parses the whole file at `path` and returns the root value, or NULL on
 * any I/O or parse error (prints a diagnostic to stderr). */
json_value *json_parse_file(const char *path);
void json_free(json_value *v);

/* NULL if `obj` is not a JSON_OBJECT or `key` is absent. */
const json_value *json_get(const json_value *obj, const char *key);
/* NULL if `v` is NULL or not a JSON_STRING. */
const char *json_str(const json_value *v);
/* 0 if `v` is NULL, not JSON_ARRAY, or index out of range. */
const json_value *json_at(const json_value *arr, size_t index);
size_t json_len(const json_value *arr_or_obj);
int json_is_null_or_absent(const json_value *v);
int json_bool(const json_value *v);

#endif
