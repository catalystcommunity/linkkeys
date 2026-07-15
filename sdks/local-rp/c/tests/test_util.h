#ifndef LRP_TEST_UTIL_H
#define LRP_TEST_UTIL_H

#include "json.h"
#include "linkkeys_local_rp.h"

extern long g_test_pass;
extern long g_test_fail;

void t_check_impl(int cond, const char *desc, const char *file, int line);
#define T_CHECK(cond, desc) t_check_impl((cond), (desc), __FILE__, __LINE__)

/* Decode a required hex-string field of `obj` named `key` into freshly
 * allocated bytes. Aborts the test process on a malformed fixture (a bug
 * in the fixture/generator, not something a test case should silently
 * ignore). */
lrp_bytes t_hex_field(const json_value *obj, const char *key);
void t_hex_field_fixed(const json_value *obj, const char *key, uint8_t *out, size_t want_len);

int run_conformance_tests(void);
int run_flow_tests(void);

#endif
