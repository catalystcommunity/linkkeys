#include <signal.h>
#include <stdio.h>

#include "test_util.h"

int main(void) {
    /* The flow tests' fake IDP server (tests/test_flow.c) uses raw SSL_write
     * over an accept()ed socket; a client that has already moved on (e.g.
     * a negative-case test that closes its connection early) can otherwise
     * deliver SIGPIPE and kill this test binary outright. This is test
     * harness plumbing only — the library itself (src/transport.c) uses
     * MSG_NOSIGNAL on its own sends and never relies on this. */
    signal(SIGPIPE, SIG_IGN);

    run_conformance_tests();
    run_flow_tests();

    printf("\n==== %ld passed, %ld failed ====\n", g_test_pass, g_test_fail);
    return g_test_fail > 0 ? 1 : 0;
}
