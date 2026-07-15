#include "error.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

const char *lrp_error_code_name(lrp_error_code code) {
    switch (code) {
        case LRP_OK: return "ok";
        case LRP_ERR_INVALID_INPUT: return "invalid_input";
        case LRP_ERR_DECODE: return "decode";
        case LRP_ERR_DNS: return "dns";
        case LRP_ERR_TRANSPORT: return "transport";
        case LRP_ERR_TLS: return "tls";
        case LRP_ERR_PROTOCOL: return "protocol";
        case LRP_ERR_SERVER: return "server";
        case LRP_ERR_VERIFICATION: return "verification";
        case LRP_ERR_CLAIM: return "claim";
        case LRP_ERR_NO_TRUSTED_KEYS: return "no_trusted_keys";
        case LRP_ERR_REVOCATION: return "revocation";
        case LRP_ERR_CRYPTO: return "crypto";
        case LRP_ERR_OUT_OF_MEMORY: return "out_of_memory";
        default: return "unknown";
    }
}

int lrp_fail(lrp_error *err, lrp_error_code code, const char *fmt, ...) {
    if (err != NULL) {
        err->code = code;
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err->message, sizeof(err->message), fmt, ap);
        va_end(ap);
    }
    return -1;
}

void lrp_clear_error(lrp_error *err) {
    if (err != NULL) {
        err->code = LRP_OK;
        err->message[0] = '\0';
    }
}
