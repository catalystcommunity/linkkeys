#include "time_util.h"

#include <stdio.h>
#include <string.h>

#include "error.h"

int64_t lrp_days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= (m <= 2);
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);              /* [0, 399] */
    unsigned doy = (153 * (m + (m > 2 ? (unsigned)-3 : 9)) + 2) / 5 + d - 1; /* [0, 365] */
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;   /* [0, 146096] */
    return era * 146097 + (int64_t)doe - 719468;
}

static void civil_from_days(int64_t z, int64_t *y, unsigned *m, unsigned *d) {
    z += 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);            /* [0, 146096] */
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; /* [0, 399] */
    int64_t yy = (int64_t)yoe + era * 400;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100); /* [0, 365] */
    unsigned mp = (5 * doy + 2) / 153;                      /* [0, 11] */
    unsigned dd = doy - (153 * mp + 2) / 5 + 1;              /* [1, 31] */
    unsigned mm = mp + (mp < 10 ? 3 : (unsigned)-9);
    yy += (mm <= 2);
    *y = yy;
    *m = mm;
    *d = dd;
}

static int parse_uint_fixed(const char *s, size_t n, unsigned *out) {
    unsigned v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (unsigned)(s[i] - '0');
    }
    *out = v;
    return 0;
}

int lrp_parse_rfc3339(const char *s, int64_t *out_unix, lrp_error *err) {
    size_t len = strlen(s);
    /* Minimum: YYYY-MM-DDTHH:MM:SSZ = 20 chars */
    if (len < 20 || s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != 't' && s[10] != ' ') ||
        s[13] != ':' || s[16] != ':') {
        return lrp_fail(err, LRP_ERR_DECODE, "invalid timestamp: bad format");
    }
    unsigned year4, month, day, hour, minute, second;
    if (parse_uint_fixed(s, 4, &year4) != 0 || parse_uint_fixed(s + 5, 2, &month) != 0 ||
        parse_uint_fixed(s + 8, 2, &day) != 0 || parse_uint_fixed(s + 11, 2, &hour) != 0 ||
        parse_uint_fixed(s + 14, 2, &minute) != 0 || parse_uint_fixed(s + 17, 2, &second) != 0) {
        return lrp_fail(err, LRP_ERR_DECODE, "invalid timestamp: non-numeric field");
    }
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60) {
        return lrp_fail(err, LRP_ERR_DECODE, "invalid timestamp: field out of range");
    }

    size_t i = 19;
    /* Optional fractional seconds: .digits (truncated, not used). */
    if (i < len && s[i] == '.') {
        i++;
        while (i < len && s[i] >= '0' && s[i] <= '9') i++;
    }

    int64_t offset_seconds = 0;
    if (i >= len) {
        return lrp_fail(err, LRP_ERR_DECODE, "invalid timestamp: missing timezone");
    }
    if (s[i] == 'Z' || s[i] == 'z') {
        i++;
    } else if (s[i] == '+' || s[i] == '-') {
        int sign = (s[i] == '-') ? -1 : 1;
        i++;
        if (len - i < 5 || s[i + 2] != ':') {
            return lrp_fail(err, LRP_ERR_DECODE, "invalid timestamp: bad timezone offset");
        }
        unsigned oh, om;
        if (parse_uint_fixed(s + i, 2, &oh) != 0 || parse_uint_fixed(s + i + 3, 2, &om) != 0) {
            return lrp_fail(err, LRP_ERR_DECODE, "invalid timestamp: bad timezone offset");
        }
        offset_seconds = sign * (int64_t)(oh * 3600 + om * 60);
        i += 5;
    } else {
        return lrp_fail(err, LRP_ERR_DECODE, "invalid timestamp: bad timezone marker");
    }
    if (i != len) {
        return lrp_fail(err, LRP_ERR_DECODE, "invalid timestamp: trailing characters");
    }

    int64_t days = lrp_days_from_civil((int64_t)year4, month, day);
    int64_t secs = days * 86400 + (int64_t)hour * 3600 + (int64_t)minute * 60 + (int64_t)second;
    secs -= offset_seconds;
    *out_unix = secs;
    return 0;
}

void lrp_format_rfc3339(int64_t unix_seconds, char out[32]) {
    int64_t days = unix_seconds >= 0 ? unix_seconds / 86400 : -((-unix_seconds + 86399) / 86400);
    int64_t rem = unix_seconds - days * 86400;
    if (rem < 0) {
        rem += 86400;
        days -= 1;
    }
    unsigned hour = (unsigned)(rem / 3600);
    unsigned minute = (unsigned)((rem % 3600) / 60);
    unsigned second = (unsigned)(rem % 60);
    int64_t y;
    unsigned m, d;
    civil_from_days(days, &y, &m, &d);
    snprintf(out, 32, "%04lld-%02u-%02uT%02u:%02u:%02u+00:00", (long long)y, m, d, hour, minute,
             second);
}
