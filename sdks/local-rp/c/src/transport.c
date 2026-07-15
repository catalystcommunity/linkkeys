/* The TCP dial seam's default implementation: a plain blocking TCP dialer.
 *
 * Wire Precision is explicit that SDKs must NOT inherit a server-side
 * SSRF guard as their *default*: "connecting from a LAN box to wherever
 * `_linkkeys_apis` points is the entire point of this mode." The default
 * policy here is LRP_ADDRESS_PERMISSIVE; LRP_ADDRESS_PUBLIC_ONLY is an
 * opt-in for integrators who specifically want that stricter posture.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "error.h"
#include "linkkeys_local_rp.h"

#define LRP_CONNECT_TIMEOUT_SECONDS 10
#define LRP_IO_TIMEOUT_SECONDS 30

static int is_non_public_v4(const struct sockaddr_in *sa) {
    uint32_t ip = ntohl(sa->sin_addr.s_addr);
    uint8_t a = (uint8_t)(ip >> 24), b = (uint8_t)(ip >> 16);
    if (a == 127) return 1;                          /* loopback */
    if (a == 10) return 1;                            /* RFC1918 */
    if (a == 172 && (b & 0xf0) == 16) return 1;        /* RFC1918 */
    if (a == 192 && b == 168) return 1;                /* RFC1918 */
    if (a == 169 && b == 254) return 1;                /* link-local */
    if (a == 100 && (b & 0xc0) == 64) return 1;         /* CGNAT 100.64.0.0/10 */
    if (ip == 0) return 1;                              /* unspecified */
    if (ip == 0xffffffffu) return 1;                    /* broadcast */
    return 0;
}

static int is_non_public_v6(const struct sockaddr_in6 *sa) {
    const uint8_t *b = sa->sin6_addr.s6_addr;
    static const uint8_t loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t unspecified[16] = {0};
    if (memcmp(b, loopback, 16) == 0) return 1;
    if (memcmp(b, unspecified, 16) == 0) return 1;
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return 1; /* link-local fe80::/10 */
    if ((b[0] & 0xfe) == 0xfc) return 1;                  /* ULA fc00::/7 */
    if (b[0] == 0xff) return 1;                            /* multicast */
    /* IPv4-mapped ::ffff:a.b.c.d */
    static const uint8_t v4mapped_prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (memcmp(b, v4mapped_prefix, 12) == 0) {
        struct sockaddr_in v4;
        memset(&v4, 0, sizeof(v4));
        memcpy(&v4.sin_addr, b + 12, 4);
        return is_non_public_v4(&v4);
    }
    return 0;
}

static int is_non_public_addr(const struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) return is_non_public_v4((const struct sockaddr_in *)sa);
    if (sa->sa_family == AF_INET6) return is_non_public_v6((const struct sockaddr_in6 *)sa);
    return 1;
}

typedef struct fd_conn_ctx {
    int fd;
} fd_conn_ctx;

static long fd_conn_read(lrp_conn *self, uint8_t *buf, size_t len) {
    fd_conn_ctx *ctx = (fd_conn_ctx *)self->ctx;
    ssize_t n = recv(ctx->fd, buf, len, 0);
    return (long)n;
}

static long fd_conn_write(lrp_conn *self, const uint8_t *buf, size_t len) {
    fd_conn_ctx *ctx = (fd_conn_ctx *)self->ctx;
    size_t total = 0;
    while (total < len) {
        /* MSG_NOSIGNAL (Linux/glibc): a peer that closed its read side
         * must surface as an ordinary -1/EPIPE return, never SIGPIPE
         * killing the embedding application. Not POSIX-portable (e.g.
         * macOS uses SO_NOSIGPIPE instead); acceptable for this SDK's
         * documented Linux/glibc/OpenSSL toolchain target. */
        ssize_t n = send(ctx->fd, buf + total, len - total, MSG_NOSIGNAL);
        if (n <= 0) return total > 0 ? (long)total : (long)n;
        total += (size_t)n;
    }
    return (long)total;
}

static void fd_conn_close(lrp_conn *self) {
    fd_conn_ctx *ctx = (fd_conn_ctx *)self->ctx;
    if (ctx != NULL) {
        if (ctx->fd >= 0) close(ctx->fd);
        free(ctx);
    }
    self->ctx = NULL;
}

static int split_host_port(const char *host_port, char *host_out, size_t host_out_len,
                            char *port_out, size_t port_out_len) {
    const char *colon = strrchr(host_port, ':');
    if (colon == NULL) return -1;
    size_t host_len = (size_t)(colon - host_port);
    if (host_len == 0 || host_len >= host_out_len) return -1;
    memcpy(host_out, host_port, host_len);
    host_out[host_len] = '\0';
    if (host_out[0] == '[' && host_out[host_len - 1] == ']') {
        memmove(host_out, host_out + 1, host_len - 2);
        host_out[host_len - 2] = '\0';
    }
    size_t port_len = strlen(colon + 1);
    if (port_len == 0 || port_len >= port_out_len) return -1;
    memcpy(port_out, colon + 1, port_len + 1);
    return 0;
}

static int default_dial(lrp_transport *self, const char *host_port, lrp_conn *out_conn,
                         lrp_error *err) {
    lrp_address_policy policy = (lrp_address_policy)(intptr_t)self->ctx;

    char host[256], port[32];
    if (split_host_port(host_port, host, sizeof(host), port, sizeof(port)) != 0) {
        return lrp_fail(err, LRP_ERR_TRANSPORT, "%s: could not split host:port", host_port);
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    int gai = getaddrinfo(host, port, &hints, &res);
    if (gai != 0) {
        return lrp_fail(err, LRP_ERR_TRANSPORT, "%s: resolve failed: %s", host_port,
                         gai_strerror(gai));
    }

    int fd = -1;
    int denied = 0;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        if (policy == LRP_ADDRESS_PUBLIC_ONLY && is_non_public_addr(rp->ai_addr)) {
            denied = 1;
            continue;
        }
        int s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s < 0) continue;

        int flags = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags | O_NONBLOCK);

        int crc = connect(s, rp->ai_addr, rp->ai_addrlen);
        if (crc == 0) {
            fd = s;
        } else if (errno == EINPROGRESS) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(s, &wfds);
            struct timeval tv;
            tv.tv_sec = LRP_CONNECT_TIMEOUT_SECONDS;
            tv.tv_usec = 0;
            int sel = select(s + 1, NULL, &wfds, NULL, &tv);
            if (sel > 0) {
                int soerr = 0;
                socklen_t soerr_len = sizeof(soerr);
                getsockopt(s, SOL_SOCKET, SO_ERROR, &soerr, &soerr_len);
                if (soerr == 0) fd = s;
            }
        }

        if (fd == s) {
            fcntl(s, F_SETFL, flags); /* restore blocking mode */
            struct timeval io_tv;
            io_tv.tv_sec = LRP_IO_TIMEOUT_SECONDS;
            io_tv.tv_usec = 0;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &io_tv, sizeof(io_tv));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &io_tv, sizeof(io_tv));
            break;
        }
        close(s);
    }
    freeaddrinfo(res);

    if (fd < 0) {
        if (denied) {
            return lrp_fail(err, LRP_ERR_TRANSPORT,
                             "%s: refusing non-public address under LRP_ADDRESS_PUBLIC_ONLY",
                             host_port);
        }
        return lrp_fail(err, LRP_ERR_TRANSPORT, "%s: connect failed", host_port);
    }

    fd_conn_ctx *ctx = (fd_conn_ctx *)malloc(sizeof(fd_conn_ctx));
    if (ctx == NULL) {
        close(fd);
        return lrp_fail(err, LRP_ERR_OUT_OF_MEMORY, "out of memory");
    }
    ctx->fd = fd;
    out_conn->ctx = ctx;
    out_conn->read = fd_conn_read;
    out_conn->write = fd_conn_write;
    out_conn->close = fd_conn_close;
    return 0;
}

lrp_transport lrp_default_transport(lrp_address_policy policy) {
    lrp_transport t;
    t.ctx = (void *)(intptr_t)policy;
    t.dial = default_dial;
    return t;
}
