# Deploying LinkKeys at scale

This document covers host and cluster settings for a LinkKeys deployment that
holds many concurrent TCP protocol connections. Read
[Deploy a relying party](DEPLOYING-RP.md) first for the general deployment
model. Read [Load testing the TCP server](load-testing.md) for the measured
numbers behind the settings below.

## The protocol port is not HTTP

The LinkKeys TCP protocol port carries CSIL-RPC over TLS. It is not HTTP.

An HTTP ingress or a Layer-7 (L7) load balancer inspects, buffers, or
terminates the request. This breaks the LinkKeys protocol connection. Do not
put an L7 ingress in front of the TCP protocol port.

Use a Layer-4 (L4), TLS-passthrough path instead. The server does its own
mutual TLS on this port. It authenticates both ends against DNS-published key
fingerprints. A passthrough path must forward the raw TLS bytes without
decrypting them.

[Deploy a relying party](DEPLOYING-RP.md) describes the Gateway API
`TLSRoute`/`TCPRoute` configuration for this passthrough path. Use that
configuration for every LinkKeys deployment that serves TCP protocol
traffic through a gateway, not only for RP deployments.

The browser-facing HTTPS API (`/csil/v1/rpc`, login, and account pages) is
separate. An HTTP ingress or L7 load balancer is correct in front of that
port.

## File-descriptor limits

The server holds one open file descriptor for each open TCP connection, from
`accept()` to close. It needs a process file-descriptor limit above
`TCP_MAX_CONNECTIONS` (default 200,000), plus headroom for the listening
socket, the database connection pool, and log files.

Check the current limit:

```sh
ulimit -n
```

Raise it for the server process. The exact mechanism depends on how you run
the server:

- **systemd**: set `LimitNOFILE=` in the unit file.
- **Docker / containerd**: set `--ulimit nofile=<soft>:<hard>` on the
  container, or the equivalent `ulimits` field in Compose.
- **Kubernetes**: the container's file-descriptor limit normally follows the
  node's default. Raise the node's limit, or set a pod
  `securityContext`/init-container step that raises `RLIMIT_NOFILE` before
  the server starts, if the platform allows it.

The server reports the file-descriptor limit it sees and the configured
`TCP_MAX_CONNECTIONS` in its startup log
(`crates/linkkeys/src/tcp/limits.rs`, `report_fd_and_connection_limits`). It
also logs a warning when `TCP_MAX_CONNECTIONS` leaves little headroom under
the soft limit. Check this log line after every deployment change to either
value.

Also raise the kernel-wide file limits if they are close to the process
limit:

```sh
cat /proc/sys/fs/file-max
cat /proc/sys/fs/nr_open
```

## TCP listen backlog

The listen backlog is the queue of TCP connections the kernel has accepted at
the network layer but the application has not yet called `accept()` on. A
short backlog under a fast connection burst causes the kernel to drop or
reset new connections before the application ever sees them — this looks
like a connection failure to the client, with no log line on the server at
all.

Two settings apply together, and the kernel uses the SMALLER of them:

- `net.core.somaxconn`, the kernel-wide ceiling.
- The backlog value the application passes to `listen()`.

LinkKeys sets the application side with `TCP_LISTEN_BACKLOG`. The default is
`1024`.

The Rust standard library binds a listener with a backlog of 128 and gives no
way to change it. A server that is built for large connection counts cannot
accept that, so LinkKeys calls `listen()` again on the socket with the
configured value. Set both settings together: the kernel uses the smaller one,
so a large `TCP_LISTEN_BACKLOG` does nothing while `net.core.somaxconn` stays
low, and a large `net.core.somaxconn` does nothing while the application asks
for a small queue.

Raise both if the deployment expects a very fast connection burst (many
thousands of new connections in one second). Watch for connection resets under
burst load, because a full backlog gives the client a failure with no log line
on the server.

Check and raise the kernel ceiling:

```sh
cat /proc/sys/net/core/somaxconn
sysctl -w net.core.somaxconn=4096
```

In Kubernetes, set this with a `sysctls` entry in the pod spec (if your
cluster allows unsafe sysctls) or with a node-level configuration.

## Connection tracking

A stateful firewall or a Kubernetes CNI network plugin that uses
`netfilter` conntrack keeps one entry for each active connection, including
long-lived, mostly-idle LinkKeys protocol connections. A conntrack table that
is too small drops new connections silently once it fills, with no error
visible to the application on either end.

Check the current limit and usage:

```sh
cat /proc/sys/net/netfilter/nf_conntrack_max
cat /proc/sys/net/netfilter/nf_conntrack_count
```

Raise `nf_conntrack_max` on the host, or the cluster-equivalent setting, to a
value comfortably above the deployment's expected connection count. Size it
for BOTH sides of a connection through any NAT hop it crosses, and for
short-lived connections (health checks, handshake retries) in addition to
the long-lived established ones.

A pass-through Gateway API `TLSRoute`/`TCPRoute` (see "The protocol port is
not HTTP" above) still passes through the node's or the CNI's own connection
tracking, even though it does not terminate TLS. Raising
`nf_conntrack_max` is still relevant with a passthrough gateway in the path.

## Putting it together

Before a deployment claims a specific connection-count capacity:

1. Set `TCP_MAX_CONNECTIONS` and the file-descriptor limit together, with
   headroom, as described above.
2. Raise `net.core.somaxconn` AND `TCP_LISTEN_BACKLOG` together. The kernel
   uses the smaller of the two.
3. Raise connection-tracking limits on the host or the cluster network path.
4. Confirm the protocol port reaches the server through an L4 passthrough
   path, never an L7 ingress.
5. Run the load-test harness against the actual target hardware and record
   the result, following [Load testing the TCP server](load-testing.md).
   Do not reuse another machine's numbers for a capacity claim.
