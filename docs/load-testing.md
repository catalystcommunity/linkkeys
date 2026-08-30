# Load testing the TCP server

This document explains the connection, handshake, cache, and DDoS-control
load-test harness. It also records one real measurement run.

Read this document before you make a capacity claim about a LinkKeys
deployment. A connection-count target is not proof that a specific machine
meets it. Only a load test on that machine is proof.

## The rule this document follows

A deployment must not claim support for a large number of connections until a
load test records the hardware, the operating-system limits, the memory use,
and the traffic pattern. This document states which numbers below are
MEASURED and which are DEFAULT SETTINGS. It does not turn a small measured run
into a claim about a larger one.

A connection-count target is not a claim about handshake speed. Holding many
connections open and completing many handshakes per second are different
limits. This document reports them as different numbers.

## The tool

`crates/linkkeys/loadtest` is a separate crate. The build system does not
include it in `cargo build --workspace` or `cargo test --workspace`. Build and
run it on its own:

```sh
cargo build --release --manifest-path crates/linkkeys/loadtest/Cargo.toml
```

The binary is `crates/linkkeys/loadtest/target/release/linkkeys-loadtest`. It
has five subcommands.

`server` starts a real instance of the async TCP server
(`linkkeys::tcp::spawn_for_test`, the same connection/handshake/dispatch code
the production binary runs). It runs in its own process, so its process
memory use reflects only the server. It reads every `TCP_*` and
`PUBLIC_READ_*` environment variable the production server reads. It writes
an info file (`port`, `domain`, `fingerprint`, `pid`) for the client
subcommands to read. It prints one JSON metrics line, prefixed `METRICS `, on
a timer.

The server subcommand uses a self-signed certificate with no client
certificate requirement. This measures connection, handshake, dispatch, and
cache SCALE. It does not measure mutual TLS. `tests/tls_mtls_e2e_test.rs`
already covers mutual TLS. The load test does not need domain-key bootstrap
or `DOMAIN_KEY_PASSPHRASE`.

`connections` opens and holds N established, mostly idle connections. It
reports how many connections it established and why the rest failed.

`handshake-bench` measures the TLS handshake rate on its own: connect,
handshake, close, repeat.

`request-bench` measures request throughput over already-established,
reused connections. It defaults to `DomainKeys/get-domain-keys`, the
anonymous public-key read this design protects.

`ddos` exercises the distinct-source protection controls. It makes one
connection attempt from each of many distinct source addresses.

### Many source addresses on one machine

The whole `127.0.0.0/8` block routes to the loopback interface on Linux. The
kernel does this without any `ip addr add` command. This harness binds
outbound sockets to addresses such as `127.0.5.17` with no extra host
configuration. Verified on the machine in this report:

```sh
python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.5',0)); print(s.getsockname())"
```

This lets the harness simulate many distinct DDoS sources, and it lets a
connection-count test spread connections across more than one ephemeral-port
range. A source address and an ephemeral port together form one TCP 4-tuple
with the server. The Linux ephemeral port range on the test machine
(`net.ipv4.ip_local_port_range`) was `32768 60999`, about 28,231 ports. One
source address can therefore hold about 28,231 concurrent connections to one
server port. The harness uses more than one source address so this port range
is not the limit on how many connections it can hold.

### What the client can and cannot see

The server can drop a connection attempt for two different reasons that look
identical to the client: the handshake rate limiter rejected it, or a TLS
handshake genuinely failed. The server closes the raw TCP socket without
sending TLS bytes either way. The client subcommands report their own
success/failure counts, but the server process's own METRICS lines
(`shed_handshake_per_source`, `shed_handshake_overflow`,
`shed_handshake_global`, `handshake_rejections`) are the authoritative
breakdown. Read both when you interpret a run.

### Two memory numbers, and why they differ

The server reports its own `frame_buffer_bytes` gauge: the exact number of
bytes currently held for a frame body read off the wire but not yet
dispatched. This number is exact and bounded by design (see
`crates/linkkeys/src/tcp/limits.rs`).

The harness also reports the server process's resident set size (RSS), read
from `/proc/self/status`. RSS is a real number, but it is noisier: the Linux
allocator does not always return freed memory to the operating system
immediately, so RSS can stay high for a while after connections close. Use
`frame_buffer_bytes` and the connection-count gauges to reason about the
server's PER-CONNECTION cost. Use RSS as a separate, rougher check that
overall memory use stays in a sane range.

## Measured run: hardware, OS, and limits

Measured 2026-08-29.

| Item | Value |
| --- | --- |
| CPU | AMD Ryzen 7 5800X, 8 cores / 16 threads |
| Memory | 125 GiB |
| OS | EndeavourOS (Arch Linux), kernel 7.1.11-arch1-1 |
| `ulimit -n` (soft/hard, default shell) | 524288 / 524288 |
| `ulimit -n` (used for this run) | 300000 |
| `fs.file-max` | 9223372036854775807 (effectively unlimited on this kernel) |
| `fs.nr_open` | 2147483584 |
| `net.core.somaxconn` | 4096 |
| `net.ipv4.ip_local_port_range` | 32768 60999 |
| `net.netfilter.nf_conntrack_max` | 262144 |

Set the shell's file-descriptor limit before you start the server or a client
subcommand:

```sh
ulimit -n 300000
```

The server and the client subcommands are separate operating-system
processes on this machine. Set `ulimit -n` before you start EACH one — a
shell's `ulimit -n` does not carry over to a process started from a different
shell invocation.

## Traffic pattern and environment variables

Every run below used a real SQLite database file (not `:memory:`), migrated
at startup, exactly like a production SQLite deployment. It used
`DOMAIN_NAME=loadtest.local`.

This report used two different environment profiles. The results below say
which profile applies to which number.

**Default profile.** No `TCP_HANDSHAKE_*` or `PUBLIC_READ_*` variable set —
the values shipped in `crates/linkkeys/src/tcp/limits.rs` and
`crates/linkkeys/src/services/public_ratelimit.rs`. This is what a fresh
deployment runs with.

**Scale profile.** An operator deliberately raises the handshake-admission
and public-read limiters, as the design expects an operator to do for a
large deployment ("The operator must be able to increase this limit for a
large deployment"). Exact variables:

```sh
export TCP_MAX_CONNECTIONS=220000
export TCP_HANDSHAKE_CONCURRENCY=1024
export TCP_HANDSHAKE_RATE_PER_MINUTE=6000000
export TCP_HANDSHAKE_BURST=1000000
export TCP_HANDSHAKE_GLOBAL_RATE_PER_SECOND=100000
export TCP_HANDSHAKE_GLOBAL_BURST=200000
export PUBLIC_READ_RATE_PER_MINUTE=6000000
export PUBLIC_READ_BURST=1000000
export PUBLIC_READ_GLOBAL_RATE_PER_SECOND=100000
export PUBLIC_READ_GLOBAL_BURST=200000
```

Without the scale profile, the default handshake-admission limiter (a global
burst of 1000, refilling 500 per second) becomes the bottleneck long before
200,000 connections are established — this is the DDoS control working as
designed, not a defect. See "DDoS controls" below for what the DEFAULT
profile actually does.

## Results

### 1. Established connections (scale profile)

Command:

```sh
linkkeys-loadtest server --info-file info.json --db-path db.sqlite3 \
    --metrics-interval-secs 5 --duration-secs 240 &
linkkeys-loadtest connections --info-file info.json \
    --count 200000 --concurrency 3000 --hold-secs 20 \
    --attempt-timeout-secs 20 --client-ip-base 127.0.1.0 --client-ip-count 64
```

MEASURED result: **199,977 of 200,000 requested connections established**
(99.99%), in 34.6 seconds. 23 connections failed with a client-side attempt
timeout; the server's own metrics recorded exactly 23
`handshake_rejections` and zero connections shed by any rate limiter for this
run, so these 23 were genuine TLS-handshake-layer failures under load, not
DoS-control rejections.

The design sets a first acceptance target: at least 200,000 established,
mostly-idle connections. This machine met that target at 99.99%, under the
scale profile, with the traffic pattern and environment above. The default
environment profile did NOT meet this target, and this report does not
claim it did. See "DDoS controls" below for what the default profile does
at this scale of connection attempts.

Server memory at 199,977 established connections:

| Metric | Value |
| --- | --- |
| `frame_buffer_bytes` (server gauge, exact) | 0 — idle connections hold no in-flight frame buffer, as designed |
| Process RSS (server process, noisier) | 3,696,185,344 bytes (3.44 GiB) |
| Process RSS at 0 connections (baseline) | 12,861,440 bytes (12.3 MiB) |
| RSS delta per established connection | about 18.0 KiB |

18 KiB per mostly-idle connection is a real, machine-specific number, not a
theoretical one. A capacity plan for a different machine needs its own
measurement. This document does not replace that measurement.

### 2. TLS handshake rate (scale profile, isolated)

Command:

```sh
linkkeys-loadtest handshake-bench --info-file info.json \
    --duration-secs 15 --concurrency 256 \
    --client-ip-base 127.0.2.0 --client-ip-count 128
```

MEASURED result: **18,972 handshakes/second**, sustained over 15 seconds
(284,584 handshakes, zero failures). This is a SEPARATE number from the
established-connection count above — it is how fast this machine can complete
connect + TLS handshake + close cycles in a tight loop, not how many
connections it can hold at once.

### 3. Public-key request throughput (scale profile)

Command:

```sh
linkkeys-loadtest request-bench --info-file info.json \
    --connections 64 --duration-secs 20
```

MEASURED result: **about 49,000 to 51,000 `DomainKeys/get-domain-keys`
requests/second**, sustained, over already-established persistent
connections, repeated across two runs (64 and 256 connections). Every request
in these runs hit the server's warm response cache (`pubkey_cache`) after the
first one — this is a cache-hit throughput number, not a cold-database-read
number.

Throughput did not scale from 64 to 256 connections (49,402/sec vs
51,216/sec). Increasing client concurrency past a small number did not raise
this ceiling on this machine.

One possible explanation: the server dispatches each frame through
`tokio::task::spawn_blocking` (`crates/linkkeys/src/tcp/mod.rs`). This
operation is cheap — a cache-hit read, no cryptography, no disk I/O. The
`spawn_blocking` scheduling hop itself may cost more than the handler's own
work. This harness did not test that idea further. Treat it as a lead for
whoever next profiles the dispatch path, not as a confirmed cause.

One early run of this same command reported 105,554 requests/second. Three
later repeats did not reproduce it (49,402 / 51,216 / 59,841/sec). This
report uses the repeatable range, not the high outlier. An unreproduced fast
number is not evidence of sustained capacity.

### 4. DDoS controls (default profile)

Command:

```sh
# server started with NO TCP_HANDSHAKE_*/PUBLIC_READ_* overrides
linkkeys-loadtest ddos --info-file info.json \
    --sources 12000 --concurrency 500 --client-ip-base 127.0.5.0
```

MEASURED result, against the UNMODIFIED default configuration: of 12,000
connection attempts, each from its own distinct source address, only 1,099
were admitted in about 1.27 seconds. The server's own metrics account for
every rejection:

| Reason | Count |
| --- | --- |
| Admitted | 1,099 |
| Rejected — global handshake bucket exhausted (`shed_handshake_global`) | 8,963 |
| Rejected — distinct-source overflow protection (`shed_handshake_overflow`) | 1,955 |
| Rejected — per-source bucket (`shed_handshake_per_source`) | 0 (expected — one attempt per source) |

This is the design's distinct-source protection, working as specified. Once
more distinct sources arrive in the tracking window than
`TCP_HANDSHAKE_DISTINCT_SOURCE_THRESHOLD` (default 10,000), new sources move
to the shared overflow bucket. The server does not create per-source state
for them. Server process RSS stayed at about 27 MiB during this run — the
12,000 distinct source addresses did not cause unbounded growth.

This result also shows why the "established connections" run above needed
the scale profile. The DEFAULT global handshake bucket (burst 1000, refill
500 per second) cannot admit 200,000 new connections quickly. An operator
who sizes a public-facing deployment for a fast connection ramp must raise
`TCP_HANDSHAKE_GLOBAL_BURST` and `TCP_HANDSHAKE_GLOBAL_RATE_PER_SECOND`
deliberately, the same way this report did. This is a documented,
observable trade-off between ramp speed and DoS resistance. It is not a
hidden one.

## What this run does and does not prove

Proven, on the machine and profile described above:

- 200,000 established, mostly-idle connections: met at 99.99%.
- A real, isolated TLS handshake rate: 18,972/second.
- A real, isolated public-key request rate: about 50,000/second, cache-hit.
- Bounded memory under a 12,000-distinct-source DDoS pattern with the
  default configuration.

Not proven by this run:

- Sustained throughput while connections, handshakes, and requests all
  happen at once, at these same magnitudes, at the same time. This harness
  measures one thing at a time on purpose (see "The tool" above). One thing
  at a time is simpler to reason about and to reproduce. A combined-load run
  is future work, if a deployment's real traffic pattern needs it.
- Behavior under the default (not scale) profile at 200,000 connections. The
  DDoS run above shows why this report did not attempt that combination: the
  default admission rate cannot ramp that fast, by design.
- Behavior on different hardware, a different kernel, a container runtime, or
  a different Linux distribution. Re-run this harness and update this
  document before you rely on these numbers elsewhere.
- Multi-day stability, memory behavior over hours, or a real WAN traffic
  pattern (latency, packet loss, many real peers). This report used one
  machine, talking to itself over loopback, for minutes at a time.

## Reproducing this report

```sh
ulimit -n 300000
cargo build --release --manifest-path crates/linkkeys/loadtest/Cargo.toml
BIN=crates/linkkeys/loadtest/target/release/linkkeys-loadtest

# Scale profile — established connections, handshake rate, request throughput
export TCP_MAX_CONNECTIONS=220000 TCP_HANDSHAKE_CONCURRENCY=1024 \
       TCP_HANDSHAKE_RATE_PER_MINUTE=6000000 TCP_HANDSHAKE_BURST=1000000 \
       TCP_HANDSHAKE_GLOBAL_RATE_PER_SECOND=100000 TCP_HANDSHAKE_GLOBAL_BURST=200000 \
       PUBLIC_READ_RATE_PER_MINUTE=6000000 PUBLIC_READ_BURST=1000000 \
       PUBLIC_READ_GLOBAL_RATE_PER_SECOND=100000 PUBLIC_READ_GLOBAL_BURST=200000
"$BIN" server --info-file /tmp/lk-info.json --db-path /tmp/lk-db.sqlite3 \
    --metrics-interval-secs 5 --duration-secs 240 &
sleep 2
"$BIN" connections --info-file /tmp/lk-info.json --count 200000 \
    --concurrency 3000 --hold-secs 20 --attempt-timeout-secs 20 \
    --client-ip-base 127.0.1.0 --client-ip-count 64
"$BIN" handshake-bench --info-file /tmp/lk-info.json --duration-secs 15 \
    --concurrency 256 --client-ip-base 127.0.2.0 --client-ip-count 128
"$BIN" request-bench --info-file /tmp/lk-info.json --connections 64 \
    --duration-secs 20
kill %1

# Default profile — DDoS controls
env -u TCP_MAX_CONNECTIONS -u TCP_HANDSHAKE_CONCURRENCY \
    -u TCP_HANDSHAKE_RATE_PER_MINUTE -u TCP_HANDSHAKE_BURST \
    -u TCP_HANDSHAKE_GLOBAL_RATE_PER_SECOND -u TCP_HANDSHAKE_GLOBAL_BURST \
    "$BIN" server --info-file /tmp/lk-info2.json --db-path /tmp/lk-db2.sqlite3 \
    --metrics-interval-secs 5 --duration-secs 90 &
sleep 2
"$BIN" ddos --info-file /tmp/lk-info2.json --sources 12000 --concurrency 500 \
    --client-ip-base 127.0.5.0
kill %1
```

Read the server process's `METRICS` lines during and after each run — the
numbers in this document came from those lines, not from the client
subcommands' own summaries alone.

A quick smoke run (small counts, under a minute) is also available:

```sh
./tools.sh load-test
```

That smoke run only proves the harness and the server's real code path work
end to end. It is not a capacity claim at any scale — see the comment above
`load_test()` in `tools.sh`.
