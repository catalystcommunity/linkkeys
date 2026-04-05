# LinkKeys server Dockerfile
# Build context: repo root (workspace needed for liblinkkeys)
FROM rust:1-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev libsqlite3-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY demoappsite/ demoappsite/
COPY csil/ csil/
COPY migrations/ migrations/
RUN cargo build --release --bin linkkeys

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libpq5 libsqlite3-0 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 2000 -m linkkeys
RUN mkdir -p /data && chown linkkeys:linkkeys /data

COPY --from=builder /build/target/release/linkkeys /usr/local/bin/linkkeys

USER linkkeys
EXPOSE 8443 4987

CMD ["linkkeys", "serve"]
