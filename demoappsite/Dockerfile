# Build context must be the repo root (for workspace deps)
FROM rust:1-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY demoappsite/ demoappsite/
RUN cargo build --release --bin demoappsite

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd -r -u 2000 -m demoapp

COPY --from=builder /build/target/release/demoappsite /usr/local/bin/demoappsite

USER demoapp
EXPOSE 9090

CMD ["demoappsite"]
