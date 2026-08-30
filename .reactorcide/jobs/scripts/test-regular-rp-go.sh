#!/usr/bin/env bash
set -euo pipefail

# The Go SDK carries the application-key verification rules for every Go
# consumer (Tinku first). Its tests replay the cross-language conformance
# vectors in sdks/regular-rp/conformance/, which is the only thing that proves
# the Go implementation still agrees with the Rust reference in
# crates/liblinkkeys/src/application_keys.rs. A drift there is a silent
# verification difference between two implementations of one protocol.

echo "================================================"
echo "regular-RP Go SDK tests"
echo "================================================"

# cd FIRST. The job's inherited working directory is not guaranteed to exist
# for the runner user, and Go fails with
#   go: cannot determine current directory: getwd: no such file or directory
# before it does anything else.
cd "${REACTORCIDE_REPOROOT:-${REACTORCIDE_CODE_DIR:-/job/src}}/sdks/regular-rp/go"

export HOME="${HOME:-/home/runner}"

# This job runs under a non-root CI profile (may_run_as_root: false), so every
# path Go writes to must be inside the job's own workspace. The runner image
# ships GOPATH=/go, which the runner user cannot create:
#   go: could not create module cache: mkdir /go/pkg: permission denied
export GOPATH="${HOME}/go"
export GOMODCACHE="${GOPATH}/pkg/mod"
export GOCACHE="${HOME}/.cache/go-build"
mkdir -p "$GOMODCACHE" "$GOCACHE"

# Go is preinstalled on the runner image. Install into HOME only as a fallback,
# never with sudo, which this profile does not grant.
GO_VERSION="1.26.4"
if ! command -v go >/dev/null 2>&1; then
    echo "Go not found; installing ${GO_VERSION} into HOME..."
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz
    mkdir -p "$HOME/.local"
    tar -C "$HOME/.local" -xzf /tmp/go.tgz
    rm -f /tmp/go.tgz
    export PATH="$HOME/.local/go/bin:$PATH"
fi
go version

echo "=== gofmt ==="
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
    echo "unformatted files:"
    echo "$unformatted"
    exit 1
fi

echo "=== go vet ==="
go vet ./...

echo "=== go test (race) ==="
go test ./... -race

echo "================================================"
echo "regular-RP Go SDK tests passed"
echo "================================================"
