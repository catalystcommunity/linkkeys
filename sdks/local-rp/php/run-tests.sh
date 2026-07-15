#!/usr/bin/env bash
# Runs this SDK's full test suite with plain system PHP (no Composer/PHPUnit
# required — see README.md, "Testing" for why and for the container-based
# fallback command if system PHP is unavailable).
#
# Requirements: PHP >= 8.1 with ext-sodium, ext-openssl, ext-hash, and the
# `openssl` CLI binary on PATH (only needed by tests/TlsPinningTest.php,
# which mints a real X.509 certificate to test SPKI pin-checking).
#
# Do not add this file to the repo's top-level tools.sh (AGENTS.md-adjacent
# task instructions) — this script IS the reported test command.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v php >/dev/null 2>&1; then
  echo "PHP not found on PATH. Install PHP >= 8.1 with ext-sodium/ext-openssl/ext-hash," >&2
  echo "or run these tests in a container, e.g.:" >&2
  echo "  sudo nerdctl run --rm -v \"\$(pwd)/..\":/repo -w /repo/php php:8.3-cli ./run-tests.sh" >&2
  exit 1
fi

fail=0
tests=(
  tests/conformance/KeysTest.php
  tests/conformance/EnvelopesTest.php
  tests/conformance/CallbackBoxTest.php
  tests/conformance/DnsTest.php
  tests/conformance/TicketsTest.php
  tests/conformance/UrlParamsTest.php
  tests/conformance/ExpirationsTest.php
  tests/conformance/RevocationsTest.php
  tests/conformance/ClaimsTest.php
  tests/CborTest.php
  tests/IdentityTest.php
  tests/BeginTest.php
  tests/FlowTest.php
  tests/TlsPinningTest.php
)

for t in "${tests[@]}"; do
  echo "--- ${t} ---"
  if ! php "${t}"; then
    fail=1
  fi
done

if [ "${fail}" -ne 0 ]; then
  echo "FAILED: one or more test files reported failures." >&2
  exit 1
fi

echo "All PHP local-RP SDK tests passed."
