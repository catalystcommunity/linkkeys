/// LinkKeys DNS-less local RP identity SDK.
///
/// See `dns-less-local-rp-design.md` at the repository root and
/// `sdks/local-rp/conformance/README.md`. This library re-exports the
/// public API surface from `src/`; internal wire/crypto plumbing
/// (`src/wire/`, `src/crypto/`, `src/rpc/`) is reachable by this package's
/// own test suite but is not part of the supported public API for external
/// consumers.
library;

export 'src/linkkeys_local_rp.dart';
