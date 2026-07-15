// Loads `sdks/local-rp/conformance/*.json` fixture files for tests.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:linkkeys_local_rp/src/crypto/hex.dart';

/// The conformance vector directory, resolved relative to this package
/// directory (not the process cwd, so tests work regardless of how `dart
/// test` was invoked).
String conformanceDir() {
  // This file lives at <package>/test/testutil/fixtures.dart; the vectors
  // live at <package>/../conformance/.
  final here = Platform.script.toFilePath();
  // When run under `dart test`, Platform.script points at the test runner,
  // not this file, so fall back to a path relative to the current working
  // directory (the package root, per `dart test`'s own convention) with an
  // override available via LINKKEYS_CONFORMANCE_DIR for other runners.
  final envOverride = Platform.environment['LINKKEYS_CONFORMANCE_DIR'];
  if (envOverride != null) return envOverride;
  final candidate = Directory(_join(Directory.current.path, '../conformance'));
  if (candidate.existsSync()) return candidate.path;
  // Fall back to resolving relative to this source file's location, for
  // runners that don't set cwd to the package root.
  final fileDir = File(here).parent.parent.parent;
  return _join(fileDir.path, '../conformance');
}

String _join(String a, String b) => '$a/$b';

dynamic loadJson(String name) {
  final path = '${conformanceDir()}/$name';
  final text = File(path).readAsStringSync();
  return jsonDecode(text);
}

Uint8List hex(String s) => Hex.decode(s);
