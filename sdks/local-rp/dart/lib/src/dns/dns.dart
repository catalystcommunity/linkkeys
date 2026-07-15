// DNS TXT record parsing, pinning, and vouch verification -- mirrors
// `crates/liblinkkeys/src/dns.rs` / the Rust/Go/Java reference SDKs' own
// `dns` modules. This library performs no I/O itself; [DnsResolver] is the
// network seam (design doc, "Required Network Access": every SDK needs a
// DNS TXT lookup capability, configurable, defaulting to the system
// resolver).
library;

import '../crypto/crypto.dart';
import '../errors.dart';
import '../local_rp.dart';
import '../wire/cbor.dart';
import '../wire/types.dart';

/// Default TCP port for the LinkKeys protocol service. Advertised `tcp=`
/// values omit the port when it equals this.
const int defaultTcpPort = 4987;

String linkkeysDnsName(String domain) => '_linkkeys.$domain';

String linkkeysApisDnsName(String domain) => '_linkkeys_apis.$domain';

/// A parsed `_linkkeys.{domain}` TXT record -- the trust anchor.
class LinkKeysRecord {
  final List<String> fingerprints;
  const LinkKeysRecord(this.fingerprints);
}

/// A parsed `_linkkeys_apis.{domain}` TXT record -- service endpoints.
class LinkKeysApis {
  final String? tcp;
  final String? httpsBase;
  const LinkKeysApis({this.tcp, this.httpsBase});
}

List<String> _fields(String txt) =>
    txt.split(RegExp(r'\s+')).where((p) => p.isNotEmpty).toList();

void _requireLk1Version(List<String> parts) {
  String? version;
  var found = false;
  for (final p in parts) {
    if (p.startsWith('v=')) {
      version = p.substring(2);
      found = true;
      break;
    }
  }
  if (!found) {
    throw DnsParseError(DnsParseErrorKind.missingVersion, null);
  }
  if (version != 'lk1') {
    throw DnsParseError(DnsParseErrorKind.unsupportedVersion, version);
  }
}

/// Parse a single `_linkkeys` TXT record string. Errors if it isn't a
/// LinkKeys v1 record.
LinkKeysRecord parseLinkKeysTxt(String txt) {
  final parts = _fields(txt);
  _requireLk1Version(parts);
  final fingerprints = <String>[];
  for (final p in parts) {
    if (p.startsWith('fp=')) {
      fingerprints.add(p.substring(3));
    }
  }
  return LinkKeysRecord(fingerprints);
}

String _normalizeTcpEndpoint(String value) {
  if (value.isEmpty || value.contains(':')) return value;
  return '$value:$defaultTcpPort';
}

/// Parse a single `_linkkeys_apis` TXT record string. Errors if it isn't a
/// LinkKeys v1 record or carries no endpoint.
LinkKeysApis parseLinkKeysApisTxt(String txt) {
  final parts = _fields(txt);
  _requireLk1Version(parts);

  String? tcp;
  String? httpsBase;
  for (final p in parts) {
    if (tcp == null && p.startsWith('tcp=')) {
      final v = _normalizeTcpEndpoint(p.substring(4));
      if (v.isNotEmpty) tcp = v;
    }
    if (httpsBase == null && p.startsWith('https=')) {
      final v = p.substring(6);
      if (v.isNotEmpty) httpsBase = 'https://$v';
    }
  }
  if (tcp == null && httpsBase == null) {
    throw DnsParseError(DnsParseErrorKind.missingApisEndpoint, null);
  }
  return LinkKeysApis(tcp: tcp, httpsBase: httpsBase);
}

/// Whether [fp] is a syntactically valid key fingerprint: 64 hex chars (a
/// SHA-256 digest), case-insensitive.
bool isValidFingerprint(String fp) {
  if (fp.length != 64) return false;
  for (var i = 0; i < fp.length; i++) {
    final c = fp.codeUnitAt(i);
    final hex = (c >= 0x30 && c <= 0x39) ||
        (c >= 0x61 && c <= 0x66) ||
        (c >= 0x41 && c <= 0x46);
    if (!hex) return false;
  }
  return true;
}

/// Pin fetched keys to the DNS-published fingerprint set: for each
/// candidate key, RECOMPUTE `fingerprint(public_key)` (never trust the wire
/// `fingerprint` field, which is attacker-controlled) and keep only keys
/// whose recomputed fingerprint is a member of [pinned].
Future<List<DomainPublicKey>> pinKeysToFingerprints(
    List<DomainPublicKey> keys, List<String> pinned) async {
  final pinnedLower = <String>{
    for (final f in pinned)
      if (isValidFingerprint(f)) f.toLowerCase(),
  };
  final out = <DomainPublicKey>[];
  for (final k in keys) {
    final fp = (await Crypto.fingerprint(k.publicKey)).toLowerCase();
    if (pinnedLower.contains(fp)) out.add(k);
  }
  return out;
}

const String _keyVouchTag = 'linkkeys-key-vouch-v1';

List<int> _keyVouchPayload(String encFingerprint, String encExpiresAt) {
  return Cbor.encode(Cbor.tuple([
    Cbor.vtext(_keyVouchTag),
    Cbor.vtext(encFingerprint),
    Cbor.vtext(encExpiresAt),
  ]));
}

/// Verify that [signingKey] vouches for [encKey]: the encryption key names
/// this signing key, the signing key is itself valid, and its signature
/// covers the recomputed encrypt-key fingerprint + expiry.
Future<bool> verifyKeyVouch(
    DomainPublicKey encKey, DomainPublicKey signingKey) async {
  if (encKey.signedByKeyId == null ||
      encKey.signedByKeyId != signingKey.keyId) {
    return false;
  }
  try {
    LocalRp.checkSigningKeyValid(signingKey);
  } catch (_) {
    return false;
  }
  if (encKey.keySignature == null) return false;
  if (signingKey.algorithm != 'ed25519') return false;
  final recomputedFp = await Crypto.fingerprint(encKey.publicKey);
  final payload = _keyVouchPayload(recomputedFp, encKey.expiresAt);
  return Crypto.verifyEd25519(
      payload, encKey.keySignature!, signingKey.publicKey);
}

/// Establish the trusted key set from a fetched key list and the DNS-pinned
/// fingerprint set: signing keys (`key_usage == "sign"`) are pinned
/// directly; encryption keys (`key_usage == "encrypt"`) are trusted only
/// when a DNS-pinned signing key vouches for them.
Future<List<DomainPublicKey>> trustKeys(
    List<DomainPublicKey> keys, List<String> pinned) async {
  final signing = keys.where((k) => k.keyUsage == 'sign').toList();
  final pinnedSigning = await pinKeysToFingerprints(signing, pinned);

  final trusted = <DomainPublicKey>[...pinnedSigning];
  for (final k in keys) {
    if (k.keyUsage != 'encrypt') continue;
    for (final sk in pinnedSigning) {
      if (await verifyKeyVouch(k, sk)) {
        trusted.add(k);
        break;
      }
    }
  }
  return trusted;
}
