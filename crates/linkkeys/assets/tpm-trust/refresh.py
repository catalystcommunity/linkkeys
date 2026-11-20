"""Rebuild the TPM trust bundles from the vendors' own servers.

usage (from this directory):
    python3 -I refresh.py <upstream-tag>      e.g. 2026-06-10

Steps:
1. Fetch `.tpm-roots.yaml` and `.tpm-intermediates.yaml` from
   loicsikidi/tpm-ca-certificates at <upstream-tag> (needs `gh`).
2. Download each certificate from the vendor URI in the manifest. A
   `file:///{local}/...` URI (a certificate the vendor no longer publishes)
   comes from the upstream repository at the same tag.
3. Check each certificate against the pinned fingerprint (SHA-256, or SHA-1
   where the vendor publishes only SHA-1). Any failure stops the run and
   writes nothing.
4. Write tpm-roots.pem / tpm-intermediates.pem (DER -> PEM, manifest order,
   one `# VENDOR: name` and `# SHA256:` comment per certificate) and the two
   manifests.

Where the manifest sets `allowHttpFallback`, a download with a broken vendor TLS
certificate is tried again without TLS verification. The pinned fingerprint is
the integrity check, not TLS.

Then compare with the upstream signed release and update README.md:
    gh release download <tag> -R loicsikidi/tpm-ca-certificates -p '*.pem'
"""
import base64
import hashlib
import os
import subprocess
import sys
import tempfile

import yaml

REPO = "loicsikidi/tpm-ca-certificates"
LOCAL_PREFIX = "file:///{local}/"
BUNDLES = [
    (".tpm-roots.yaml", "tpm-roots.yaml", "tpm-roots.pem"),
    (".tpm-intermediates.yaml", "tpm-intermediates.yaml", "tpm-intermediates.pem"),
]


def gh_file(path, tag):
    out = subprocess.run(
        ["gh", "api", f"repos/{REPO}/contents/{path}?ref={tag}", "--jq", ".content"],
        capture_output=True, text=True, check=True,
    ).stdout
    return base64.b64decode(out)


def curl(uri, insecure):
    with tempfile.NamedTemporaryFile() as tmp:
        flags = "-kfsSL" if insecure else "-fsSL"
        subprocess.run(["curl", flags, "--max-time", "30", "-o", tmp.name, uri],
                       check=True, capture_output=True)
        return open(tmp.name, "rb").read()


def fetch(cert, tag):
    uri = cert["uri"]
    if uri.startswith(LOCAL_PREFIX):
        return gh_file(uri[len(LOCAL_PREFIX):], tag), "upstream"
    last = None
    for attempt in range(3):
        try:
            return curl(uri, insecure=False), "vendor"
        except subprocess.CalledProcessError as e:
            last = e
            if cert.get("allowHttpFallback"):
                try:
                    return curl(uri, insecure=True), "vendor-notls"
                except subprocess.CalledProcessError as e2:
                    last = e2
    raise RuntimeError(f"download failed: {uri}: {last}")


def to_der(raw):
    if b"-----BEGIN CERTIFICATE-----" in raw:
        return subprocess.run(["openssl", "x509", "-outform", "DER"], input=raw,
                              capture_output=True, check=True).stdout
    return raw


def build(manifest, tag):
    out, problems = [], []
    for vendor in manifest["vendors"]:
        for cert in vendor["certificates"]:
            pin = cert["validation"]["fingerprint"]
            algo = "sha256" if "sha256" in pin else "sha1"
            want = pin[algo].replace(":", "").lower()
            label = f'{vendor["id"]}: {cert["name"]}'
            try:
                raw, source = fetch(cert, tag)
                der = to_der(raw)
            except Exception as e:  # noqa: BLE001 - report every failure, then stop
                problems.append(f"{label}: {e}")
                continue
            if hashlib.new(algo, der).hexdigest() != want:
                problems.append(f"{label}: {algo} fingerprint mismatch")
                continue
            pem = subprocess.run(["openssl", "x509", "-inform", "DER", "-outform", "PEM"],
                                 input=der, capture_output=True, check=True).stdout.decode()
            out.append(f"# {label}\n# SHA256: {hashlib.sha256(der).hexdigest()}\n{pem}")
            print(f"ok  {source:13} {label}")
    return out, problems


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    tag = sys.argv[1]
    here = os.path.dirname(os.path.abspath(__file__))
    results, problems = [], []
    for upstream_name, manifest_name, pem_name in BUNDLES:
        raw = gh_file(upstream_name, tag)
        certs, errs = build(yaml.safe_load(raw), tag)
        results.append((manifest_name, raw, pem_name, certs))
        problems += errs
    if problems:
        print("\nFAILED, nothing written:", *problems, sep="\n  ")
        sys.exit(1)
    for manifest_name, raw, pem_name, certs in results:
        open(os.path.join(here, manifest_name), "wb").write(raw)
        open(os.path.join(here, pem_name), "w").write("".join(certs))
        print(f"wrote {pem_name}: {len(certs)} certificates")


if __name__ == "__main__":
    main()
