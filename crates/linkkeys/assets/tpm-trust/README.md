# TPM trust set

The default trust anchors for `tpm2-certify` evidence in device enrollment
(see `docs/device-enrollment-and-attestation.md` §4.3). The server gives these
to `liblinkkeys::device::evidence` as data. An operator can replace them.

## Contents

| File | What |
| --- | --- |
| `tpm-roots.pem` | 32 TPM manufacturer certificates. These are the trust anchors. |
| `tpm-intermediates.pem` | 159 intermediate certificates. They let a verifier build an EK chain offline, without a fetch from a vendor URL. They are never anchors. |
| `tpm-roots.yaml`, `tpm-intermediates.yaml` | The upstream manifests: vendor, name, vendor download URI, pinned fingerprint. |
| `refresh.py` | Rebuilds the four files above from the vendors' servers. |
| `LICENSE.tpm-ca-certificates` | Upstream license (BSD-3-Clause). It applies to the manifests. |

Vendors: AMD, Google, Infineon, Intel, Microsoft, NSING, Nuvoton, Nationz,
STMicroelectronics.

## Source

The manifests come from
[loicsikidi/tpm-ca-certificates](https://github.com/loicsikidi/tpm-ca-certificates),
tag `2026-06-10`. That project records, for each certificate, the vendor's own
download URI, a pinned fingerprint, and evidence that the vendor publishes it.

We do not use the upstream PEM files. `refresh.py` downloads each certificate
from the vendor URI and checks it against the pin.

## Verification record (2026-11-14)

- 189 of 191 certificates came from the vendor URI and matched the pin. 12
  Nuvoton pins are SHA-1, because Nuvoton publishes only SHA-1.
- 2 AMD roots (`AMDTPM ECC`, `AMDTPM RSA`, old encoding) are no longer on
  AMD's server. They came from the upstream repository and matched the pin.
  AMD still serves the same key pairs in a newer encoding, and those are also
  in the set.
- 1 Nationz intermediate (`Nationz TPM Manufacturing CA 001`) came over HTTPS
  without TLS verification, because the vendor's TLS certificate names a
  different host. The manifest allows this (`allowHttpFallback`); the pinned
  fingerprint matched.
- The set of fingerprints is identical to the upstream signed release
  `2026-06-10` (`tpm-ca-certificates.pem`, `tpm-intermediate-ca-certificates.pem`).
- A run of `refresh.py 2026-06-10` in a clean directory gives files that are
  byte-identical to the committed files.

## Rules for the verifier

- **Every certificate in `tpm-roots.pem` is an anchor, self-signed or not.**
  Three are not self-signed: `AMD Pluton Global Factory ICA`,
  `STM TPM EK Root CA`, and `STM TPM ECC Root CA 01` (the last two are signed by
  GlobalSign roots that are also in the set). Chain building stops at the first
  anchor. Do not require an anchor to be self-signed.
- Intermediates only fill gaps in a chain. A chain that ends at an intermediate
  and not at an anchor fails.
- Some certificates are expired or expire soon (`Nuvoton TPM Root CA 1110`:
  2035). Check validity at the EK certificate's issue time, as TPM EK
  certificates often outlive their issuers.

## Who may change this directory

A change here makes the pull request trust-critical. It merges only with a
coordinator approval from todpunk or JuniPuff, pinned to the PR head. The PR
job `linkkeys-trust-guard` enforces this; see
`docs/trust-change-control.md`. Git author fields are not proof and are not
checked.

## Refresh

```sh
cd crates/linkkeys/assets/tpm-trust
python3 -I refresh.py <upstream-tag>      # needs gh, curl, openssl, PyYAML
```

The script writes nothing if any certificate fails. After a run:

1. Review `git diff tpm-roots.yaml tpm-intermediates.yaml`. Every added
   certificate must have a vendor source in upstream's `src/` directory.
2. Compare with the upstream signed release of the same tag.
3. Update the tag and the verification record above.
