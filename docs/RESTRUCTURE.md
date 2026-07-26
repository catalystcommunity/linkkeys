# Documentation restructure — working plan

**Temporary.** Delete this file when the last row of the disposition table is
done. It is a work plan, not documentation.

## Goal

Make it possible to answer "what must I implement to be LinkKeys?" without
reading the source. Today that question has no answer: `docs/DESIGN.md`
interleaves protocol invariants, deployment opinion, and this repository's cargo
conventions in one voice, and two of its most distinctive sections — device/app
keys and the web-of-trust signing service — describe mechanisms that exist
nowhere in code.

The framework, invariants, conformance roles, and capability classification now
live in [`spec/README.md`](spec/README.md). This file tracks the mechanical work
of moving content to match it.

## Rule

**Every new document must name what it absorbs.** A restructure that only adds
files makes comprehension worse, which is the opposite of the point. No row
below creates a document without retiring or absorbing something.

## Target layout

```
docs/
├── spec/            normative only; extractable; no repo references
│   ├── README.md            framework, roles, invariants, classification  [done]
│   ├── trust-and-anchors.md anchor discovery, DNS-TXT binding, pinning
│   ├── keys.md              key model, rotation, revocation
│   ├── assertions.md        handshake, negotiation, assertion format, domain sep
│   ├── claims.md            claim format, signed payload, verification
│   ├── claim-policy.md      value types, signing lanes, set rules, release rules
│   ├── browser-binding.md   I2/R2 interactive flow
│   ├── local-rp.md          I4/R3 ticket issuance and redemption
│   ├── attestation.md       I3 third-party claim deposit
│   ├── reserved/            designed, unimplemented, will change
│   └── conformance/         per-role checklists + vector index
├── rationale/       why, not what; carries no obligations
├── operations/      running this implementation
└── developing/      building against or on this implementation
```

## Disposition

| Source | Action | Destination |
| --- | --- | --- |
| `DESIGN.md` — identity model, key hierarchy (custody tier), protocol, wire format, negotiation | **Split → normative** | `spec/keys.md`, `spec/assertions.md` |
| `DESIGN.md` — DNS key discovery, caching | **Split → normative**, reworded per invariant I-2 (anchor discovery, DNS as binding) | `spec/trust-and-anchors.md` |
| `DESIGN.md` — key signing / web of trust, device & app key tier, domain migration | **Split → Reserved** | `spec/reserved/` |
| `DESIGN.md` — core philosophy, design priorities, threat model | **Split → rationale** | `rationale/philosophy.md` |
| `DESIGN.md` — project structure, adding a feature, codebase guidelines, tests, simplicity | **Delete**; already in `AGENTS.md` | — |
| `DESIGN.md` (file itself) | **Retire** once split; leave a stub pointing at the three destinations for one release | — |
| `claim-policy-and-consent.md` | **Split**: claim/policy/release model → normative; consent UX design → rationale | `spec/claims.md`, `rationale/consent-design.md` |
| `claim-trust-verification.md` | **Move → normative**; reconcile with `spec/claims.md`, drop overlap | `spec/claims.md` |
| `local-rp-key-lifecycle.md` | **Split**: wire-visible lifecycle → normative; operational rotation guidance → operations | `spec/local-rp.md`, `operations/local-rp.md` |
| `local-rp-admin-guide.md` + `local-rp-operator-guide.md` | **Merge** — these are the clearest duplication in `docs/` | `operations/local-rp.md` |
| `local-rp-app-developer-guide.md` | **Move** | `developing/local-rp-sdk.md` |
| `local-rp-security-tradeoffs.md` | **Move**, unchanged | `rationale/local-rp-security.md` |
| `kerberos_comparison.md` | **Move**, unchanged | `rationale/kerberos-comparison.md` |
| `DEPLOYING-RP.md` | **Move** | `operations/deploying-rp.md` |
| `LIVE-ENV.md` | **Move** | `operations/live-env.md` |
| `DEMO.md` | **Move** | `operations/demo.md` |
| `reactorcide-jobs.md` | **Move** | `developing/ci.md` |
| `rp-claims.example.toml` | **Move** beside its guide | `operations/` |
| `/dns-less-local-rp-design.md` (repo root) | **Move out of root** — it is an agent prompt, not documentation. Its normative content is superseded by `spec/local-rp.md` | `.agents/` or delete after extraction |
| `README.md` | **Rewrite** — lead with the value proposition, link the spec | — |
| `/sdks/local-rp/conformance/{keys,envelopes,dns,revocations,claims,expirations,url_params}.json` | **Relocate** — these are core protocol vectors misfiled under an extension. Update the path in `liblinkkeys/tests/conformance.rs` and every SDK that loads them | `spec/conformance/vectors/` |
| `/sdks/local-rp/conformance/{tickets,callback_box}.json` | **Relocate** — genuinely Local-RP | `spec/conformance/vectors/local-rp/` |

Five `local-rp-*` documents become four with non-overlapping jobs (normative /
operations / rationale / SDK), and the genuine duplication — admin guide vs.
operator guide — collapses to one.

## Sequence

1. ~~Framework, invariants, conformance roles, classification~~ — done
2. ~~`spec/trust-and-anchors.md` and `spec/keys.md`~~ — done. Anchor-discovery
   rewording is in place, so later documents have correct phrasing to copy
3. ~~`spec/assertions.md`, `spec/claims.md`~~ — done. **Split:** claim *format
   and verification* (`claims.md`) is separated from claim *policy*
   (`claim-policy.md`, still to write). The original plan had them as one
   document. They divide cleanly by role: format and verification are R1
   obligations every verifier must implement, while value types, the four
   signing lanes, set rules, trusted issuers, and release rules are properties
   of an issuing domain (I1/I2) that a verifier never needs. One document mixing
   them would be unimplementable by half its audience
4. `spec/reserved/` — partially done: `signing-authorities.md`,
   `device-keys.md`, and `subdomain-hierarchies.md` written. Still to move:
   domain migration. After that, `DESIGN.md` can be retired
5. `spec/browser-binding.md`, `spec/local-rp.md`, `spec/attestation.md`
6. Mechanical moves (rationale, operations, developing)
7. `spec/conformance/` — the vectors already exist and mostly already cover the
   core, so this is a relocation plus per-role checklists, not an authoring job.
   **Sequence it last among the spec work**: the move touches
   `liblinkkeys/tests/conformance.rs` and every SDK that loads a vector path, so
   it should land as one mechanical commit with no prose changes riding along
8. README rewrite
9. Architecture and protocol diagrams — in-repo mermaid, not images, so they
   review in diffs
10. Delete this file

Steps 2–5 each end with a document that is smaller than the prose it replaces.
If one doesn't, the split was wrong.

## Watch for

- **Normative text acquiring repo references.** The extraction plan in
  `spec/README.md` lists what is forbidden. Grep for crate names before
  promoting a document.
- **Reserved content drifting into normative sections.** Reserved material gets
  its own subsection or its own file, never a parenthetical.
- ~~**The deprecated HTTP server-to-server routes.**~~ Removed. The
  `/v1alpha/{domain-keys,users/<id>/keys,handshake,userinfo}` routes are gone
  from `web/mod.rs`; server-to-server is TCP CSIL-RPC only, per invariant I-4.
  `/csil/v1/rpc` and the browser flow are untouched. Nothing in `spec/` needs to
  acknowledge them.
- **Tag rewrites corrupting the box tag.** The unsuffixed
  `linkkeys-local-rp-callback` is a proper prefix of
  `linkkeys-local-rp-callback-box`. Any bulk rewrite must match the longest form
  first *and* be idempotent — applying a naive suffix-append twice produces
  `...callback-v1alpha-box-v1alpha`. This bit once during the epoch sweep.
- **JSON creeping back in.** A JSON representation of protocol messages is now an
  explicit non-goal (invariant I-5). `DESIGN.md`'s promise of "JSON wrappers …
  for web browser consumption" must not survive into any document. Note that
  JSON remains correct for non-protocol uses — the message catalog, conformance
  vector fixtures, test helpers — and those were deliberately left alone.
- **Promotion without vectors.** Reserved → Normative requires an implementation
  *and* conformance vectors. Profiles are the near-term candidate; confirm
  coverage before the claims document promotes them.
