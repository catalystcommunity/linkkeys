# Trust change control

How LinkKeys stops a pull request from changing what LinkKeys trusts without
an authorized person approving that exact change.

## 1. Principles

- **The event system proves identity, not git.** Git author and committer
  fields are text that anyone can write. The VCS provider authenticates who
  acts on a pull request; the Reactorcide coordinator verifies the webhook and
  turns that identity into a subject. Only those subjects can authorize.
- **Approve exact content.** An accept binds one head SHA. A new push needs a
  new accept. A change to the base branch alone does not cancel it; the
  ruleset's strict status rule makes the PR update its head first.
- **Detect wide, not narrow.** A sneaky PR does not edit the anchor file. It
  edits the loader, the verifier, the guard, the build, or git itself. The
  guard looks for all of these.
- **Fail closed.** Unknown, malformed, or missing facts fail the check.
- **Enforcement is the merge system's job.** The CI check computes a status.
  The forge (GitHub today, vcsstar later) must require that status to merge.

## 2. Layers

| Layer | Owner | Does |
| --- | --- | --- |
| Detection | `.reactorcide/plugins/trust_guard.py` (trusted base CI) | Decides if a PR is trust-critical (§3). |
| Authorization | Reactorcide coordinator | Required review `linkkeys-trust-anchors`: accepts from the maintainers group, pinned to the head SHA. Posts `Reactorcide Reviews`. |
| Enforcement | GitHub ruleset; vcsstar merge gates | Requires `Reactorcide Checks` (includes the guard) and `Reactorcide Reviews` before merge. |

A gap in any layer is a gap in the whole. §6 lists what each owner must do.

## 3. What is trust-critical

A PR is trust-critical if any commit in `base..head`, or the whole-PR diff,
has one of these. Merge commits count by their combined diff, so an edit
hidden in a merge counts.

| Signal | Why |
| --- | --- |
| A path under `.reactorcide/` | Every plugin there runs in the guard's process and can sabotage it. Workflow and job files decide if the guard runs. |
| A path under `crates/linkkeys/assets/tpm-trust/` | The anchors. |
| A file that carries the marker `LINKKEYS-TRUST-CRITICAL`, before or after the change | Anchor loaders and verifiers. Removing the marker is a change to a marked file. |
| An added or removed line, in any file, with a PEM block, `include_bytes!`, `include_str!` of a certificate file, the text `tpm-trust` (not in Markdown), the marker, or a change to `forbid(unsafe_code)` | Anchors embedded somewhere new; code that points at the anchor directory; an escape from Rust privacy. |
| A symlink or submodule; a `.gitattributes`, `.gitmodules`, or `build.rs` file | Ways to redirect content or run code at build time. |
| A non-ASCII path; a path that case-folds into a guarded prefix | Look-alike paths. |
| A file with a certificate extension, or content that starts like a DER certificate | An anchor under another name. |

### 3.1 Marking code

Put `LINKKEYS-TRUST-CRITICAL` in a comment in each file that loads anchors or
decides trust. Keep trust decisions in small, dedicated files, so the marker
does not lock unrelated code.

Make bypasses need a marked file. In Rust, a verifier returns a capability
type with a private constructor (for example `VerifiedEvidence`), and the
enrollment record takes that type, not a `bool`. Code outside the marked
module cannot make one. `#![forbid(unsafe_code)]` in `liblinkkeys` keeps
`transmute` out; a change to that line is a tripwire.

Marked today (2026-11-14):

| Area | Files |
| --- | --- |
| Crypto and anchors | `liblinkkeys`: `lib.rs` (holds `forbid(unsafe_code)`), `crypto.rs`, `dns.rs`, `revocation.rs` |
| Signed-structure verification | `liblinkkeys`: `claims.rs`, `claim_policy.rs`, `assertions.rs`, `auth_request.rs`, `application_keys.rs`, `consent.rs`, `signing_request.rs`, `domain_claims.rs`, `act_as.rs`, `local_rp.rs`, `userinfo.rs`, `legacy_signatures.rs` |
| Server key trust | `linkkeys`: `services/pins.rs`, `services/pubkey_cache.rs`, `services/rp_cache.rs`, `services/attestation.rs`, `services/domain_keys.rs`, `services/revocations.rs`, `services/signature_upgrade.rs`, `dns.rs`, `web/rp.rs` (`fetch_domain_keys`), `tcp/dns_pin_cache.rs`, `tcp/tls.rs` |
| Transport pinning | `linkkeys-rpc-client`: `tls.rs` |

Not marked, on purpose: `tcp/mod.rs` and other dispatch code. They call the
marked modules. A change that skips a call is the semantic gap in §5; the
long-term answer is to move each decision behind a capability type, so a
skipped call does not compile.

## 4. How to approve

The coordinator has a required review, `linkkeys-trust-anchors`. It applies
to a PR that changes a path in its list (§6). The coordinator posts the status
`Reactorcide Reviews`: `pending` until the review is accepted, `success` when
it is accepted or when no review applies. The GitHub ruleset requires this
status.

To accept, a member of the group `linkkeys-trust-maintainers` does one of
these on the PR:

- Comments `/reactorcide accept linkkeys-trust-anchors`.
- Approves the PR on GitHub with the line
  `/reactorcide accept linkkeys-trust-anchors` in the review body.

Rules:

- The accept binds to the head SHA. A new push needs a new accept.
- Only the group can accept. An org admin adds members in Reactorcide and
  links each member's VCS login (`reactorcide identities link`).
- `/reactorcide revoke` withdraws the accept. A "changes requested" review
  withdraws the reviewer's accept.
- An accept starts no CI. It only updates `Reactorcide Reviews`.
- A member can accept their own PR. To stop that, add a second review for the
  same paths with `accept: [non_author]`. Not configured today.
- If the coordinator cannot list the PR's files, the review applies to the PR.

The review matches paths only, and it applies to the whole PR when one
changed path matches. The guard (§3) also finds trust signals by content: PEM
blocks, `include_bytes!`, the marker, and others, in any file. It fails the PR
when:

- the PR is trust-critical, but no changed path matches the review list, so
  the review would not apply. Example: a PEM block in an unmarked file, or an
  anchor changed and changed back in the history. Remove the signal, move the
  code into a marked and listed file, or squash the commits;
- a file carries the marker, but no pattern in the PR's copy of
  `.reactorcide/trust-review-paths.txt` matches it;
- the PR's copy of that list drops `.reactorcide/**` or
  `crates/linkkeys/assets/tpm-trust/**`.

The guard compares changed paths with the list in the trusted CI checkout (the
base), because that is the list the coordinator has. It uses the
coordinator's match rules (§6). The guard does not read approvals.

In `reactorcide run-local`, the guard gives the same result as in CI. A local
pass does not replace the accept: only the coordinator posts `Reactorcide
Reviews`.

## 5. Threats and answers

| Attack | Answer |
| --- | --- |
| Commit with a forged todpunk author email | Git identity is ignored. Needs a maintainer accept on the required review. |
| Add anchors in a new file elsewhere | PEM, `include_*`, DER, and `tpm-trust` tripwires. |
| Change the loader or verifier, not the anchors | Marked files. |
| Remove the marker, then change the file later | The removal is itself trust-critical. |
| Edit the guard, its job, or the workflow | `.reactorcide/` is guarded; the guard runs from base CI. |
| Hide an edit in a merge commit | Combined diff of each merge. |
| Change and revert, so the final diff is clean | Each commit is checked. The review sees only the final diff, so the guard fails; squash the commits. |
| Look-alike or case-variant path | NFKC + case folding; non-ASCII paths are trust-critical. The review list is case-sensitive, so the guard fails such a PR. |
| Symlink, submodule, `.gitattributes` filter, `build.rs` | Git and build control signals. |
| Reuse an accept after a new push | The accept binds the head SHA. A new head has no accept. |
| Use `approve-ci` or another review's accept | `approve-ci` releases the run gate only; it is not an accept. A labeled accept counts only for its review. |
| Click "Update branch" or reopen someone else's PR, so the sender is an approver | The sender is not used. Only an explicit accept counts. |
| Shallow checkout hides commits | Unshallow, or fail. |
| Checkout is not the event head | Fail. |
| Forge env facts from workflow YAML | The guard is a `base_nodes` node, so its env comes only from guarded base YAML. Reactorcide R1 adds coordinator-side reserved names as defense in depth. API-submitted jobs post no commit status. |
| Drop the guard node in the PR's own CI | Coordinator `base_nodes` re-adds it from base CI. The PR touches `.reactorcide/`, so the review applies too. |
| Push straight to `main` | Needs branch protection (§6). |
| Post a passing status with the required name | The required statuses are `Reactorcide Checks` and `Reactorcide Reviews`, names only the coordinator can post. A workflow-declared status context is never a required one (§6). |
| Add a trust signal to a file outside the review list | The guard fails: the review would not apply. |
| Mark a new file but leave it out of the list | The guard fails: each marked file must match the list. |
| Add a pattern to the list in the PR to cover itself | The guard uses the base list. A list change is under `.reactorcide/`, so the review applies. |
| Weaken trust through a dependency | Not covered. Supply chain needs its own control (`deny.toml` is the start). |

What a pattern check cannot catch: a semantic change in an unmarked file that
weakens a trust decision. The answer is §3.1: keep every trust decision in a
marked file, behind types that unmarked code cannot forge.

## 6. Configuration and open requests

### GitHub (changed 2026-11-19)

Repository ruleset `ci-checks` on the default branch: pull request required
(merge method rebase), linear history, no force push, no deletion, no
creation, and required statuses `Reactorcide Checks` and `Reactorcide Reviews`
with strict updates. The
coordinator posts that status once per event, and a failed
`linkkeys-trust-guard` node fails it. Only the coordinator can post
`Reactorcide Checks`. Do not declare a workflow status context and make it
required: a workflow that gets head CI can declare the same context.

Before the Reactorcide `0381109` deploy, the required status was
`LinkKeys pull request`. The coordinator no longer posts that name.

Bypass: team `automation` (`todpunk`, `catalystcommunityci`), mode `always`.
The release automation needs it to push version bumps. Anyone who controls
the `catalystcommunityci` token can push to `main` without the guard. Keep
that token's scope and storage under the same care as the anchors.

### Reactorcide coordinator policy (applied 2026-11-14)

Project `linkkeys`, revision
`72cd5fb8df7c7d42bd40576844642b35efb2ae80a75162365f3746638ed2a6d6`. Rule
`ci-dev` (head CI for `linkkeys-pr`) grants `base_nodes` for
`linkkeys-trust-guard` (`ci_source: base`, profile `standard`). If the base
workflow has no such node, the coordinator runs the whole workflow from base
CI. If a PR's CI drops the node, the coordinator adds the base node back.
Source file: `~/.config/reactorcide/policies/linkkeys.yaml`.

### Reactorcide required review (applied 2026-11-19)

Org `default-user`, project `linkkeys`. Review `linkkeys-trust-anchors`,
`count: 1`, accept `reactorcide_group:linkkeys-trust-maintainers` only.

The source is `.reactorcide/trust-review-paths.txt` in this repository: the
guarded directories, the git and build control files,
`docs/trust-change-control.md`, and each file that has the marker. The review
ID, description, and accept subject are in `trust_guard.py`. Both files are
under `.reactorcide/`, so a change to them needs the review.

After a change to the list is merged, apply it:

```sh
python3 -I .reactorcide/plugins/trust_guard.py --review-yaml > linkkeys-trust.yaml
reactorcide trust set --org default-user --project linkkeys --file linkkeys-trust.yaml
```

The guard logs a reminder on a PR that changes the list. Until you apply it,
the coordinator uses the old list.

Path patterns are case-sensitive. `**` matches across `/`; `*` does not. A
rename counts the old and the new path.

`trust set` replaces all stored trust settings of the project. A project owner
can make the settings more strict. Only an org admin can make them less
strict, for example remove this review.

### Requests

Filed in `../reactorcide/linkkeys_trust_requests.md`. Status from
Reactorcide (2026-11-15, deployed by 2026-11-19):

- **B1** — done: `vcs_user:` is a valid subject.
- **B2** — done: the coordinator posts `Reactorcide Checks`; the ruleset
  requires it.
- **R1** — done: reserved event facts in runnerlib and the coordinator.
- **R2** — replaced by native required reviews (§4). The old comment forms and
  `REACTORCIDE_CONTENT_APPROVALS` never shipped.
- **R3** — replaced: `accept` and `revoke` update `Reactorcide Reviews` at
  once.
- **R4** — done: `reactorcide groups` and `reactorcide identities`.

Filed in `../vscstar/linkkeys_trust_requests.md`:

- **V1** — Approved reviews pinned to `head_sha` become coordinator approvals.
- **V2** — Per-commit signature results in the event, so the guard can require
  `verified` commits on trust-critical PRs.
- **V3** — Branch protection for `main` with `attested` signatures.
- **V4** — One merge gate during the GitHub mirror period.
