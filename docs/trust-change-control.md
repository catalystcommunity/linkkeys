# Trust change control

How LinkKeys stops a pull request from changing what LinkKeys trusts without
an authorized person approving that exact change.

## 1. Principles

- **The event system proves identity, not git.** Git author and committer
  fields are text that anyone can write. The VCS provider authenticates who
  acts on a pull request; the Reactorcide coordinator verifies the webhook and
  turns that identity into a subject. Only those subjects can authorize.
- **Approve exact content.** An approval binds one head SHA and one base SHA.
  A new push invalidates it.
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
| Authorization | Reactorcide coordinator | Records approvals from authenticated subjects, pinned to head + base SHA, and passes them to the job (`REACTORCIDE_CI_APPROVALS`). |
| Enforcement | GitHub branch protection; vcsstar merge gates | Requires `linkkeys-trust-guard` to succeed before merge. |

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
| An added or removed line, in any file, with a PEM block, `include_bytes!`, `include_str!` of a certificate file, the text `tpm-trust`, the marker, or a change to `forbid(unsafe_code)` | Anchors embedded somewhere new; code that points at the anchor directory; an escape from Rust privacy. |
| A symlink or submodule; a `.gitattributes`, `.gitmodules`, or `build.rs` file | Ways to redirect content or run code at build time. |
| A non-ASCII path; a path that case-folds into a guarded prefix | Look-alike paths. |
| A binary that looks like a DER certificate | An anchor under another name. |

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

Three ways, by Reactorcide state (see `../reactorcide/linkkeys_trust_requests.md`):

| When | How |
| --- | --- |
| Now | A member of the group `linkkeys-trust-maintainers` creates a group approval in the Reactorcide UI, or with `reactorcide approvals create --org <org> --project linkkeys --pr <n> --head-repository <owner/repo> --head-sha <head> --base-sha <base> --workflow linkkeys-trust-anchors --profile standard --policy-revision <current> --subject reactorcide_group:linkkeys-trust-maintainers`. The API accepts a group subject only from a member. |
| After Reactorcide B1 | Comment `/reactorcide approve linkkeys-trust-anchors <profile> <policy-revision>`. Today the coordinator rejects this comment: it cannot store a `vcs_user:` subject, and it then stores nothing. |
| After Reactorcide R2 | Comment `/reactorcide approve-content linkkeys-trust-anchors`. It arrives in `REACTORCIDE_CONTENT_APPROVALS`, needs no profile or policy revision, and head-CI admission ignores it. |

The guard accepts an approval only when all of these are true:

- It comes from `REACTORCIDE_CI_APPROVALS` or `REACTORCIDE_CONTENT_APPROVALS`.
- `kind` is absent, `head_ci`, or `content`. Any other kind is refused until
  someone reviews it in `trust_guard.py`.
- The scope is exactly `linkkeys-trust-anchors` (`label` for a content
  approval, else `workflow_scope`). A `*` approval or a head-CI approval for a
  workflow does not count.
- `approver_subject` is one of `vcs_user:github/todpunk`,
  `vcs_user:github/junipuff`, `reactorcide_group:linkkeys-trust-maintainers`.
  The group needs identity links made by an org admin (`verified_by=admin`)
  and works for any VCS provider the coordinator supports.
- `head_sha` is the checkout HEAD and the event head; `base_sha` is the event
  base.
- It is not invalidated and not expired. A malformed time refuses the record.

The list of approvers and the scope are in `trust_guard.py`. That file runs
from the trusted CI checkout and is itself guarded, so a PR cannot change the
list it is checked against.

**After you approve, close and reopen the PR.** The coordinator stores the
approval but does not re-run the PR, and a retry reuses the facts from the
first run. Reopen starts a new run of the same head with current approvals. A
push makes a new head and invalidates the approval. (Reactorcide R3 will start
a new evaluation when an approval matches the current head.)

`reactorcide run-local` has no coordinator approvals. A trust-critical change
fails locally. That is intended: there is no local bypass.

## 5. Threats and answers

| Attack | Answer |
| --- | --- |
| Commit with a forged todpunk author email | Git identity is ignored. Needs a coordinator approval. |
| Add anchors in a new file elsewhere | PEM, `include_*`, DER, and `tpm-trust` tripwires. |
| Change the loader or verifier, not the anchors | Marked files. |
| Remove the marker, then change the file later | The removal is itself trust-critical. |
| Edit the guard, its job, or the workflow | `.reactorcide/` is guarded; the guard runs from base CI. |
| Hide an edit in a merge commit | Combined diff of each merge. |
| Change and revert, so the final diff is clean | Each commit is checked. |
| Look-alike or case-variant path | NFKC + case folding; non-ASCII paths are trust-critical. |
| Symlink, submodule, `.gitattributes` filter, `build.rs` | Git and build control signals. |
| Reuse an approval after a new push | Approval binds head and base SHA; the coordinator invalidates on push. |
| Reuse a head-CI approval or a `*` approval | Exact scope only. |
| Click "Update branch" or reopen someone else's PR, so the sender is an approver | The sender is not used. Only an explicit approval counts. |
| Shallow checkout hides commits | Unshallow, or fail. |
| Checkout is not the event head | Fail. |
| Forge env facts from workflow YAML | The guard is a `base_nodes` node, so its env comes only from guarded base YAML. Reactorcide R1 adds coordinator-side reserved names as defense in depth. API-submitted jobs post no commit status. |
| Drop the guard node in the PR's own CI | Needs coordinator `base_nodes` for the node, and a required status (§6). |
| Push straight to `main` | Needs branch protection (§6). |
| Post a passing status with the required name | After the Reactorcide `0381109` deploy, the required status is `Reactorcide Checks`, a name only the coordinator can post. A workflow-declared status context is never the required one (§6). |
| Weaken trust through a dependency | Not covered. Supply chain needs its own control (`deny.toml` is the start). |

What a pattern check cannot catch: a semantic change in an unmarked file that
weakens a trust decision. The answer is §3.1: keep every trust decision in a
marked file, behind types that unmarked code cannot forge.

## 6. Configuration and open requests

### GitHub (checked 2026-11-14)

Repository ruleset `ci-checks` on the default branch: pull request required
(merge method rebase), linear history, no force push, no deletion, no
creation, and required status `LinkKeys pull request` with strict updates. That
status is the workflow status, so a failed `linkkeys-trust-guard` node fails
it.

**At the Reactorcide `0381109` deploy, change the required status to
`Reactorcide Checks`.** From that commit, the coordinator posts one status per
event, `Reactorcide Checks`, and no longer posts workflow-name statuses. A PR
would wait forever for `LinkKeys pull request`. Do not switch before the
deploy: the current coordinator does not post the new name, so every PR would
block. Do not declare `status: {context: LinkKeys pull request}` in `pr.yaml`
as a substitute: a workflow that gets head CI can declare the same context.
`Reactorcide Checks` is reserved for the coordinator.

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

The API (`POST /api/v1/approvals`) cannot forge a `vcs_user:` subject; it
accepts only `project_owner` or a group the caller belongs to. The guard
refuses `project_owner`. It accepts the group
`reactorcide_group:linkkeys-trust-maintainers`, which an org admin creates in
the Reactorcide UI, with identity links for each approver made through the
identities API (`verified_by=admin`). Until Reactorcide B1 ships, that group
approval is the only working path.

### Requests

Filed in `../reactorcide/linkkeys_trust_requests.md`, with Reactorcide's
response (order of work: B1, R3, R2, R1, R4):

- **B1** (found by Reactorcide) — comment approvals with a `vcs_user:` subject
  are rejected, so no comment approval is stored. Blocks the comment path.
- **B2** (found by Reactorcide) — the required status name changes at deploy;
  see GitHub above.
- **R1** — reserved event facts, enforced in the coordinator. Defense in depth
  for this guard.
- **R2** — content approvals (`approve-content`,
  `REACTORCIDE_CONTENT_APPROVALS`). The guard already reads them.
- **R3** — an approval that matches the current head starts a new evaluation.
- **R4** — groups exist through the UI; a CLI is still open.

Filed in `../vscstar/linkkeys_trust_requests.md`:

- **V1** — Approved reviews pinned to `head_sha` become coordinator approvals.
- **V2** — Per-commit signature results in the event, so the guard can require
  `verified` commits on trust-critical PRs.
- **V3** — Branch protection for `main` with `attested` signatures.
- **V4** — One merge gate during the GitHub mirror period.
