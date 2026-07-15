/**
 * # @linkkeys/local-rp
 *
 * TypeScript/Node SDK for LinkKeys' DNS-less local RP identity mode
 * (`dns-less-local-rp-design.md` at the repo root — read it first; this
 * package implements its "SDK API Shape" section, Node-idiomatically
 * adapted).
 *
 * This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a
 * self-hosted service with no public DNS) use LinkKeys for login without
 * running its own DNS-pinned relying party. The app's identity is the
 * fingerprint of a locally-generated signing key (SSH-host-key style), not a
 * domain.
 *
 * **Node only — see the README's "Browser is not a target" section before
 * even considering a browser build.**
 *
 * ## Quickstart
 *
 * ```ts
 * import {
 *   generateLocalRpIdentity, beginLocalLogin, completeLocalLogin,
 *   localRpIdentityToBytes, localRpIdentityFromBytes,
 * } from "@linkkeys/local-rp";
 *
 * // Once, at install/setup time — persist the returned bytes with ordinary
 * // application-secret care (see `identity.ts`'s module docs).
 * const identity = generateLocalRpIdentity({ appName: "My LAN Jukebox", now: new Date() });
 * const storedBytes = localRpIdentityToBytes(identity);
 *
 * // Later, per login attempt:
 * const restored = localRpIdentityFromBytes(storedBytes);
 * const { redirect, pending } = beginLocalLogin({
 *   keyMaterial: restored,
 *   callbackUrl: "http://jukebox.lan:8080/auth/callback",
 *   userDomain: "example.com",
 *   now: new Date(),
 * });
 * // App: persist `pending` (e.g. in a server-side session), then redirect
 * // the browser to `redirect.redirectUrl`.
 *
 * // On callback (app's HTTP handler received `arrivedUrl` with an
 * // `encrypted_token=` query parameter whose value is `encryptedToken`):
 * const verified = await completeLocalLogin({
 *   keyMaterial: restored,
 *   pending,
 *   encryptedToken,
 *   arrivedUrl,
 *   now: new Date(),
 * });
 * // `verified` carries user id/domain, claims, domain keys used, the local
 * // RP fingerprint, and expirations — session creation, local user
 * // records, and authorization are all the app's own responsibility.
 * ```
 *
 * ## Storage and single-use responsibilities this SDK assigns to the app
 *
 * - **Key material**: persist the bytes from `localRpIdentityToBytes` with
 *   ordinary application-secret care (same tier as a database credential or
 *   API key).
 * - **`PendingLogin`**: persist it (it is plain, JSON-serializable data)
 *   between `beginLocalLogin` and `completeLocalLogin`, and discard it after
 *   one completion attempt. This package owns no storage and cannot enforce
 *   single-use itself.
 * - **Sessions, local user records, authorization**: entirely the app's.
 *   This package returns verified protocol facts; it never creates a
 *   session or writes to an app database.
 *
 * ## Security notes
 *
 * - Revoking this local RP identity at the IDP kills future logins AND any
 *   outstanding claim tickets immediately — but it does NOT reach into
 *   sessions the app already minted from a prior successful login. Session
 *   lifecycle is the app's to manage.
 * - Key rotation is not supported as a continuity operation: generating a
 *   new identity means a new fingerprint and re-approval at every LinkKeys
 *   domain.
 * - Domain keys and revocations fetched over the network are only ever
 *   trusted after DNS `fp=` pinning (`src/rpc.ts`) — an unpinned/
 *   unauthenticated key can never reach the verification chain.
 * - The default DNS resolver is the OS-configured system resolver; LAN
 *   resolver spoofing is an accepted, documented tradeoff for this mode.
 *   Inject a hardened `DnsResolver` if your deployment needs more.
 */

export {
  DEFAULT_LIFETIME_MS,
  InvalidInputError,
  encryptionKeyFromBytes,
  encryptionKeyToBytes,
  fingerprintFromString,
  fingerprintToString,
  generateLocalRpIdentity,
  localRpIdentityFromBytes,
  localRpIdentityToBytes,
  signingKeyFromBytes,
  signingKeyToBytes,
  type GenerateLocalRpIdentityConfig,
  type LocalRpKeyMaterial,
} from "./identity.ts";

export {
  DEFAULT_LOGIN_REQUEST_LIFETIME_MS,
  DEFAULT_REQUESTED_CLAIMS,
  DEFAULT_REQUIRED_CLAIMS,
  beginLocalLogin,
  type BeginLocalLoginConfig,
  type LocalLoginRedirect,
  type PendingLogin,
} from "./begin.ts";

export {
  completeLocalLogin,
  type CompleteLocalLoginConfig,
  type VerifiedLocalLogin,
} from "./complete.ts";

export {
  DEFAULT_CLOCK_SKEW_SECONDS,
  LocalRpError,
  type ExpirationLevel,
  type ExpirationStatus,
  type LocalRpErrorCode,
} from "./localRp.ts";

export { ClaimError, signClaim, type ClaimSigner, type ClaimSpec, type DomainKeySet } from "./claims.ts";
export { DnsParseError, isValidFingerprint } from "./dnsRecords.ts";
export { DnsLookupError, SystemDnsResolver, type DnsResolver } from "./dns.ts";
export { NodeTransport, TransportError, type AddressPolicy, type Transport } from "./transport.ts";
export { NoTrustedDomainKeysError, ProtocolError, RpcServerError, TlsError } from "./rpc.ts";
export { defaultDnsResolver, defaultTransport } from "./defaults.ts";

// Re-exported so app code doesn't need a direct dependency on the generated
// module just to name these types.
export type { Claim, ClaimSignature, DomainPublicKey } from "./generated/types.gen.ts";

import * as generated from "./generated/codec.gen.ts";
import type { LocalRpKeyMaterial } from "./identity.ts";
import { checkExpirations as checkExpirationsForTimestamp, type ExpirationStatus } from "./localRp.ts";

/**
 * `check_expirations(identity, now) -> ExpirationStatus` (design doc, "SDK
 * API Shape" / "Expiration Helper"). Thin wrapper taking the identity's
 * descriptor `expiresAt` directly. The SDK reports facts; the app decides
 * whether to warn admins, warn users, block login, renew, or ignore.
 */
export function checkExpirations(identity: LocalRpKeyMaterial, now: Date): ExpirationStatus {
  const descriptor = generated.fromLocalRpDescriptorCbor(identity.descriptor.descriptor);
  return checkExpirationsForTimestamp(descriptor.expiresAt, now);
}
