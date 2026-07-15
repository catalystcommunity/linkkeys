// Package localrp is the Go SDK for LinkKeys' DNS-less local RP identity
// mode (dns-less-local-rp-design.md at the repo root — read it first; this
// package implements its "SDK API Shape" section, Go-idiomatically adapted).
//
// This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a
// self-hosted service with no public DNS) use LinkKeys for login without
// running its own DNS-pinned relying party. The app's identity is the
// fingerprint of a locally-generated signing key (SSH-host-key style), not a
// domain.
//
// # Quickstart
//
//	// Once, at install/setup time — persist the returned bytes with
//	// ordinary application-secret care (see "Security notes" below).
//	identity, err := localrp.GenerateLocalRpIdentity(localrp.GenerateLocalRpIdentityConfig{
//		AppName: "My LAN Jukebox",
//		Now:     time.Now(),
//	})
//	storedBytes := localrp.LocalRpIdentityToBytes(identity)
//
//	// Later, per login attempt:
//	identity, err = localrp.LocalRpIdentityFromBytes(storedBytes)
//	redirect, pending, err := localrp.BeginLocalLogin(localrp.BeginLocalLoginConfig{
//		KeyMaterial: identity,
//		CallbackURL: "http://jukebox.lan:8080/auth/callback",
//		UserDomain:  "example.com",
//		Now:         time.Now(),
//	})
//	// App: persist `pending` (it's a plain JSON-taggable struct — put it in
//	// a server-side session), then redirect the browser to
//	// redirect.RedirectURL.
//
//	// On callback (app's HTTP handler received arrivedURL with an
//	// `encrypted_token=` query parameter whose value is encryptedToken):
//	verified, err := localrp.CompleteLocalLogin(localrp.CompleteLocalLoginConfig{
//		KeyMaterial:    identity,
//		Pending:        pending,
//		EncryptedToken: encryptedToken,
//		ArrivedURL:     arrivedURL,
//		Now:            time.Now(),
//	})
//	// `verified` carries user id/domain, claims, domain keys used, the
//	// local RP fingerprint, and expirations — session creation, local user
//	// records, and authorization are all the app's own responsibility.
//
// # Storage and single-use responsibilities this SDK assigns to the app
//
//   - Key material: persist the bytes from [LocalRpIdentityToBytes] with
//     ordinary application-secret care (same tier as a database credential
//     or API key).
//   - [PendingLogin]: persist it between [BeginLocalLogin] and
//     [CompleteLocalLogin], and discard it after one completion attempt.
//     This package owns no storage and cannot enforce single-use itself.
//   - Sessions, local user records, authorization: entirely the app's. This
//     package returns verified protocol facts; it never creates a session or
//     writes to an app database.
//
// # Security notes
//
//   - Revoking this local RP identity at the IDP kills future logins AND any
//     outstanding claim tickets immediately (redemption re-checks approval
//     status every time) — but it does NOT reach into sessions the app
//     already minted from a prior successful login. Session lifecycle is
//     the app's to manage.
//   - Key rotation is not supported as a continuity operation: generating a
//     new identity means a new fingerprint and re-approval at every LinkKeys
//     domain. There is no "same app, new key" story in this protocol
//     version.
//   - Domain keys and revocations fetched over the network are only ever
//     trusted after DNS `fp=` pinning ([FetchDomainKeys]) — an
//     unpinned/unauthenticated key can never reach the verification chain.
//   - The default DNS resolver is the OS-configured system resolver; LAN
//     resolver spoofing is an accepted, documented tradeoff for this mode.
//     Inject a hardened [DnsResolver] if your deployment needs more.
//   - The default [Transport] ([StdTransport]) dials whatever address DNS
//     returns, including private/loopback/LAN addresses — that is the
//     entire point of this mode. Set its Policy field to
//     [AddressPolicyPublicOnly] to opt into a stricter SSRF-guard posture.
package localrp
