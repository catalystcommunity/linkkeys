# LinkKeys vs Kerberos / NT Domains

LinkKeys shares a lot with Kerberos in spirit, less in mechanics.

## What's Very Similar

- **Domain as trust root.** An NT domain controller owns user identities. A LinkKeys domain server owns user private keys. In both, the domain admin is custodian, not the user's device.
- **Transparent SSO.** Kerberos's killer feature was that after you logged into your Windows workstation, you just... opened file shares, printers, intranet apps. No more logins. LinkKeys is explicitly trying to recreate this for the internet — your mother sees nothing unless enrollment is needed.
- **Ticket-like trust delegation.** Kerberos issues TGTs and service tickets so the user doesn't re-authenticate per service. LinkKeys's three-way negotiation (user ↔ user's domain ↔ service's domain) serves the same purpose, just with signed claims instead of tickets.
- **Device as the entry point.** You log into your NT workstation once. LinkKeys enrolls the device once. After that, apps ride the trust chain down.
- **Admin controls the realm.** A Kerberos realm admin manages who's in, who's out, password resets, etc. A LinkKeys domain admin does the same with keys.

## What's Fundamentally Different

- **Federation is native, not bolted on.** Kerberos cross-realm trust was possible but painful — it required explicit admin-to-admin configuration between every pair of realms. LinkKeys uses a web-of-trust model via DNS and signing authorities, so federation scales without bilateral agreements. More like how email works (anyone can send to anyone) than how Kerberos realms work (explicit trust paths).
- **No shared secrets.** Kerberos is symmetric crypto — the KDC and user share a secret (derived from the password). LinkKeys is entirely asymmetric. The domain server holds the user's private key, but trust verification uses public keys. This matters because a compromised service ticket in Kerberos can be replayed or cracked. In LinkKeys, intercepted messages can be verified but not forged.
- **No central time authority dependency.** Kerberos is famously brittle about clock skew (usually 5 minute tolerance). LinkKeys uses UTC timestamps for revocations and signing freshness, but it's not a hard protocol-breaking constraint the same way.
- **Claims vs tickets.** Kerberos tickets are opaque blobs with a fixed structure (principal, realm, validity period, session key). LinkKeys claims are individually signed, individually shareable, and can be countersigned by third parties. A Kerberos ticket says "the KDC says this user is authenticated." A LinkKeys claim can say "the DMV says this user is over 21, and the user's domain countersigned it." Much more granular.
- **No password anywhere.** Kerberos ultimately derives from a password. LinkKeys has no concept of passwords at all — it's keys all the way down. Device keys, user keys, domain keys. Password auth could be a plugin for legacy web flows, but it's not in the identity model.
- **DNS as the discovery layer.** NT domains used WINS, then eventually AD-integrated DNS, but discovery was a LAN-first concern. LinkKeys uses public DNS TXT records as the trust anchor, which is what makes it internet-scale without a central directory.
- **Key ephemerality.** In Kerberos, the KDC's master key is sacred — lose it and you rebuild the realm. In LinkKeys, keys are designed to be ephemeral. Rotate often, revoke casually, keep at least three so losing one is a non-event.

## The Short Version

LinkKeys is what you'd get if you took the NT domain experience (log in once, everything works, admin manages your identity) and redesigned it for the internet age with asymmetric crypto, DNS-based federation, and a web-of-trust model instead of a central authority hierarchy. The UX goal is identical to Kerberos. The trust model is closer to PGP's web of trust. The discovery model is closer to email/DKIM.
