# LinkKeys documentation

Start with the documents in this section if you want to evaluate or integrate
LinkKeys.

In these documents, an RP server is a LinkKeys server that has the RP function
enabled. It can be a dedicated RP server, or it can be an IDP server that also
has the RP function enabled. The combined IDP and RP configuration is the
common configuration.

## Start here

- [Authentication and claims flow](authentication-and-claims-flow.md) explains
  the components, API operations, web login sequences, claim release, and
  application responsibilities.
- [Deploy a relying party](DEPLOYING-RP.md) explains how to run the LinkKeys
  server that holds an application domain's keys.
- [Regular-RP SDKs](../sdks/regular-rp/README.md) lists the complete SDKs and
  the lower-level generated bindings.
- [Build a local-RP app](local-rp-app-developer-guide.md) is for an application
  that does not have public DNS.

## Protocol and trust

- [Protocol specification](spec/README.md) is the normative interoperability
  specification.
- [Design](DESIGN.md) explains the project goals and architecture.
- [Claim trust and verification](claim-trust-verification.md) explains how
  identities, subjects, profiles, and claim signatures relate.
- [Claim policy and consent](claim-policy-and-consent.md) explains claim types,
  signing rules, release policy, and user consent.

## Operations

- [Deploy a relying party](DEPLOYING-RP.md)
- [Local-RP operator guide](local-rp-operator-guide.md)
- [Local-RP administrator guide](local-rp-admin-guide.md)
- [Local-RP key lifecycle](local-rp-key-lifecycle.md)
- [Upgrade LinkKeys](UPGRADING.md)

## Development

- [Runtime web UI](developing/runtime-web-ui.md)
- [Outbound communications and account recovery](developing/outbound-communications-and-account-recovery.md)
- [Repository restructure](RESTRUCTURE.md)

Documents outside `docs/spec/` describe this implementation. If an
implementation document conflicts with the protocol specification, the
specification controls interoperability.
