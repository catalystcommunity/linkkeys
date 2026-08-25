# Runtime web UI and extensions

Status: Implemented.

Scope: This document defines the web UI host in the LinkKeys server. It does not
define a LinkKeys protocol requirement.

Absorbs: This document expands the server plugin-hosting boundary in
[`DESIGN.md`](../DESIGN.md) and replaces the current assumption that the server
must render each application page from Rust.

## Current implementation

The canonical HTTP carrier accepts browser, API-key, and server identities.
Browser calls use the generated CSIL session, account, administration,
notification, recovery, and UI configuration contracts. Cookie-authenticated
calls must pass the same-origin check.

LinkKeys creates a random 256-bit browser token. The cookie contains only this
opaque token. The database contains its SHA-256 digest and session state. The
cookie is named `__Host-linkkeys_session`. It uses `Secure`, `HttpOnly`,
`SameSite=Lax`, and the `/` path. It has no `Domain` attribute. Session
introspection requires the `ui_extension` relation.

`UI_CONFIG_FILE` can define safe display values, a theme, and runtime extension
records. LinkKeys validates IDs, host API versions, same-origin asset URLs, and
mounted asset directories at startup. The CSIL response does not expose asset
directory paths. `UI_DIST_DIR` must name an existing directory when it is set.
For each file request, LinkKeys resolves the configured root and target. It
rejects a target that resolves outside the configured root.

The binary embeds a SolidJS host and its generated TypeScript CSIL client. The
server supplies SPA fallback routing, strict security headers, theme assets,
runtime extension assets, and full UI replacement. The host provides login,
account and claim functions, application authorization and consent, email
verification, password recovery, and core account administration.

The older Rust pages stay available at their existing paths for one
compatibility release after the SPA release. New integrations must use the SPA
and CSIL path. LinkKeys can remove the older pages only in an announced
breaking release.

## Goals

The LinkKeys binary must include a complete web UI. An operator can run the
binary without a separate UI build or service.

An operator must also be able to change the theme, add product functions, or
replace the complete UI at runtime. These changes must not require a new
LinkKeys build.

CatalystLinkKeys must be able to add its inbox and other product functions to
the LinkKeys UI. It must not replace the account, login, consent, or protocol
functions that LinkKeys already provides.

## Embedded host

LinkKeys embeds a compiled SolidJS single-page application. This application is
the UI host. It includes the default theme and all core LinkKeys pages.

The host must provide:

- login and logout;
- account and claim management;
- consent;
- contact verification and password recovery when available;
- core administration;
- error and unavailable pages;
- extension loading and failure isolation.

The server must also include a small static error page. The server can return
this page when the SPA assets cannot load.

The supported browser target is a modern browser released in the last two
years. The host must keep a small initial bundle. Do not add a large component
library or browser cryptography without a measured need.

## CSIL browser path

CSIL remains the source of truth for UI data and service operations. Generate a
TypeScript client with the `typescript-client` target. The generated client is
transport-neutral. The UI supplies a browser transport that sends CBOR to:

```text
POST /csil/v1/rpc
```

Do not add a JSON UI API or a second `/ui/v1/rpc` carrier. The browser carrier
must use the canonical CSIL-RPC envelope and status registry.

The browser sends its opaque session cookie with same-origin requests. The
HTTP carrier must add browser session identity to the dispatch context. The
same dispatcher must continue to support API-key and server identities.

Use these service access rules:

| Service | Allowed identity |
| --- | --- |
| `I18n` | Public |
| `Ui/get-configuration` | Public |
| `Notification/get-capabilities` | Public |
| `Session/login-password` | Public browser carrier |
| `Session/logout` and `Session/get-current` | Browser session |
| `Session/introspect` | Server identity with the `ui_extension` relation |
| `BrowserAuthorization` | Browser session |
| `Recovery` | Public |
| `Account` | Browser session or API key for the same account |
| `Admin` | Authorized browser session or authorized API key |
| `Rp` | API key or server identity only |

Cookie-authenticated CSIL requests must pass the existing same-origin
Origin/Referer check. This check is not required for API-key or mutually
authenticated server requests.

The CSIL schema defines browser session, browser authorization, UI
configuration, notification capability, contact verification, and recovery
operations. Implement these generated contracts. Do not create hand-written
UI data types that duplicate them.

`GET /auth/authorize` validates the signed relying-party request before it
redirects to `/app/authorize`. It puts the signed request in the URL fragment.
The SPA keeps the value in session storage until authorization finishes. A
signed-in browser calls `BrowserAuthorization/inspect` to get the consent
screen and calls `BrowserAuthorization/complete` to get the relying-party
redirect URL.

## Asset and route paths

The default path layout is:

| Path | Owner |
| --- | --- |
| `/app/*` | Embedded UI host and its client routes |
| `/auth/*` | Browser authentication protocol routes |
| `/csil/v1/rpc` | Canonical CSIL-RPC HTTP carrier |
| `/_linkkeys/assets/*` | Embedded or replacement UI assets |
| `/_linkkeys/themes/*` | Operator theme assets |
| `/_linkkeys/extensions/<id>/*` | Same-origin extension assets |

The host owns these core client paths:

- `/app/login`;
- `/app/authorize`;
- `/app/consent`;
- `/app/account/*`;
- `/app/verify/*`;
- `/app/password/*`;
- `/app/admin/*` for core administration.

An extension can register a different `/app/*` path. It cannot replace a core
path. LinkKeys must reject a route conflict and report it in operator
diagnostics. A full UI replacement is the only supported way to replace core
routes.

## UI configuration

The host calls `Ui/get-configuration` during startup. Its generated
`GetUiConfigurationResponse` contains:

- the LinkKeys UI host API version;
- public domain information;
- enabled capabilities;
- theme asset URLs;
- extension records;
- safe display settings.

The response must not contain a filesystem path, credential, private relation,
or server secret.

Use `UI_CONFIG_FILE` for the optional runtime UI configuration file. The file
uses TOML. The single file can name a theme and one or more extensions. For
example:

```toml
[theme]
asset_dir = "/srv/linkkeys-ui/theme"
stylesheet_url = "/_linkkeys/themes/operator/theme.css"
logo_url = "/_linkkeys/themes/operator/logo.svg"
favicon_url = "/_linkkeys/themes/operator/favicon.svg"

[[extensions]]
id = "catalyst"
asset_dir = "/srv/catalyst-linkkeys/ui-dist"
module_url = "/_linkkeys/extensions/catalyst/extension.js"
api_version = 1
stylesheet_url = "/_linkkeys/extensions/catalyst/extension.css"
```

`asset_dir` is optional. When it is present, LinkKeys serves files from that
directory under the URL namespace for the theme or extension. Omit it when a
reverse proxy serves the URL. The CSIL UI configuration response must omit this
filesystem value.

LinkKeys must validate the file at startup. Duplicate IDs, incompatible API
versions, missing asset directories, and invalid URLs are configuration errors.
The browser host detects route conflicts when an extension registers a route.

## Themes

The embedded UI loads its default CSS first. It then loads the configured theme
stylesheet. The default stylesheet exposes CSS custom properties for colors,
type, radius, shadows, and layout limits.

The theme can set these properties on `:root`:

- colors: `--bg`, `--panel`, `--panel-raised`, `--ink`, `--muted`,
  `--accent`, `--accent-ink`, `--good`, `--bad`, `--line`, and `--control-bg`;
- shape and depth: `--radius`, `--control-radius`, and `--shadow`;
- type: `--font-family`;
- layout: `--content-width`, `--narrow-width`, and `--wide-width`.

A theme can supply a stylesheet, logo, and favicon. A theme cannot run
JavaScript. Theme URLs must be same-origin by default.

An operator can mount theme files for LinkKeys to serve under
`/_linkkeys/themes/<id>/`. A reverse proxy can also provide same-origin theme
URLs.

## Runtime extensions

A UI extension is a compiled ECMAScript module. LinkKeys reads its record at
runtime. The UI host imports the module at runtime. LinkKeys does not compile or
link the extension into its binary.

An extension developer still builds source files such as TypeScript or TSX into
browser JavaScript. This build is independent of the LinkKeys build. A product
can deploy a new extension without rebuilding LinkKeys.

The module exports an activation function:

```js
export function activate(host) {
  host.registerRoute({
    path: "/app/catalyst/inbox",
    title: "Inbox",
    render(container, context) {
      container.textContent = `Signed in as ${context.session.user.username}`;
      return () => {
        container.replaceChildren();
      };
    },
  });

  host.registerNavigation({
    path: "/app/catalyst/inbox",
    label: "Inbox",
    order: 50,
  });
}
```

The host API is framework-neutral. It passes a DOM container and a small
context object. It does not pass a SolidJS owner, signal, or component. An
extension can use SolidJS, another framework, or plain DOM code. This rule
prevents the host and extension from sharing a framework version.

Host API version 1 supports these contributions:

- client routes;
- navigation items;
- capability reads;
- host navigation;
- lifecycle cleanup.

The host gives each extension a separate host facade. The facade assigns each
contribution to that extension. The host removes all registrations if module
load or activation fails. A five-second timeout applies to each phase. A late
registration from a disabled extension has no effect.

## Extension delivery

LinkKeys supports two same-origin delivery forms:

1. An operator mounts a directory. LinkKeys serves it from
   `/_linkkeys/extensions/<id>/`.
2. A reverse proxy routes `/_linkkeys/extensions/<id>/` to another web service.

The reverse-proxy form is the preferred CatalystLinkKeys deployment. It lets
the Catalyst service deploy its extension with its other assets.

Extensions are disabled by default. Each extension needs an operator
configuration record. Same-origin module URLs are the default and recommended
mode.

The current host rejects cross-origin module URLs. A reverse proxy can serve an
external service under the same LinkKeys origin.

## Trust and failure rules

A runtime extension is privileged code. It runs in the same origin and page as
the LinkKeys UI. It can see the page and can make requests with the user's
session. Install extensions only from a trusted operator source.

Do not use this extension API for untrusted code. A future untrusted extension
model must use a sandboxed iframe and a small message interface.

The host must:

- set a module load timeout;
- isolate activation and lifecycle errors;
- continue to provide all core routes after an extension failure;
- show a safe operator diagnostic without showing it to normal users;
- reject an unsupported host API major version;
- apply a Content Security Policy that names every permitted script, style,
  image, and connection source.

An extension cannot weaken cookie flags, CSRF checks, CSIL authorization, or
core route policy.

## Full UI replacement

An operator can set `UI_DIST_DIR` to a directory with a complete UI build. This
option replaces the embedded host assets. The server still owns protocol paths,
the CSIL carrier, security headers, and the static failure page.

The replacement must implement the LinkKeys UI configuration and CSIL client
contracts. It receives no compatibility promise beyond the declared UI host
API and CSIL versions.

Use this option for a complete product UI. Do not use it only to add one route
or change colors.

## CatalystLinkKeys layout

A same-origin reverse proxy can use this layout:

```text
/app/*                                      -> LinkKeys UI host
/auth/*                                     -> LinkKeys browser protocol
/csil/v1/rpc                                -> LinkKeys
/_linkkeys/extensions/catalyst/*            -> Catalyst web assets
/api/v1/*                                   -> Catalyst application service
```

The Catalyst module registers its additional routes and navigation items with
the host. LinkKeys continues to own login, account, consent, verification, and
password recovery.

For same-origin application requests, Catalyst can pass the opaque LinkKeys
browser session value to LinkKeys over an authenticated and encrypted CSIL
connection. A session introspection operation returns only the account ID,
effective session expiry, and required authorization context. The effective
expiry includes the idle timeout. A caller must not cache the result after this
time. Catalyst can map this
identity to its data and can create its own application session.

The server identity that calls introspection needs a dedicated `ui_extension`
relation. The operation must reject an expired or invalidated browser session.
Neither service can log the opaque session value.

Do not expose a general browser-session introspection operation to public
clients. A later cross-origin design can use a short-lived audience-bound
assertion instead of forwarding an opaque cookie.

## Test requirements

Tests must cover:

- startup with the embedded UI and no configuration file;
- theme load order and missing theme assets;
- extension configuration validation;
- extension API version mismatch;
- extension load timeout and activation failure;
- route conflict rejection;
- cleanup after extension failure or unload;
- core route availability after every extension failure;
- same-origin checks for cookie-authenticated CSIL requests;
- service authorization for browser, API-key, and server identities;
- Content Security Policy output for embedded, mounted, and reverse-proxy
  assets;
- a production build with no development source maps or secret configuration;
- browser tests for the oldest supported mobile browser engines.

Use a small test extension that does not depend on SolidJS. Add a separate
Catalyst contract test for its route and navigation registrations.

## Build and deploy

Run `./tools.sh ui-build` after a change in `web-ui/`. Commit the generated
files in `crates/linkkeys/assets/ui/` with the source change. The server image
does not need Node.js because it embeds these generated files.

Use `deploy/ui.example.toml` as the base runtime configuration. Set
`UI_CONFIG_FILE` to the file path. Mount each `asset_dir` into the LinkKeys
process, or serve the matching URL from a same-origin reverse proxy.

Set `UI_DIST_DIR` only when you must replace the complete host. The directory
must contain `index.html` and all assets that this file references.
