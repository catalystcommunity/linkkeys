# LinkKeys web UI

This directory contains the source for the embedded SolidJS UI. The generated
TypeScript CSIL client is in `src/generated/`. The build output is in
`../crates/linkkeys/assets/ui/` and is part of the server binary.

## Build

From the repository root, run:

```sh
./tools.sh ui-build
```

The command checks password-manager metadata, checks TypeScript, and creates a
production Vite build. Commit the build output with the source change.

Do not edit files in `src/generated/`. Change `csil/linkkeys.csil` and run
this command from the repository root:

```sh
csilgen generate --input csil/linkkeys.csil --target typescript-client \
  --output web-ui/src/generated/
```

## Runtime extensions

An extension is a trusted ECMAScript module. It can use plain DOM code or its
own UI framework. It must export an `activate(host)` function.

```js
export function activate(host) {
  host.registerRoute({
    path: "/app/example",
    title: "Example",
    render(container, context) {
      const button = document.createElement("button");
      button.textContent = `Account: ${context.session?.user.username ?? "none"}`;
      container.append(button);
      return () => button.remove();
    },
  });

  host.registerNavigation({
    path: "/app/example",
    label: "Example",
    order: 100,
  });
}
```

An extension route must start with `/app/`. It must not use a core route. A
route also matches child paths. The host uses the longest matching route.

The host calls `activate(host)` after the first session check. It calls the
function again when the browser session changes. This includes sign-in,
sign-out, and a new session for a different account. Before each new call, the
host removes the routes and navigation from the prior call. The extension must
register all contributions that apply to the current session.

The render context contains these values:

- `path`: the current client path;
- `navigate(path)`: same-origin client navigation;
- `clients`: the generated asynchronous CSIL clients;
- `configuration`: the public UI configuration;
- `session`: the current browser session, when one exists.

Return a cleanup function from `render`. Remove event listeners and DOM state
in this function.

The host removes all registrations when activation fails. It retries the
extension after the next session change. It keeps core routes available and
writes a safe error to the browser console. It shows extension IDs only on the
administration page after the administration call succeeds.

See `../docs/developing/runtime-web-ui.md` and
`../deploy/ui.example.toml` for deployment details.
