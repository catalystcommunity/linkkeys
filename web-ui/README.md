# LinkKeys web UI

This directory contains the source for the embedded LinkKeys UI. The UI uses
Zest web components (`@catalystcommunity/*`) and plain TypeScript. It uses no
application framework. The generated TypeScript CSIL client is in
`src/generated/`. The build output is in
`../crates/linkkeys/assets/ui/` and is part of the server binary.

## Structure

- `src/main.ts` defines the Zest controls, loads the configuration and the
  message catalog, and starts the app shell.
- `src/app.ts` is the shell: header, navigation, session state, and routing.
  `SimpleRouter` keeps the browser history. The shell selects the page for a
  path, because the page depends on the session and the admin permission.
- `src/pages/` holds the pages. Each page is a light DOM Zest
  `BaseComponent` that extends `Page` (`src/page.ts`).
- `src/dom.ts` holds the DOM builder `h()` and the helpers for Zest controls.

Rules for a page:

- Build the elements one time in `build()`. Keep references to the parts that
  change, and change only those parts. Do not build all of the page again for a
  small change, because that loses the focus and the scroll position.
- Use Zest controls for form controls (`text-field`, `text-area`,
  `check-box`, `combo-box`, `push-button`, `date-time-picker`). Credential
  fields are `text-field` elements with the correct `autocomplete` value. Use
  a native element only when Zest has no control for it and the native element
  needs no extra behavior. If a page needs a control that Zest does not have,
  make a component in this repository.
- After each `await`, stop if `this.isActive()` is false.
- Get each text from the message catalog (`t`, `plural`, `formatted`).
- Keep the CSS class names in `src/styles.css`. Operator theme stylesheets use
  them. Zest controls read the `--zest-*` tokens, which `styles.css` maps from
  the LinkKeys colors.

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
