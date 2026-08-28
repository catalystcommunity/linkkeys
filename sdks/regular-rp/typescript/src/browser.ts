export class BrowserLoginError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BrowserLoginError";
  }
}

export interface BrowserLoginOptions {
  /** An application endpoint that calls RegularRpClient.beginLogin. */
  backendUrl: string;
  identity: string;
  fetch?: typeof globalThis.fetch;
  navigate?: (url: string) => void;
  signal?: AbortSignal;
}

/** Ask the application backend to begin login. This function never contacts an IDP directly. */
export async function requestLoginRedirect(options: BrowserLoginOptions): Promise<string> {
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const response = await fetchImpl(options.backendUrl, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json", "accept": "application/json" },
    body: JSON.stringify({ identity: options.identity }),
    signal: options.signal,
  });
  if (!response.ok) throw new BrowserLoginError(`the application rejected login (${response.status})`);
  const body: unknown = await response.json();
  if (typeof body !== "object" || body === null || !("redirectUrl" in body) || typeof body.redirectUrl !== "string") {
    throw new BrowserLoginError("the application returned an invalid login response");
  }
  const redirect = new URL(body.redirectUrl);
  if (redirect.protocol !== "https:") throw new BrowserLoginError("the LinkKeys redirect must use HTTPS");
  return redirect.href;
}

/** Begin login and move the current browser page to the LinkKeys IDP. */
export async function startLinkKeysLogin(options: BrowserLoginOptions): Promise<void> {
  const redirectUrl = await requestLoginRedirect(options);
  const navigate = options.navigate ?? ((url: string) => globalThis.location.assign(url));
  navigate(redirectUrl);
}
