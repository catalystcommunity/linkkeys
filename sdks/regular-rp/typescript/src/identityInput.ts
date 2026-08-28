export interface IdentityInput {
  username?: string;
  domain: string;
}

export class InvalidIdentityInputError extends Error {
  constructor() {
    super("identity must be a username@domain or a domain");
    this.name = "InvalidIdentityInputError";
  }
}

function validUsername(username: string): boolean {
  if (username.length === 0 || username.length > 64 || username.startsWith(".") || username.endsWith(".")) {
    return false;
  }
  return /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+(?:\.[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*$/.test(username);
}

function validDomain(domain: string): boolean {
  if (domain.length === 0 || domain.length > 259) return false;
  const match = /^(.*?)(?::([0-9]+))?$/.exec(domain);
  if (!match) return false;
  const host = match[1]!;
  const portText = match[2];
  const hasPort = portText !== undefined;
  if (hasPort) {
    const port = Number(portText);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return false;
  }
  if (host.length === 0 || host.length > 253 || (!host.includes(".") && !hasPort)) return false;
  return host.split(".").every((label) =>
    label.length > 0 && label.length <= 63 && !label.startsWith("-") && !label.endsWith("-") && /^[A-Za-z0-9-]+$/.test(label),
  );
}

/** Parse the identity field that an application collects before login. */
export function parseIdentityInput(raw: string): IdentityInput {
  const input = raw.trim();
  if (input.length === 0 || !/^[\x00-\x7f]+$/.test(input)) throw new InvalidIdentityInputError();
  const parts = input.split("@");
  if (parts.length > 2) throw new InvalidIdentityInputError();
  const username = parts.length === 2 ? parts[0] : undefined;
  const domain = parts.length === 2 ? parts[1]! : parts[0]!;
  if ((username !== undefined && !validUsername(username)) || !validDomain(domain)) {
    throw new InvalidIdentityInputError();
  }
  return { username, domain: domain.toLowerCase() };
}
