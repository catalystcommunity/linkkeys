// Fail the build if a password form loses the metadata that password
// managers use. The UI pages are TypeScript files under src/pages/.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("../src/pages/", import.meta.url).pathname;
function sources(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sources(path);
    return entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts") ? [readFileSync(path, "utf8")] : [];
  });
}

const source = sources(root).join("\n");
for (const value of ["username", "current-password", "new-password"]) {
  const pattern = new RegExp(`autocomplete:\\s*["']${value}["']`);
  if (!pattern.test(source)) throw new Error(`Missing password-manager field metadata: autocomplete "${value}"`);
}
