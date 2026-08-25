import { readFileSync } from "node:fs";

const source = readFileSync(new URL("../src/index.tsx", import.meta.url), "utf8");
for (const value of ["autocomplete=\"username\"", "autocomplete=\"current-password\"", "autocomplete=\"new-password\""]) {
  if (!source.includes(value)) throw new Error(`Missing password-manager field metadata: ${value}`);
}
