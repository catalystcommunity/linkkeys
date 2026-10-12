import { readFileSync } from "node:fs";

const source = ["index.tsx", "admin.tsx"].map((name) => readFileSync(new URL(`../src/${name}`, import.meta.url), "utf8")).join("\n");
for (const value of ["autocomplete=\"username\"", "autocomplete=\"current-password\"", "autocomplete=\"new-password\""]) {
  if (!source.includes(value)) throw new Error(`Missing password-manager field metadata: ${value}`);
}
