import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Pure logic tests run in Node. A DOM test opts in with
    // `// @vitest-environment happy-dom` at the top of its file.
    environment: "node",
  },
});
