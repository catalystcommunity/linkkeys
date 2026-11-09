import { defineConfig } from "vite";

export default defineConfig({
  base: "/_linkkeys/assets/",
  build: {
    outDir: "../crates/linkkeys/assets/ui",
    emptyOutDir: true,
    assetsDir: "",
    // Keep light-dark() as written. An older target rewrites it to a
    // page-wide media query, and color-scheme on part of a page stops working.
    cssTarget: ["chrome123", "firefox120", "safari17.5"],
    rollupOptions: {
      output: {
        // The server embeds exactly app.js, app.css, and index.html.
        inlineDynamicImports: true,
        entryFileNames: "app.js",
        assetFileNames: (asset) => asset.names?.some((name) => name.endsWith(".css")) ? "app.css" : "[name]-[hash][extname]"
      }
    }
  }
});
