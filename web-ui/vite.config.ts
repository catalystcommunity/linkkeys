import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

export default defineConfig({
  base: "/_linkkeys/assets/",
  plugins: [solid()],
  build: {
    outDir: "../crates/linkkeys/assets/ui",
    emptyOutDir: true,
    assetsDir: "",
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "chunk-[hash].js",
        assetFileNames: (asset) => asset.names?.some((name) => name.endsWith(".css")) ? "app.css" : "[name]-[hash][extname]"
      }
    }
  }
});
