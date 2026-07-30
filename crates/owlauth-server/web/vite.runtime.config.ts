import { fileURLToPath, URL } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  plugins: [react()],
  publicDir: false,
  build: {
    outDir: "dist/runtime",
    emptyOutDir: true,
    manifest: true,
    sourcemap: false,
    assetsInlineLimit: 0,
    cssCodeSplit: true,
    rollupOptions: {
      input: fileURLToPath(new URL("./src/runtime/main.tsx", import.meta.url)),
      output: {
        entryFileNames: "assets/runtime-[hash].js",
        chunkFileNames: "assets/runtime-chunk-[hash].js",
        assetFileNames: "assets/runtime-[hash][extname]",
      },
    },
  },
});
