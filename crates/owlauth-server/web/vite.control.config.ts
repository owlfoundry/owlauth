import { fileURLToPath, URL } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  plugins: [react()],
  publicDir: false,
  build: {
    outDir: "dist/control",
    emptyOutDir: true,
    manifest: true,
    sourcemap: false,
    assetsInlineLimit: 0,
    cssCodeSplit: true,
    rollupOptions: {
      input: fileURLToPath(new URL("./src/control/main.tsx", import.meta.url)),
      output: {
        entryFileNames: "assets/control-[hash].js",
        chunkFileNames: "assets/control-chunk-[hash].js",
        assetFileNames: "assets/control-[hash][extname]",
      },
    },
  },
});
