import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/targets": "http://127.0.0.1:8000",
      "/sweeps": "http://127.0.0.1:8000",
      "/findings": "http://127.0.0.1:8000",
      "/attestations": "http://127.0.0.1:8000",
      "/healthz": "http://127.0.0.1:8000",
      "/ws": { target: "ws://127.0.0.1:8000", ws: true },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test-setup.ts"],
  },
});
