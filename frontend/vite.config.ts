import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` serves the SPA on :5173 and sends /api to the app container on :8080.
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": "http://localhost:8080" } },
  build: { outDir: "dist", sourcemap: false },
});
