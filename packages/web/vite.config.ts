import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    /**
     * Proxy the API through the dev server so the browser sees a single origin.
     *
     * This is not just convenience: it means the session cookie is same-origin in
     * development exactly as it is in production behind nginx, so the auth flow
     * being tested locally is the real one rather than a CORS-relaxed variant
     * that could hide a cookie problem until deploy.
     */
    /*
      Anchored patterns, not bare prefixes.

      A plain `"/api"` key is a prefix match, so it also captured client routes that merely
      begin with those letters -- `/api-access` was forwarded to the API and came back as
      `route_not_found`, while working perfectly in production. That asymmetry is the trap:
      nginx proxies `location /api/` with the slash, so the deployed build routes such a path
      to the SPA and only the dev server disagrees. Matching production here means a new client
      route cannot be broken in development alone.
    */
    proxy: {
      "^/api/": {
        target: "http://127.0.0.1:3000",
        changeOrigin: false,
      },
      "^/health(/|$)": {
        target: "http://127.0.0.1:3000",
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
