import { readFileSync } from "node:fs";
import type { ClientRequest, IncomingMessage, ServerResponse } from "node:http";
import { resolve } from "node:path";

import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

import { DEV_PAGE_POLICY, PAGE_POLICY, pageHeaders } from "./pagePolicy.ts";

const REPO_ROOT = resolve(import.meta.dirname, "..");

/** The proxy's "a request is about to go to the gateway" event: the request to it, and the browser's request and response. */
type ProxyRequestListener = (upstream: ClientRequest, request: IncomingMessage, response: ServerResponse) => void;

export default defineConfig(({ mode, command }) => {
  if (command === "build") {
    return { plugins: [react()] };
  }

  // Read here on the server only. The browser never sees these: envDir stays this folder,
  // so nothing from the root .env can reach the page.
  const { SSL_KEYSTORE_PASSWORD } = loadEnv(mode, REPO_ROOT, "SSL_KEYSTORE_PASSWORD");
  const https = { pfx: readFileSync(resolve(REPO_ROOT, "certs/gateway-dev.p12")), passphrase: SSL_KEYSTORE_PASSWORD };

  // The browser only talks to this server, which passes /api on. One origin, so no CORS. The
  // gateway's certificate is checked against ours, not switched off.
  const proxy = {
    "/api": {
      target: { protocol: "https:", host: "localhost", port: 8443, ca: readFileSync(resolve(REPO_ROOT, "certs/gateway-dev.crt")) },
      changeOrigin: true,
      secure: true,
      // When a page goes away (closed, reloaded), close its request to the gateway too. Otherwise
      // the proxy keeps a live-updates feed open for a page that no longer exists, and after a few
      // reloads the gateway's per-user limit pauses live updates. (Caddy does this on the server.)
      configure: (server: { on: (event: "proxyReq", listener: ProxyRequestListener) => void }) => {
        server.on("proxyReq", (upstream, _request, response) => {
          response.on("close", () => {
            if (!response.writableEnded) {
              upstream.destroy();
            }
          });
        });
      },
    },
  };

  return {
    plugins: [react()],
    server: { port: 5173, strictPort: true, host: "localhost", https, proxy, headers: pageHeaders(DEV_PAGE_POLICY) },
    preview: { port: 5173, strictPort: true, host: "localhost", https, proxy, headers: pageHeaders(PAGE_POLICY) },
  };
});
