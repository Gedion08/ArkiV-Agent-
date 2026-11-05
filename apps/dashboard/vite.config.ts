import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defaultClientConditions, defineConfig, type Plugin } from "vite";

// L9 §5 CSP on the built page only (dev needs Vite's inline HMR preamble). A <meta> can't carry
// frame-ancestors: whatever serves dist/ must also send the policy, with frame-ancestors 'none', as a header.
// The wallet origins are for sign-in only: WalletConnect relay, Verify and AppKit assets; Coinbase keys popup;
// Base public RPCs (wagmi transports).
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "connect-src 'self' https://*.walletconnect.com wss://*.walletconnect.com https://*.walletconnect.org wss://*.walletconnect.org https://*.reown.com https://keys.coinbase.com https://mainnet.base.org https://sepolia.base.org",
  "img-src 'self' blob: data: https://*.walletconnect.com https://*.reown.com",
  "font-src 'self' https://fonts.reown.com",
  "frame-src https://verify.walletconnect.com https://verify.walletconnect.org https://secure.walletconnect.org https://keys.coinbase.com",
  "style-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
].join("; ");
const csp = (): Plugin => ({
  name: "afr-csp",
  apply: "build",
  transformIndexHtml: () => [
    {
      tag: "meta",
      attrs: { "http-equiv": "Content-Security-Policy", content: CSP },
      injectTo: "head-prepend",
    },
  ],
});

export default defineConfig({
  plugins: [react(), tailwindcss(), csp()],
  resolve: { conditions: ["@afr/source", ...defaultClientConditions] },
  // same origin as the API in dev too: its cookies are __Host- and SameSite=Strict (L8 §2)
  server: { proxy: { "/v1": process.env.AFR_API_URL ?? "http://127.0.0.1:8080" } },
});
