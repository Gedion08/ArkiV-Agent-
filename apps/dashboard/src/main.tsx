import "./index.css";
import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { WagmiProvider } from "wagmi";
import { App } from "./app.js";
import { ApiError } from "./lib/api.js";
import { navigate } from "./lib/route.js";
import { wagmiConfig } from "./lib/wallet.js";

const toLogin = (e: unknown) => {
  if (e instanceof ApiError && e.status === 401 && location.pathname !== "/login")
    navigate("/login", true);
};
const queryClient = new QueryClient({
  queryCache: new QueryCache({ onError: toLogin }),
  mutationCache: new MutationCache({ onError: toLogin }),
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      // 4xx won't change on retry
      retry: (n, e) => !(e instanceof ApiError && e.status < 500) && n < 2,
    },
  },
});

createRoot(document.getElementById("root") as HTMLElement).render(
  <StrictMode>
    {/* no reconnect on load: the wallet is only used to sign in, so its SDKs load on demand */}
    <WagmiProvider config={wagmiConfig} reconnectOnMount={false}>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </WagmiProvider>
  </StrictMode>,
);
