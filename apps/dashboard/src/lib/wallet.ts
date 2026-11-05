// Wallets for SIWE sign-in (L9 §5, ADR-026): every EIP-6963 browser extension, Coinbase Wallet and, when a
// Reown project id is built in, WalletConnect for mobile wallets. Sign-in only signs a message.
import { createConfig, http } from "wagmi";
import { base, baseSepolia } from "wagmi/chains";
import { coinbaseWallet, injected, walletConnect } from "wagmi/connectors";

/** Public Reown (WalletConnect Cloud) project id, set at build time. Without it WalletConnect is hidden. */
export const WALLETCONNECT_PROJECT_ID: string | undefined =
  import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || undefined;

const APP = "Agent Flight Recorder";

export const wagmiConfig = createConfig({
  chains: [base, baseSepolia],
  // a transport per chain is required; the dashboard never sends transactions through them
  transports: { [base.id]: http(), [baseSepolia.id]: http() },
  // EIP-6963 extensions are discovered on top of these (multiInjectedProviderDiscovery)
  connectors: [
    injected(),
    coinbaseWallet({ appName: APP }),
    ...(WALLETCONNECT_PROJECT_ID
      ? [
          walletConnect({
            projectId: WALLETCONNECT_PROJECT_ID,
            showQrModal: true,
            metadata: {
              name: APP,
              description: "Flight recorder for AI agents that move money",
              url: location.origin,
              icons: [],
            },
          }),
        ]
      : []),
  ],
});

declare module "wagmi" {
  interface Register {
    config: typeof wagmiConfig;
  }
}
