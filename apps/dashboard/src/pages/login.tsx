// L8 §4.1 SIWE login: pick a wallet (wagmi connectors) → nonce → EIP-4361 message signed by it → session
// cookie. The wallet stays connected only for this; the session is the cookie.
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { type Connector, useConnect, useDisconnect, useSignMessage } from "wagmi";
import { ApiError, api, ok } from "../lib/api.js";
import { navigate } from "../lib/route.js";
import { siweMessage } from "../lib/siwe.js";

/** True if any error in the cause chain is the wallet's EIP-1193 user rejection. */
function rejected(e: unknown): boolean {
  for (let x = e, i = 0; typeof x === "object" && x !== null && i < 8; i++) {
    const { code, name, cause } = x as { code?: unknown; name?: unknown; cause?: unknown };
    if (code === 4001 || name === "UserRejectedRequestError") return true;
    x = cause;
  }
  return false;
}

export function loginError(e: unknown): string {
  if (e instanceof ApiError)
    return e.code === "SIWE_UNAVAILABLE"
      ? "The server can't check signatures right now. Try again in a minute."
      : `Sign-in failed (${e.code}).`;
  if (rejected(e)) return "The request was rejected in your wallet.";
  if ((e as { name?: unknown } | null)?.name === "ProviderNotFoundError")
    return "No browser wallet found. Install a wallet extension, or use another option.";
  return "Sign-in failed. Check your wallet and try again.";
}

/** Extensions first (EIP-6963 ones carry their own name and icon), then Coinbase and WalletConnect. */
const ORDER: Record<string, number> = { injected: 0, coinbaseWallet: 1, walletConnect: 2 };
export const sortConnectors = <C extends Pick<Connector, "id" | "type">>(cs: readonly C[]) =>
  [...cs].sort((a, b) => (ORDER[a.type] ?? 0) - (ORDER[b.type] ?? 0));

const LABEL: Record<string, string> = {
  injected: "Browser wallet",
  coinbaseWalletSDK: "Coinbase Wallet",
  walletConnect: "WalletConnect (mobile wallets)",
};

export function LoginPage() {
  const qc = useQueryClient();
  const { connectors, connectAsync } = useConnect();
  const { signMessageAsync } = useSignMessage();
  const { disconnectAsync } = useDisconnect();
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  // the generic "injected" entry only helps when no EIP-6963 wallet announced itself
  const discovered = connectors.some((c) => c.type === "injected" && c.id !== "injected");
  const shown = sortConnectors(connectors).filter((c) => !(discovered && c.id === "injected"));

  async function signIn(connector: Connector) {
    setBusy(connector.uid);
    setError(undefined);
    try {
      const { accounts, chainId } = await connectAsync({ connector });
      const address = accounts[0];
      if (!address) throw new Error("no account");
      const { nonce } = await ok(api().GET("/v1/auth/nonce"));
      const message = siweMessage({
        address,
        chainId,
        nonce,
        host: location.host,
        origin: location.origin,
        now: new Date(),
      });
      const signature = await signMessageAsync({ account: address, message, connector });
      await ok(api().POST("/v1/auth/siwe", { body: { message, signature } }));
      qc.clear();
      navigate("/", true);
    } catch (e) {
      setError(loginError(e));
    } finally {
      await disconnectAsync({ connector }).catch(() => {});
      setBusy(undefined);
    }
  }

  return (
    <main className="mx-auto mt-24 max-w-md px-4">
      <h1 className="text-2xl font-semibold">Agent Flight Recorder</h1>
      <p className="mt-2 text-slate-600 dark:text-slate-400">
        Sign in by signing a message with your wallet. It's not a transaction and costs no gas.
      </p>
      <ul className="mt-6 space-y-2">
        {shown.map((c) => (
          <li key={c.uid}>
            <button
              type="button"
              disabled={!!busy}
              onClick={() => signIn(c)}
              className="flex w-full items-center gap-3 rounded-md border border-slate-300 px-4 py-2.5 text-left hover:bg-slate-50 disabled:opacity-50 dark:border-slate-600 dark:hover:bg-slate-800"
            >
              {c.icon?.startsWith("data:image/") ? (
                <img src={c.icon} alt="" className="h-6 w-6" />
              ) : (
                <span aria-hidden className="h-6 w-6 rounded bg-slate-200 dark:bg-slate-700" />
              )}
              <span className="font-medium">{LABEL[c.id] ?? c.name}</span>
              {busy === c.uid && (
                <span className="ml-auto text-sm text-slate-500">Check your wallet…</span>
              )}
            </button>
          </li>
        ))}
      </ul>
      {error && (
        <p role="alert" className="mt-4 text-red-600 dark:text-red-400">
          {error}
        </p>
      )}
    </main>
  );
}
