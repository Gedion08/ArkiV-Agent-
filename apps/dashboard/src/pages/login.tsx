// L8 §4.1 SIWE login: nonce → EIP-4361 message signed by the injected wallet → session cookie.
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { createWalletClient, custom, type EIP1193Provider } from "viem";
import { ApiError, api, ok } from "../lib/api.js";
import { navigate } from "../lib/route.js";
import { siweMessage } from "../lib/siwe.js";

export function loginError(e: unknown): string {
  if (e instanceof ApiError)
    return e.code === "SIWE_UNAVAILABLE"
      ? "The server can't check signatures right now. Try again in a minute."
      : `Sign-in failed (${e.code}).`;
  if (typeof e === "object" && e !== null && (e as { code?: unknown }).code === 4001)
    return "The request was rejected in your wallet.";
  return "Sign-in failed. Check your wallet and try again.";
}

export function LoginPage() {
  const qc = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const eth = (window as { ethereum?: EIP1193Provider }).ethereum;

  async function signIn(provider: EIP1193Provider) {
    setBusy(true);
    setError(undefined);
    try {
      const wallet = createWalletClient({ transport: custom(provider) });
      const [address] = await wallet.requestAddresses();
      if (!address) throw new Error("no account");
      const chainId = await wallet.getChainId();
      const { nonce } = await ok(api().GET("/v1/auth/nonce"));
      const message = siweMessage({
        address,
        chainId,
        nonce,
        host: location.host,
        origin: location.origin,
        now: new Date(),
      });
      const signature = await wallet.signMessage({ account: address, message });
      await ok(api().POST("/v1/auth/siwe", { body: { message, signature } }));
      qc.clear();
      navigate("/", true);
    } catch (e) {
      setError(loginError(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto mt-24 max-w-md px-4">
      <h1 className="text-2xl font-semibold">Agent Flight Recorder</h1>
      <p className="mt-2 text-slate-600 dark:text-slate-400">
        Sign in by signing a message with your wallet. It's not a transaction and costs no gas.
      </p>
      {eth ? (
        <button
          type="button"
          disabled={busy}
          onClick={() => signIn(eth)}
          className="mt-6 rounded-md bg-slate-900 px-4 py-2 text-white disabled:opacity-50 dark:bg-slate-100 dark:text-slate-900"
        >
          {busy ? "Waiting for your wallet…" : "Sign in with wallet"}
        </button>
      ) : (
        <p className="mt-6">No browser wallet found. Install a wallet extension and reload.</p>
      )}
      {error && (
        <p role="alert" className="mt-4 text-red-600 dark:text-red-400">
          {error}
        </p>
      )}
    </main>
  );
}
