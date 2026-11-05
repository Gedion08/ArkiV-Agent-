// L8 §4.1 SIWE login: pick a wallet (wagmi connectors) → nonce → EIP-4361 message signed by it → session
// cookie. The wallet stays connected only for this; the session is the cookie.
import { useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Link2, LockKeyhole, ShieldAlert, Wallet } from "lucide-react";
import { useState } from "react";
import { type Connector, useConnect, useDisconnect, useSignMessage } from "wagmi";
import { Logo } from "../components/logo.js";
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
    <div className="grid min-h-screen lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
      <main className="flex flex-col justify-center px-6 py-12 sm:px-12">
        <div className="mx-auto flex w-full max-w-sm flex-col gap-8">
          <div className="flex items-center gap-2.5">
            <Logo size={32} />
            <span className="flex flex-col leading-tight">
              <span className="text-base font-semibold tracking-tight">AFR</span>
              <span className="text-xs text-muted">Agent Flight Recorder</span>
            </span>
          </div>
          <div className="flex flex-col gap-2">
            <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
            <p className="text-muted">
              Sign a message with your wallet to continue. It's not a transaction and costs no gas.
            </p>
          </div>
          <ul className="flex flex-col gap-2">
            {shown.map((c) => (
              <li key={c.uid}>
                <button
                  type="button"
                  disabled={!!busy}
                  onClick={() => signIn(c)}
                  className="flex min-h-12 w-full items-center gap-3 rounded-xl border border-line-strong bg-raised px-4 text-left font-medium transition-colors hover:border-accent hover:bg-surface disabled:opacity-60"
                >
                  {c.icon?.startsWith("data:image/") ? (
                    <img src={c.icon} alt="" className="size-6 rounded" />
                  ) : (
                    <Wallet aria-hidden className="size-5 text-muted" />
                  )}
                  <span>{LABEL[c.id] ?? c.name}</span>
                  {busy === c.uid ? (
                    <span className="ml-auto text-[13px] font-normal text-muted">
                      Check your wallet…
                    </span>
                  ) : (
                    <ArrowRight aria-hidden className="ml-auto size-4 text-muted" />
                  )}
                </button>
              </li>
            ))}
          </ul>
          {error && (
            <p
              role="alert"
              className="rounded-xl border border-bad-soft bg-bad-soft px-4 py-3 text-bad-soft-fg"
            >
              {error}
            </p>
          )}
          <p className="text-xs text-muted">
            New here? Sign in once, then create an organisation or accept an invitation.
          </p>
        </div>
      </main>

      <aside className="hidden flex-col justify-center gap-10 border-l border-line bg-surface px-12 py-12 lg:flex xl:px-20">
        <div className="flex max-w-lg flex-col gap-3">
          <h2 className="text-3xl font-semibold tracking-tight text-balance">
            A flight recorder for AI agents that move money.
          </h2>
          <p className="text-base text-muted">
            Every action your agents take is recorded, encrypted and provable, and anything that
            skips the record is flagged.
          </p>
        </div>
        <ul className="flex max-w-lg flex-col gap-5">
          {POINTS.map(({ icon: Icon, title, body }) => (
            <li key={title} className="flex gap-4">
              <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-accent-soft text-accent-soft-fg">
                <Icon aria-hidden className="size-[18px]" />
              </span>
              <span className="flex flex-col gap-0.5">
                <span className="font-medium">{title}</span>
                <span className="text-muted">{body}</span>
              </span>
            </li>
          ))}
        </ul>
      </aside>
    </div>
  );
}

const POINTS = [
  {
    icon: Link2,
    title: "Signed and hash-chained",
    body: "Each record is signed by the agent's key and chained to the one before, so gaps and edits show.",
  },
  {
    icon: LockKeyhole,
    title: "Encrypted before it leaves",
    body: "Records are encrypted client-side and stored on Arkiv; only your reader key decrypts them, in your browser.",
  },
  {
    icon: ShieldAlert,
    title: "Unrecorded actions flagged",
    body: "A chain watcher compares the agent's on-chain transactions with its records and alerts on any without one.",
  },
];
