import { parseSiweMessage } from "viem/siwe";
import { describe, expect, test } from "vitest";
import { type Alert, ApiError, csrfFrom } from "../src/lib/api.js";
import { agentLabel, ago, displayStatus, severityCounts, short } from "../src/lib/format.js";
import { parseRoute } from "../src/lib/route.js";
import { siweMessage } from "../src/lib/siwe.js";
import { loginError, sortConnectors } from "../src/pages/login.js";

const ORG = "0b8f5f3e-4a51-4c0e-9d1e-2f1a9c8b7d6e";
const AG = "6c2d7e1a-9b3f-4e8d-a1c5-0f9e8d7c6b5a";

describe("routes", () => {
  test("parses the P4-08 routes and rejects everything else", () => {
    expect(parseRoute("/")).toEqual({ name: "home" });
    expect(parseRoute("/login")).toEqual({ name: "login" });
    expect(parseRoute(`/o/${ORG}/agents`)).toEqual({ name: "agents", org: ORG });
    expect(parseRoute(`/o/${ORG}/agents/`)).toEqual({ name: "agents", org: ORG });
    expect(parseRoute(`/o/${ORG}/agents/${AG}`)).toEqual({ name: "agent", org: ORG, id: AG });
    for (const p of ["/o/x/agents", `/o/${ORG.toUpperCase()}/agents`, `/o/${ORG}`, "/keys"])
      expect(parseRoute(p)).toEqual({ name: "not_found" });
  });
});

describe("csrf cookie", () => {
  test("reads only the CSRF cookie, not the session cookie", () => {
    expect(csrfFrom("a=1; __Host-afr-csrf=abc123; b=2")).toBe("abc123");
    expect(csrfFrom("__Host-afr=session")).toBeUndefined();
    expect(csrfFrom("")).toBeUndefined();
  });
});

test("SIWE message round-trips with the dashboard's host, a 10 min expiry and the nonce", () => {
  const now = new Date("2026-11-05T12:00:00.000Z");
  const m = parseSiweMessage(
    siweMessage({
      address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
      chainId: 84532,
      nonce: "abcdef0123456789",
      host: "dash.example.com",
      origin: "https://dash.example.com",
      now,
    }),
  );
  expect(m).toMatchObject({
    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    chainId: 84532,
    nonce: "abcdef0123456789",
    domain: "dash.example.com",
    uri: "https://dash.example.com",
    version: "1",
  });
  expect(m.expirationTime?.getTime()).toBe(now.getTime() + 600_000);
});

describe("format", () => {
  const alert = (p: Partial<Alert>) =>
    ({ agent_id: AG, severity: "high", type: "X", ...p }) as Alert;

  test("short and ago", () => {
    expect(short(`0x${"ab".repeat(32)}`)).toBe("0xababab…ababab");
    expect(short("0x1234")).toBe("0x1234");
    const now = Date.parse("2026-11-05T12:00:00Z");
    expect(ago(null, now)).toBe("never");
    expect(ago("2026-11-05T11:59:30Z", now)).toBe("30 s ago");
    expect(ago("2026-11-05T11:30:00Z", now)).toBe("30 min ago");
    expect(ago("2026-11-05T09:00:00Z", now)).toBe("3 h ago");
    expect(ago("2026-11-01T12:00:00Z", now)).toBe("4 d ago");
    expect(ago("2026-11-05T12:00:05Z", now)).toBe("0 s ago"); // clock skew
  });

  test("severity counts", () => {
    const xs = [
      alert({ severity: "critical" }),
      alert({ severity: "critical" }),
      alert({ severity: "low" }),
    ];
    expect(severityCounts(xs)).toEqual({ critical: 2, low: 1 });
  });

  test("silent only for an active agent with an open RECORDER_SILENT", () => {
    expect(displayStatus("active", true)).toBe("silent");
    expect(displayStatus("active", false)).toBe("active");
    expect(displayStatus("paused", true)).toBe("paused");
  });

  test("agent ids read as token and chain, not as a hash", () => {
    expect(agentLabel("eip155:84532:0x8004a6090cd10a7288092483047b097295fb8847:10593")).toEqual({
      primary: "#10593",
      secondary: "Base Sepolia · registry 0x8004…8847",
    });
    expect(agentLabel("eip155:999:0x8004a6090cd10a7288092483047b097295fb8847:7").secondary).toMatch(
      /^chain 999 · /,
    );
    expect(agentLabel("local:afc0a2a1-0000-4000-8000-000000084532")).toEqual({
      primary: "local",
      secondary: "afc0a2a1",
    });
  });
});

test("wallet picker: extensions first, then Coinbase, then WalletConnect", () => {
  const c = (id: string, type: string) => ({ id, type });
  expect(
    sortConnectors([
      c("walletConnect", "walletConnect"),
      c("coinbaseWalletSDK", "coinbaseWallet"),
      c("io.rabby", "injected"),
      c("injected", "injected"),
    ]).map((x) => x.id),
  ).toEqual(["io.rabby", "injected", "coinbaseWalletSDK", "walletConnect"]);
});

test("login errors show codes, never raw messages", () => {
  expect(loginError(new ApiError(401, "SIWE_NONCE"))).toBe("Sign-in failed (SIWE_NONCE).");
  expect(loginError({ code: 4001, message: "User rejected" })).toBe(
    "The request was rejected in your wallet.",
  );
  expect(loginError(new Error("https://rpc.example/key-123 failed"))).not.toContain("rpc");
  // wagmi wraps the wallet's rejection
  const wrapped = Object.assign(new Error("Connection failed"), {
    cause: { name: "UserRejectedRequestError", code: 4001 },
  });
  expect(loginError(wrapped)).toBe("The request was rejected in your wallet.");
  expect(loginError({ name: "ProviderNotFoundError" })).toMatch(/^No browser wallet found/);
});
