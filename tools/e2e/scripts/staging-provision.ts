// P3-12 A4 setup: what an operator does in the dashboard, against a deployed API. Signs in with SIWE as a
// fresh throwaway wallet (the org owner), creates an org and the agent, and writes a recorder key to
// --key-out (0600, never printed) for `testnet-e2e.ts --api … --agent …` (AFR_API_KEY).
//
//   NODE_EXTRA_CA_CERTS=cert.pem node --import ./tools/ts/register.mjs tools/e2e/scripts/staging-provision.ts \
//     --api https://<alb> --domain <siwe domain> --agent eip155:84532:… --key-out .afr-demo/staging.recorder-key
import { writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createSiweMessage } from "viem/siwe";

const { values: v } = parseArgs({
  options: {
    api: { type: "string" },
    domain: { type: "string" },
    agent: { type: "string" },
    "key-out": { type: "string" },
  },
});
if (!v.api?.startsWith("https://") || !v.domain || !v.agent || !v["key-out"]) {
  process.stdout.write(
    "usage: staging-provision.ts --api https://… --domain HOST --agent ID --key-out FILE\n",
  );
  process.exit(2);
}
const api = v.api.replace(/\/$/, "");
const acct = privateKeyToAccount(generatePrivateKey()); // the throwaway org owner; nothing else uses it
let cookies = "";
let csrf = "";

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${api}${path}`, {
    method,
    headers: {
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
      ...(cookies ? { cookie: cookies } : {}),
      ...(csrf ? { "x-csrf-token": csrf } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const set = res.headers.getSetCookie().map((c) => c.split(";")[0]);
  if (set.length) cookies = set.join("; ");
  const json = (await res.json().catch(() => ({}))) as T & { code?: string };
  // status and error code only: bodies of failed calls aren't echoed
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${json.code ?? ""}`);
  return json;
}

const { nonce } = await call<{ nonce: string }>("GET", "/v1/auth/nonce");
const message = createSiweMessage({
  address: acct.address,
  chainId: 8453,
  domain: v.domain,
  nonce,
  uri: `https://${v.domain}`,
  version: "1",
});
({ csrf } = await call<{ csrf: string }>("POST", "/v1/auth/siwe", {
  message,
  signature: await acct.signMessage({ message }),
}));
const org = await call<{ id: string }>("POST", "/v1/orgs", { name: "afr-staging-demo" });
const { agent } = await call<{ agent: { id: string } }>("POST", `/v1/orgs/${org.id}/agents`, {
  agent_id: v.agent,
  name: "demo agent (staging)",
  retention_days: 30,
});
const key = await call<{ id: string; key: string }>(
  "POST",
  `/v1/agents/${agent.id}/recorder-keys`,
  { lanes: [0] },
);
writeFileSync(v["key-out"], key.key, { mode: 0o600, flag: "wx" });
process.stdout.write(
  `${JSON.stringify({ org: org.id, agent: agent.id, recorder_key_id: key.id, key_file: v["key-out"] })}\n`,
);
