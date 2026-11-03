// Generates golden vectors (L1 §11) from fixed keys and salts. Refuses to change a committed file.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import {
  agentKey,
  batchDigest,
  batchProof,
  batchRoot,
  buildBody,
  buildHeader,
  COMMIT_DOMAIN,
  chainRoot,
  commit,
  EIP712_TYPES,
  EVIDENCE_LOCK_ADDRESS,
  hashHeader,
  hashTyped,
  jcs,
  jcsData,
  localSigner,
  parseAgentId,
  typedData,
  verifyBody,
  verifyRecords,
  ZERO_HASH,
} from "@afr/core";
import { keccak256, stringToBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const OUT = new URL("../vectors/", import.meta.url);
const SESSION_PK = `0x${"00".repeat(31)}01`;
const OPERATOR_PK = `0x${"00".repeat(31)}02`;
const session = localSigner(SESSION_PK);
const operator = privateKeyToAccount(OPERATOR_PK);
const salt = (label) => keccak256(stringToBytes(`afr-test-salt:${label}`));
const h32 = (label) => keccak256(stringToBytes(`afr-test:${label}`));
const big = (_, v) => (typeof v === "bigint" ? v.toString() : v);

const AGENT_ID = "eip155:84532:0x00000000000000000000000000000000000a8004:7";
const SESSION_ID = "0x0123456789abcdef0123456789abcdef";
const TS = "1793577600000";
const base = { agent_id: AGENT_ID, lane: 0, session_id: SESSION_ID, ts: TS };

const pending = [];
function emit(name, format, cases) {
  const text = `${JSON.stringify({ format, version: 1, cases }, big, 2)}\n`;
  const url = new URL(name, OUT);
  if (existsSync(url)) {
    if (readFileSync(url, "utf8") !== text) {
      throw new Error(
        `${name}: committed vectors are immutable; a format change needs an ADR and a new file`,
      );
    }
    return;
  }
  pending.push([url, text]); // written only after every case succeeded
}

// jcs.json: raw JSON text in, canonical text out
emit(
  "jcs.json",
  "afr/jcs",
  [
    {
      name: "rfc8785-3.2.2-sample",
      input: {
        mode: "data",
        json: '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}',
      },
    },
    {
      name: "rfc8785-3.2.3-sorting-with-nfc",
      input: {
        mode: "data",
        json: '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}',
      },
    },
    { name: "nfc-key-and-value", input: { mode: "strict", json: '{"cafe\\u0301":"e\\u0301"}' } },
    {
      name: "nested-key-order",
      input: { mode: "strict", json: '{"b":{"z":1,"a":[3,{"y":"",  "x":true}]},"a":0}' },
    },
    { name: "max-small-int", input: { mode: "strict", json: '{"v":2147483647}' } },
  ].map((c) => ({
    ...c,
    expected: (c.input.mode === "strict" ? jcs : jcsData)(JSON.parse(c.input.json)),
  })),
);

// agent_id.json
emit(
  "agent_id.json",
  "afr/agent_id",
  [
    AGENT_ID,
    "eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:0",
    "local:9b2f4e0a-1c3d-4e5f-8a6b-7c8d9e0f1a2b",
  ].map((id) => ({
    name: id.split(":")[0],
    input: id,
    expected: { agent_key: agentKey(id), ...(id.startsWith("eip155") ? parseAgentId(id) : {}) },
  })),
);

// commit.json
const commitCases = [
  ["args-object", COMMIT_DOMAIN.ARGS, { to: "0xabc", amount: "1000000", memo: "café" }],
  ["result-mcp", COMMIT_DOMAIN.RESULT, { content: [{ type: "text", text: "ok" }], isError: false }],
  [
    "context-float",
    COMMIT_DOMAIN.CONTEXT,
    { temperature: 0.7, messages: [{ role: "user", content: "hi" }] },
  ],
  ["output-string", COMMIT_DOMAIN.OUTPUT, "Swapping 10 USDC"],
  [
    "calldata",
    COMMIT_DOMAIN.CALLDATA,
    "0xa9059cbb000000000000000000000000000000000000000000000000000000000000beef",
  ],
  ["null-value", COMMIT_DOMAIN.ARGS, null],
];
emit(
  "commit.json",
  "afr/commit",
  commitCases.map(([name, domain, value]) => ({
    name,
    input: { domain, value_json: JSON.stringify(value), salt: salt(name) },
    expected: commit(domain, value, salt(name)),
  })),
);

// records.json: one signed record per type, chained
const recordInputs = [
  {
    ...base,
    type: "session_start",
    commit: {},
    meta: {
      recorder_version: "0.1.0",
      config_hash: h32("config"),
      delegation_hash: h32("delegation"),
      session_key: session.address,
    },
  },
  {
    ...base,
    type: "tool_call",
    tool: { server: "everything", name: "echo" },
    body: { args: { message: "hi" } },
  },
  {
    ...base,
    type: "tool_result",
    ref_seq: "1",
    tool: { server: "everything", name: "echo", is_error: false, duration_ms: "12" },
    body: { result: { content: [{ type: "text", text: "Echo: hi" }] } },
  },
  {
    ...base,
    type: "model_call",
    model: { provider: "anthropic", id: "claude-opus-5-5", tokens_in: "1200", tokens_out: "85" },
    body: {
      context: { messages: [{ role: "user", content: "swap 10 usdc" }] },
      output: { text: "ok" },
    },
  },
  {
    ...base,
    type: "tx_sign",
    tx: {
      chain_id: "84532",
      from: session.address,
      to: "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
      nonce: "0",
      value: "0",
      data_commit: "0x",
      selector: "0xa9059cbb",
      kind: "eoa",
    },
    body: {
      calldata: "0xa9059cbb000000000000000000000000000000000000000000000000000000000000beef",
    },
  },
  {
    ...base,
    type: "msg_sign",
    meta: {
      signer: session.address,
      kind: "typed",
      primary_type: "Permit",
      verifying_contract: h32("x").slice(0, 42),
    },
    body: { args: { primaryType: "Permit", value: "1000000" } },
  },
  { ...base, type: "gap", commit: {}, meta: { from_seq: "6", to_seq: "6", reason: "crash" } },
  { ...base, type: "note", meta: { event: "heartbeat" }, body: { args: { event: "heartbeat" } } },
  { ...base, type: "session_end", commit: {}, meta: { reason: "shutdown" } },
];

function signedChain(inputs) {
  let prev = ZERO_HASH;
  let seq = 0n;
  return inputs.map((inp, i) => {
    // a gap record sits at to_seq + 1 (L2 §3.2): the reserved seqs are skipped
    if (inp.type === "gap") seq = BigInt(inp.meta.to_seq) + 1n;
    const { body: parts, ...hdr } = inp;
    let body;
    if (parts) {
      const built = buildBody(parts, salt(`record-${i}`));
      body = built.body;
      hdr.commit = built.commit;
      if (hdr.type === "tx_sign") hdr.tx = { ...hdr.tx, data_commit: built.commit.calldata };
    }
    const header = buildHeader(hdr, { seq: seq++, prevHash: prev });
    const hash = hashHeader(header);
    prev = hash;
    return { header, body, hash, sig: session.signDigest(hash) };
  });
}
const chain = signedChain(recordInputs);
emit(
  "records.json",
  "afr/record",
  chain.map((r, i) => ({
    name: `${i}-${r.header.type}`,
    input: { header: r.header, ...(r.body ? { body: r.body } : {}) },
    expected: { record_hash: r.hash, sig: r.sig, signer: session.address },
  })),
);

// chain.json: first 5 records in 2 batches
const ak = agentKey(AGENT_ID);
const batches = [
  [0, 2],
  [3, 4],
];
let prevRoot = ZERO_HASH;
emit(
  "chain.json",
  "afr/chain",
  batches.map(([from, to], b) => {
    const entries = chain
      .slice(from, to + 1)
      .map((r) => ({ seq: BigInt(r.header.seq), hash: r.hash }));
    const root = batchRoot(entries);
    const cr = chainRoot(prevRoot, root, BigInt(to));
    const payloadCtHash = h32(`ciphertext-${b}`);
    const digest = batchDigest({
      agentKey: ak,
      lane: 0,
      seqFrom: BigInt(from),
      seqTo: BigInt(to),
      batchRoot: root,
      prevChainRoot: prevRoot,
      chainRoot: cr,
      payloadCtHash,
    });
    const out = {
      name: `batch-${b}`,
      input: {
        agent_key: ak,
        lane: 0,
        entries,
        prev_chain_root: prevRoot,
        payload_ct_hash: payloadCtHash,
      },
      expected: {
        batch_root: root,
        chain_root: cr,
        batch_digest: digest,
        batch_sig: session.signDigest(digest),
      },
    };
    prevRoot = cr;
    return out;
  }),
);

// merkle.json
const leaves = chain.map((r) => ({ seq: BigInt(r.header.seq), hash: r.hash }));
emit(
  "merkle.json",
  "afr/merkle",
  [1, 2, 3, leaves.length].map((n) => {
    const e = leaves.slice(0, n);
    return {
      name: `${n}-leaves`,
      input: { entries: e },
      expected: { root: batchRoot(e), proofs: e.map((x) => batchProof(e, x.seq)) },
    };
  }),
);

// eip712.json
const AK = ak;
const statements = {
  Delegation: {
    agentKey: AK,
    lane: 0,
    sessionKey: session.address,
    notBefore: 1793577600n,
    notAfter: 1793664000n,
    scope: 1,
    recorder: "afr-recorder/0.1.0",
    nonce: 1n,
  },
  Revocation: {
    agentKey: AK,
    sessionKey: session.address,
    effectiveAt: 1793600000n,
    reason: "rotated",
  },
  AgentProfile: {
    agentKey: AK,
    privacyLevel: 1,
    retentionDays: 365,
    watchedHash: h32("watched"),
    readersHash: h32("readers"),
    version: 1n,
  },
  ReaderKey: {
    owner: operator.address.toLowerCase(),
    x25519: h32("x25519"),
    label: "operator",
    notAfter: 1825113600n,
  },
  KeyGrant: {
    agentKey: AK,
    epochId: 352,
    kekId: h32("kek"),
    reader: h32("x25519"),
    encHash: h32("enc"),
  },
  Approval: {
    agentKey: AK,
    lane: 0,
    requestSeq: 4n,
    requestHash: chain[4].hash,
    decision: 1,
    expiresAt: 1793581200n,
  },
  ApprovalAttestation: {
    agentKey: AK,
    lane: 0,
    requestSeq: 4n,
    requestHash: chain[4].hash,
    decision: 2,
    approver: "slack:T123/U456",
    attestedAt: 1793578000n,
  },
  Attestation: {
    agentKey: AK,
    lane: 0,
    seqTo: 4n,
    chainRoot: prevRoot,
    verdict: 1,
    findingsHash: ZERO_HASH,
    scope: "vector",
  },
  CheckpointStatement: {
    agentKey: AK,
    lane: 0,
    seqTo: 4n,
    chainRoot: prevRoot,
    anchorRoot: h32("anchor"),
    anchorChainId: 84532n,
    anchorTx: h32("tx"),
  },
};
const chainId = 84532;
const eipCases = [];
for (const [type, message] of Object.entries(statements)) {
  if (!(type in EIP712_TYPES)) throw new Error(`unknown type ${type}`);
  eipCases.push({
    name: type,
    input: { chain_id: chainId, primary_type: type, message },
    expected: {
      digest: hashTyped(chainId, type, message),
      sig: await operator.signTypedData(typedData(chainId, type, message)),
      signer: operator.address.toLowerCase(),
    },
  });
}
emit("eip712.json", "afr/eip712", eipCases);

emit("lock_address.json", "afr/lock_address", [
  { name: "evidence-lock", input: "AFR_EVIDENCE_LOCK_V1", expected: EVIDENCE_LOCK_ADDRESS },
]);

// negative/records.json: each case MUST fail with exactly these codes (sorted, de-duplicated)
const signed = chain.slice(0, 5).map(({ header, sig, hash }) => ({ header, sig, hash }));
const clone = () => structuredClone(signed);
const reSign = (r, signer) => ({
  ...r,
  sig: signer(hashHeader(r.header)),
  hash: hashHeader(r.header),
});
const negatives = [
  [
    "tampered-last-record-old-sig",
    (c) => {
      c[4].header.tx.value = "1000000000000000000";
      delete c[4].hash;
      return c;
    },
    ["RECORD_SIG"],
  ],
  [
    "tampered-field-claimed-hash",
    (c) => {
      c[1].header.tool.name = "transfer";
      return c;
    },
    ["CHAIN_BREAK", "HEADER_HASH", "RECORD_SIG"],
  ],
  [
    "swapped-records",
    (c) => {
      [c[1], c[2]] = [c[2], c[1]];
      return c;
    },
    ["CHAIN_BREAK", "SEQ_GAP"],
  ],
  [
    "removed-record",
    (c) => {
      c.splice(2, 1);
      return c;
    },
    ["CHAIN_BREAK", "SEQ_GAP"],
  ],
  [
    "duplicated-record",
    (c) => {
      c.splice(2, 0, c[2]);
      return c;
    },
    ["CHAIN_BREAK", "SEQ_GAP"],
  ],
  [
    "foreign-signer",
    (c) => {
      c[3] = reSign(c[3], (h) => localSigner(OPERATOR_PK).signDigest(h));
      return c;
    },
    ["RECORD_SIG"],
  ],
  [
    "uppercase-hex",
    (c) => {
      c[0].header.session_id = c[0].header.session_id.toUpperCase().replace("0X", "0x");
      return c;
    },
    ["HEADER_INVALID"],
  ],
  [
    "missing-required-field",
    (c) => {
      delete c[1].header.tool;
      return c;
    },
    ["HEADER_INVALID"],
  ],
  [
    "float-in-header",
    (c) => {
      c[1].header.ts = 1793577600000.5;
      return c;
    },
    ["HEADER_INVALID"],
  ],
];
const negCases = [];
for (const [name, mutate, expected] of negatives) {
  const records = mutate(clone());
  const codes = [...new Set((await verifyRecords(records)).map((f) => f.code))].sort();
  if (JSON.stringify(codes) !== JSON.stringify(expected)) {
    throw new Error(`negative ${name}: verifier returned ${codes}, expected ${expected}`);
  }
  negCases.push({ name, input: { records }, expected: { codes: expected } });
}
const { body: goodBody } = chain[1];
const bodyNeg = { ...goodBody, args: { message: "bye" } };
const bodyCodes = verifyBody(chain[1].header, bodyNeg).map((f) => f.code);
if (bodyCodes.join() !== "COMMIT_MISMATCH") throw new Error("body negative failed");
negCases.push({
  name: "body-commit-mismatch",
  input: { header: chain[1].header, body: bodyNeg },
  expected: { codes: ["COMMIT_MISMATCH"] },
});
emit("negative/records.json", "afr/negative-records", negCases);

for (const [url, text] of pending) {
  mkdirSync(new URL(".", url), { recursive: true });
  writeFileSync(url, text);
}
console.log(`test-vectors: wrote ${pending.length} new file(s)`);
