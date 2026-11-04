// Test world for the anchor service: anvil with the real RecorderAnchor, a MemoryStore standing in for
// Arkiv, a MemoryAnchorDb standing in for Postgres, and synthetic batches signed by real session keys.
import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";
import { agentKey, batchDigest } from "@afr/core";
import { encodeFrame, MemoryChain, MemoryStore } from "@afr/store";
import {
  createPublicClient,
  createWalletClient,
  type Hex,
  http,
  keccak256,
  type PublicClient,
  parseAbi,
  stringToHex,
} from "viem";
import { privateKeyToAccount, privateKeyToAddress, signMessage } from "viem/accounts";
import { foundry } from "viem/chains";
import { AnchorChain, type AnchorSigner, MemoryAnchorDb } from "../../src/index.js";
import { RECORDER_ANCHOR_BYTECODE } from "./recorder-anchor.js";

export const ANVIL = [process.env.ANVIL, "anvil", join(homedir(), ".foundry/bin/anvil")].find(
  (b) => b && spawnSync(b, ["--version"]).status === 0,
);
const ADMIN = privateKeyToAccount(
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
); // anvil #2
export const ANCHOR_KEY = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
); // anvil #1
const h32 = (s: string) => keccak256(stringToHex(s));

export async function startAnvil(): Promise<{ url: string; pc: PublicClient; stop: () => void }> {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const url = `http://127.0.0.1:${port}`;
  const proc: ChildProcess = spawn(ANVIL as string, ["--port", String(port), "--silent"], {
    stdio: "ignore",
  });
  const pc = createPublicClient({
    chain: foundry,
    transport: http(url),
    pollingInterval: 50,
  }) as PublicClient;
  for (let i = 0; i < 100 && !(await pc.getChainId().catch(() => 0)); i++)
    await new Promise((r) => setTimeout(r, 100));
  return { url, pc, stop: () => proc.kill() };
}

export async function deployAnchor(url: string, pc: PublicClient): Promise<Hex> {
  const w = createWalletClient({ account: ADMIN, chain: foundry, transport: http(url) });
  const hash = await w.deployContract({
    abi: parseAbi(["constructor(address admin_, address[] recorders)"]),
    bytecode: RECORDER_ANCHOR_BYTECODE,
    args: [ADMIN.address, [ANCHOR_KEY.address]],
  });
  const r = await pc.waitForTransactionReceipt({ hash });
  return r.contractAddress as Hex;
}

export function anchorChain(
  pc: PublicClient,
  contract: Hex,
  signer: AnchorSigner = ANCHOR_KEY as AnchorSigner,
) {
  return new AnchorChain({ publicClient: pc, chain: foundry, contract, signer });
}

const WRITER = `0x${"a1".repeat(20)}` as Hex;
// viem, not core's localSigner: same EIP-191 signature over the digest, without the per-key precompute
const addressOf = (k: Hex) => privateKeyToAddress(k).toLowerCase() as Hex;

/** One Arkiv chain + DB shared across "process restarts" (each restart gets a fresh MemoryStore). */
export class World {
  readonly arkiv = new MemoryChain();
  readonly db = new MemoryAnchorDb();
  store = new MemoryStore(this.arkiv, WRITER);
  restartStore() {
    this.store = new MemoryStore(this.arkiv, WRITER);
    return this.store;
  }

  /** A batch entity ending at seqTo, signed by `sk` (registered as announced unless `announce` is false). */
  async batch(o: {
    agent: number;
    lane: number;
    seqTo: bigint;
    sk?: Hex;
    announce?: boolean;
    signWith?: Hex;
  }) {
    const agentId = `eip155:31337:0x${"00".repeat(19)}01:${o.agent}`;
    const ak = agentKey(agentId);
    const skey = o.sk ?? (`0x${(o.agent * 8 + o.lane + 1).toString(16).padStart(64, "0")}` as Hex);
    const session = { address: addressOf(skey) };
    const seqFrom = o.seqTo - 4n < 0n ? 0n : o.seqTo - 4n;
    const tag = `${o.agent}:${o.lane}:${o.seqTo}`;
    const chainRoot = h32(`chain:${tag}`);
    const pub = {
      v: 1 as const,
      agent_id: agentId,
      lane: o.lane,
      seq_from: seqFrom.toString(),
      seq_to: o.seqTo.toString(),
      prev_chain_root: h32(`prev:${tag}`),
      chain_root: chainRoot,
      batch_root: h32(`root:${tag}`),
      session_keys: [session.address],
      records: [
        {
          seq: o.seqTo.toString(),
          hash: h32(`rec:${tag}`),
          sig: `0x${"11".repeat(64)}1b` as Hex,
          sk: 0,
        },
      ],
      tx_commitments: [],
      nonce_commitments: [],
      epoch_id: 0,
      kek_id: h32("kek"),
      wrapped_dek: "0x00" as Hex,
      iv: `0x${"00".repeat(12)}` as Hex,
      payload_ct_hash: keccak256(new Uint8Array([1, 2, 3])),
      batch_sig: "0x" as Hex,
    };
    const digest = batchDigest({
      agentKey: ak,
      lane: o.lane,
      seqFrom,
      seqTo: o.seqTo,
      batchRoot: pub.batch_root,
      prevChainRoot: pub.prev_chain_root,
      chainRoot,
      payloadCtHash: pub.payload_ct_hash,
    });
    pub.batch_sig = await signMessage({ message: { raw: digest }, privateKey: o.signWith ?? skey });
    const ref = await this.store.await(
      await this.store.put({
        schema: "afr.batch.v1",
        attrs: {
          agent_key: ak,
          lane: BigInt(o.lane),
          seq_from: seqFrom,
          seq_to: o.seqTo,
          chain_root: chainRoot,
          prev_chain_root: pub.prev_chain_root,
          batch_root: pub.batch_root,
          session_key: session.address,
          epoch_id: 0n,
          record_count: 1n,
          privacy: 0n,
        },
        payload: encodeFrame({ pub, ct: new Uint8Array([1, 2, 3]) }),
        expiresAt: { days: 30 },
        readonly: true,
        permissionlessExtension: true,
        lock: true,
        idempotencyKey: h32(`batch:${tag}`),
      }),
    );
    if (o.announce !== false) this.db.addSessionKey(ak, o.lane, session.address);
    const id = this.db.addCheckpoint({
      agentId,
      agentKey: ak,
      lane: o.lane,
      seqTo: o.seqTo,
      chainRoot,
      batchEntity: ref.key,
    });
    return {
      id,
      agentKey: ak,
      agentId,
      seqFrom,
      chainRoot,
      batchRoot: pub.batch_root,
      sessionKey: session.address,
      entity: ref.key,
    };
  }
}
