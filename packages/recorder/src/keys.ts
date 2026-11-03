// Session keys and delegations (L2 §7, L1 §7).
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import {
  AfrError,
  agentKey,
  DELEGATION_SCOPE,
  hashTyped,
  isLocalAgentId,
  localSigner,
  parseAgentId,
  type SyncSigner,
  typedData,
  verifyTyped,
} from "@afr/core";
import { bytesToHex, type Hex, recoverTypedDataAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { Config } from "./config.js";

export interface DelegationMessage {
  agentKey: Hex;
  lane: number;
  sessionKey: Hex;
  notBefore: bigint;
  notAfter: bigint;
  scope: number;
  recorder: string;
  nonce: bigint;
}

export interface SessionKey {
  address: Hex;
  sessionId: Hex;
  signer: SyncSigner;
  delegation: DelegationMessage;
  /** EIP-712 digest of the delegation: known before it is signed, recorded in session_start. */
  delegationHash: Hex;
  /** Resolves with the operator's (or identity key's) signature; may stay pending in interactive mode. */
  delegationSig: Promise<{ sig: Hex; signer: Hex }>;
}

/** Interactive mode: show the typed data to a human, resolve with their signature. */
export type SignatureRequester = (
  typed: ReturnType<typeof typedData>,
  delegationHash: Hex,
) => Promise<Hex>;

export interface KeyManagerOptions {
  agentId: string;
  lane: number;
  delegation: Config["delegation"];
  recorderVersion: string;
  random: (n: number) => Uint8Array;
  now?: () => number;
  /** operator_env: the operator private key (AFR_OPERATOR_KEY). */
  operatorKey?: Hex;
  requestSignature?: SignatureRequester;
}

/** Identity chain of the agent (L1 §7); local agents use Base. */
export function identityChainId(agentId: string): bigint {
  return isLocalAgentId(agentId) ? 8453n : parseAgentId(agentId).chainId;
}

export class KeyManager {
  readonly #o: KeyManagerOptions;
  readonly #chainId: bigint;

  constructor(opts: KeyManagerOptions) {
    if (
      opts.delegation.mode === "operator_env" &&
      !/^0x[0-9a-f]{64}$/i.test(opts.operatorKey ?? "")
    ) {
      throw new AfrError(
        "OPERATOR_KEY_MISSING",
        "delegation.mode=operator_env needs AFR_OPERATOR_KEY (32-byte hex)",
      );
    }
    if (opts.delegation.mode === "interactive" && !opts.requestSignature) {
      throw new AfrError(
        "DELEGATION_UNSUPPORTED",
        "interactive delegation needs a signature requester",
      );
    }
    if (opts.delegation.mode === "kms" || opts.delegation.mode === "identity_key") {
      // shortcut: kms + identity_key modes land with the production key path (P3 identity, P6 KMS)
      throw new AfrError(
        "DELEGATION_UNSUPPORTED",
        `delegation.mode=${opts.delegation.mode} is not implemented yet`,
      );
    }
    this.#o = opts;
    this.#chainId = identityChainId(opts.agentId);
  }

  /** Creates a fresh in-memory session key and requests its delegation. */
  newSession(): SessionKey {
    const { random, delegation: cfg } = this.#o;
    const signer = localSigner(bytesToHex(random(32)));
    const nowS = BigInt(Math.floor((this.#o.now ?? Date.now)() / 1000));
    const delegation: DelegationMessage = {
      agentKey: agentKey(this.#o.agentId),
      lane: this.#o.lane,
      sessionKey: signer.address,
      notBefore: nowS,
      notAfter: nowS + BigInt(cfg.session_ttl_s),
      scope: DELEGATION_SCOPE.RECORDS | DELEGATION_SCOPE.TX_INTENTS | DELEGATION_SCOPE.KEYGRANTS,
      recorder: this.#o.recorderVersion,
      nonce: BigInt(bytesToHex(random(32))),
    };
    const message = delegation as unknown as Record<string, unknown>;
    const delegationHash = hashTyped(this.#chainId, "Delegation", message);
    const typed = typedData(this.#chainId, "Delegation", message);
    let delegationSig: Promise<{ sig: Hex; signer: Hex }>;
    if (cfg.mode === "operator_env") {
      const op = privateKeyToAccount(this.#o.operatorKey as Hex);
      delegationSig = op
        .signTypedData(typed as never)
        .then((sig) => ({ sig, signer: op.address.toLowerCase() as Hex }));
    } else {
      delegationSig = (this.#o.requestSignature as SignatureRequester)(typed, delegationHash).then(
        async (sig) => {
          const signer = (
            await recoverTypedDataAddress({ ...typed, signature: sig } as never)
          ).toLowerCase() as Hex;
          if (!(await verifyTyped(this.#chainId, "Delegation", message, sig, signer))) {
            throw new AfrError("DELEGATION_BAD_SIG", "delegation signature does not verify");
          }
          return { sig, signer };
        },
      );
    }
    delegationSig.catch(() => {}); // surfaced by the caller; avoid unhandled rejections while pending
    return {
      address: signer.address,
      sessionId: bytesToHex(random(16)),
      signer,
      delegation,
      delegationHash,
      delegationSig,
    };
  }
}

/**
 * File-based requester for `interactive` mode: writes `<dir>/delegation-request.json` (EIP-712 typed data)
 * and waits for a signature in `<dir>/delegation.sig`. stdin/stdout can't be used: they carry MCP traffic.
 */
export function fileSignatureRequester(
  dir: string,
  opts: { pollMs?: number; timeoutMs: number },
): SignatureRequester {
  return (typed, delegationHash) =>
    new Promise((resolve, reject) => {
      const req = `${dir}/delegation-request.json`;
      const sigFile = `${dir}/delegation.sig`;
      rmSync(sigFile, { force: true });
      writeFileSync(
        req,
        JSON.stringify(
          { delegationHash, typedData: typed },
          (_, v) => (typeof v === "bigint" ? v.toString() : v),
          2,
        ),
        {
          mode: 0o600,
        },
      );
      const started = Date.now();
      const t = setInterval(() => {
        if (existsSync(sigFile)) {
          clearInterval(t);
          const sig = readFileSync(sigFile, "utf8").trim();
          if (/^0x[0-9a-f]{130}$/i.test(sig)) resolve(sig.toLowerCase() as Hex);
          else
            reject(
              new AfrError("DELEGATION_BAD_SIG", "delegation.sig is not a 65-byte hex signature"),
            );
        } else if (Date.now() - started > opts.timeoutMs) {
          clearInterval(t);
          reject(
            new AfrError(
              "DELEGATION_TIMEOUT",
              "no delegation signature before delegation.timeout_s",
            ),
          );
        }
      }, opts.pollMs ?? 500);
      t.unref();
    });
}
