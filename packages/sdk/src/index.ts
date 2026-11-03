// @afr/sdk (L2 §6): in-process recording for agents that sign transactions and call models/tools directly.
import { AfrError } from "@afr/core";
import { createLogger, type Logger } from "@afr/log";
import {
  type CaptureEvent,
  type CaptureResult,
  type Config,
  fileSignatureRequester,
  laneDir,
  loadConfig,
  parseConfig,
  Recorder,
  type RecorderOptions,
} from "@afr/recorder";
import {
  type Account,
  type Chain,
  createWalletClient,
  custom,
  type EIP1193RequestFn,
  type Hex,
  hexToBigInt,
  keccak256,
  type Transport,
  type WalletClient,
} from "viem";
import { toAccount } from "viem/accounts";

export const PACKAGE_NAME = "@afr/sdk";

export interface CreateRecorderOptions {
  /** Path to afr.config.yaml, or an inline config object (validated like the file). */
  config: string | Record<string, unknown>;
  env?: NodeJS.ProcessEnv;
  logger?: Logger;
  requestSignature?: RecorderOptions["requestSignature"];
}

/** Minimal structural type of the Anthropic client we wrap (no SDK dependency). */
export interface AnthropicLike {
  messages: {
    create(params: Record<string, unknown>, opts?: unknown): PromiseLike<unknown>;
    stream?(params: Record<string, unknown>, opts?: unknown): { finalMessage(): Promise<unknown> };
  };
}

interface AnthropicMessage {
  model?: string;
  content?: unknown;
  usage?: { input_tokens?: number; output_tokens?: number };
}

type TxInput = NonNullable<CaptureEvent["tx"]>;

/** Body values must be JSON data: bigints become decimal strings (L1 §2); undefined and functions are dropped. */
function plain(v: unknown): unknown {
  if (typeof v === "bigint") return v.toString();
  if (Array.isArray(v)) return v.map(plain);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v))
      if (x !== undefined && typeof x !== "function") out[k] = plain(x);
    return out;
  }
  return v;
}

const errClass = (e: unknown) => (e instanceof Error ? e.constructor.name : "Error");

export class Afr {
  readonly recorder: Recorder;
  readonly #config: Config;
  readonly #log: Logger;

  constructor(recorder: Recorder, config: Config, log: Logger) {
    this.recorder = recorder;
    this.#config = config;
    this.#log = log;
  }

  /** Fail-open (L2 §14): capture problems never break the agent unless fail_mode = closed. */
  #cap(ev: CaptureEvent): CaptureResult | undefined {
    try {
      return this.recorder.capture(ev);
    } catch (e) {
      if (this.#config.fail_mode === "closed") throw e;
      this.#log.error(
        { code: (e as AfrError).code ?? errClass(e), type: ev.type },
        "capture failed",
      );
      return undefined;
    }
  }

  note(text: string, meta?: Record<string, string>): void {
    this.#cap({ type: "note", body: { args: { text } }, ...(meta ? { meta } : {}) });
  }

  /** Records tool_call before and tool_result after `fn`. Errors are recorded and rethrown. */
  wrapTool<A extends unknown[], R>(name: string, fn: (...args: A) => R | Promise<R>) {
    return async (...args: A): Promise<Awaited<R>> => {
      const tool = { server: "sdk", name };
      const call = this.#cap({ type: "tool_call", tool, body: { args: plain(args) } });
      const t0 = performance.now();
      const done = (is_error: boolean, result: unknown) =>
        call &&
        this.#cap({
          type: "tool_result",
          refSeq: call.seq,
          tool: { ...tool, is_error, duration_ms: String(Math.round(performance.now() - t0)) },
          body: { result: plain(result) },
        });
      try {
        const r = await fn(...args);
        done(false, r ?? null);
        return r;
      } catch (e) {
        done(true, { error: errClass(e) });
        throw e;
      }
    };
  }

  /**
   * Records one model_call per response (L2 §6.2). Returns the client unchanged except for
   * messages.create / messages.stream; the original promise/stream objects are returned as-is.
   */
  wrapAnthropic<T extends AnthropicLike>(client: T): T {
    if (this.#config.capture.context !== "full") {
      // shortcut: hash_only / last_turn need recorder support for committed-but-omitted context; add with P2 redaction
      throw new AfrError(
        "CAPTURE_MODE_UNSUPPORTED",
        `capture.context=${this.#config.capture.context} is not supported by wrapAnthropic yet`,
      );
    }
    const record = (params: Record<string, unknown>, res?: AnthropicMessage, err?: unknown) => {
      const { system, messages, tools, ...rest } = params;
      this.#cap({
        type: "model_call",
        model: {
          provider: "anthropic",
          id: String(params.model ?? "unknown"),
          ...(res?.model ? { version: res.model } : {}),
          ...(res?.usage?.input_tokens !== undefined
            ? { tokens_in: String(res.usage.input_tokens) }
            : {}),
          ...(res?.usage?.output_tokens !== undefined
            ? { tokens_out: String(res.usage.output_tokens) }
            : {}),
        },
        body: {
          context: plain({ system, messages, tools, params: rest }),
          output: plain(res?.content ?? null),
        },
        ...(err !== undefined ? { meta: { error: errClass(err) } } : {}),
      });
    };
    const orig = client.messages;
    let warned = false;
    const messages = new Proxy(orig, {
      get: (target, prop, receiver) => {
        const v = Reflect.get(target, prop, receiver);
        if (prop === "create" && typeof v === "function") {
          return (params: Record<string, unknown>, opts?: unknown) => {
            const p = v.call(target, params, opts) as PromiseLike<AnthropicMessage>;
            if (params.stream) {
              // shortcut: create({stream:true}) is not recorded; use messages.stream(), which is. Tee the SSE stream when needed.
              if (!warned)
                this.#log.warn(
                  {},
                  "messages.create({stream:true}) is not recorded; use messages.stream()",
                );
              warned = true;
              return p;
            }
            p.then(
              (res) => record(params, res),
              (e) => record(params, undefined, e),
            );
            return p; // keep the SDK's APIPromise (withResponse, asResponse)
          };
        }
        if (prop === "stream" && typeof v === "function") {
          return (params: Record<string, unknown>, opts?: unknown) => {
            const s = v.call(target, params, opts) as { finalMessage(): Promise<AnthropicMessage> };
            s.finalMessage().then(
              (res) => record(params, res),
              (e) => record(params, undefined, e),
            );
            return s;
          };
        }
        return v;
      },
    });
    return new Proxy(client, {
      get: (target, prop, receiver) =>
        prop === "messages" ? messages : Reflect.get(target, prop, receiver),
    });
  }

  /**
   * Wraps a viem WalletClient (L2 §6.1): local accounts are re-wrapped with toAccount so every signing
   * path records tx_sign / msg_sign; the transport is wrapped to record tx_broadcast and to cover
   * JSON-RPC accounts (eth_sendTransaction, personal_sign, eth_signTypedData_v4).
   */
  wrapWalletClient<C extends WalletClient<Transport, Chain | undefined, Account | undefined>>(
    client: C,
  ): C {
    const signed = new Map<string, { seq: bigint; tx: TxInput }>();
    const inner = client.account;
    const chainId = client.chain?.id;

    const recordSign = (tx: TxInput, args: unknown, calldata: Hex | undefined) => {
      const r = this.#cap({
        type: "tx_sign",
        tx,
        body: { args: plain(args), calldata: calldata ?? "0x" },
      });
      if (r && tx.tx_hash) signed.set(tx.tx_hash, { seq: r.seq, tx });
      return r;
    };
    const recordMsg = (signer: Hex, kind: "personal" | "typed", args: unknown) => {
      // L1 §3.1: typed data carries primary_type / verifying_contract so permits are recognisable
      const td = args as { primaryType?: unknown; domain?: { verifyingContract?: unknown } };
      const meta: Record<string, string> = { signer: signer.toLowerCase(), kind };
      if (kind === "typed" && typeof td.primaryType === "string")
        meta.primary_type = td.primaryType;
      if (kind === "typed" && typeof td.domain?.verifyingContract === "string")
        meta.verifying_contract = td.domain.verifyingContract.toLowerCase();
      return this.#cap({ type: "msg_sign", meta, body: { args: plain(args) } });
    };
    const recordBroadcast = (
      hash: Hex,
      ref: { seq: bigint; tx: TxInput },
      status: "sent" | "error",
    ) =>
      this.#cap({
        type: "tx_broadcast",
        refSeq: ref.seq,
        tx: { ...ref.tx, tx_hash: hash, status },
      });

    const account =
      inner?.type === "local"
        ? toAccount({
            address: inner.address,
            signMessage: async (a) => {
              recordMsg(inner.address, "personal", a.message);
              return inner.signMessage(a);
            },
            signTypedData: async (td) => {
              recordMsg(inner.address, "typed", td);
              return inner.signTypedData(td);
            },
            signTransaction: async (tx, opts) => {
              const raw = await inner.signTransaction(tx, opts);
              // viem passes the account (with signing functions) and chain inside tx; record only tx fields
              const {
                data,
                account: _a,
                chain: _c,
                ...rest
              } = tx as typeof tx & {
                data?: Hex;
                account?: unknown;
                chain?: unknown;
              };
              recordSign(
                {
                  chain_id: BigInt(tx.chainId ?? chainId ?? 0),
                  from: inner.address,
                  ...(tx.to ? { to: tx.to } : {}),
                  nonce: BigInt(tx.nonce ?? 0),
                  value: tx.value ?? 0n,
                  tx_hash: keccak256(raw),
                  ...(tx.to && data && data.length >= 10
                    ? { selector: data.slice(0, 10) as Hex }
                    : {}),
                  kind: "eoa",
                },
                rest,
                data,
              );
              return raw;
            },
          })
        : inner;

    const send = client.request as EIP1193RequestFn;
    const request = (async ({ method, params }: { method: string; params?: unknown }) => {
      const ps = (params ?? []) as unknown[];
      if (method === "eth_sendRawTransaction") {
        const hash = keccak256(ps[0] as Hex);
        const ref = signed.get(hash);
        signed.delete(hash);
        // shortcut: raw txs signed outside this client have no tx_sign to reference and are left to the watcher
        try {
          const res = await send({ method, params } as never);
          if (ref) recordBroadcast(hash, ref, "sent");
          return res;
        } catch (e) {
          if (ref) recordBroadcast(hash, ref, "error");
          throw e;
        }
      }
      if (method === "eth_sendTransaction") {
        // JSON-RPC account: no pre-broadcast hash (L2 §6.1). shortcut: no nonce commitment / outbox intent yet (P2)
        const tx = ps[0] as {
          from: Hex;
          to?: Hex;
          value?: Hex;
          data?: Hex;
          nonce?: Hex;
          chainId?: Hex;
        };
        const nonce =
          tx.nonce ??
          ((await send({
            method: "eth_getTransactionCount",
            params: [tx.from, "pending"],
          } as never)) as Hex);
        const cid = tx.chainId
          ? hexToBigInt(tx.chainId)
          : BigInt(chainId ?? ((await send({ method: "eth_chainId" } as never)) as Hex));
        const { data, ...rest } = tx;
        const info: TxInput = {
          chain_id: cid,
          from: tx.from,
          ...(tx.to ? { to: tx.to } : {}),
          nonce: hexToBigInt(nonce),
          value: tx.value ? hexToBigInt(tx.value) : 0n,
          ...(tx.to && data && data.length >= 10 ? { selector: data.slice(0, 10) as Hex } : {}),
          kind: "eoa",
        };
        const r = recordSign(info, rest, data);
        try {
          const hash = (await send({ method, params } as never)) as Hex;
          if (r) recordBroadcast(hash, { seq: r.seq, tx: info }, "sent");
          return hash;
        } catch (e) {
          if (r)
            this.#cap({
              type: "tx_broadcast",
              refSeq: r.seq,
              tx: { ...info, tx_hash: `0x${"00".repeat(32)}`, status: "error" },
            });
          throw e;
        }
      }
      if (method === "personal_sign") recordMsg(ps[1] as Hex, "personal", ps[0]);
      if (method === "eth_signTypedData_v4")
        recordMsg(ps[0] as Hex, "typed", JSON.parse(String(ps[1])));
      return send({ method, params } as never);
    }) as EIP1193RequestFn;

    return createWalletClient({
      ...(account ? { account } : {}),
      chain: client.chain,
      key: client.key,
      name: client.name,
      pollingInterval: client.pollingInterval,
      transport: custom({ request }),
    }) as unknown as C;
  }

  close(reason = "shutdown"): Promise<void> {
    return this.recorder.close(reason);
  }
}

export async function createRecorder(o: CreateRecorderOptions): Promise<Afr> {
  const env = o.env ?? process.env;
  const config =
    typeof o.config === "string" ? loadConfig(o.config, env) : parseConfig(o.config, env);
  const log =
    o.logger ??
    createLogger({
      name: "afr-sdk",
      level: env.AFR_LOG_LEVEL ?? "info",
      destination: process.stderr,
    });
  const requestSignature =
    o.requestSignature ??
    (config.delegation.mode === "interactive"
      ? fileSignatureRequester(laneDir(config), { timeoutMs: config.delegation.timeout_s * 1000 })
      : undefined);
  const recorder = await Recorder.start({
    config,
    env,
    logger: log,
    ...(requestSignature ? { requestSignature } : {}),
  });
  return new Afr(recorder, config, log);
}
