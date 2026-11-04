// ERC-8004 registration file (L5 §4.2) and the AFR service entry. The file is untrusted: shapes are checked,
// unknown fields are kept but never interpreted.
import { AfrError } from "@afr/core";
import type { Hex } from "viem";

export const REGISTRATION_TYPE = "https://eips.ethereum.org/EIPS/eip-8004#registration-v1";
export const AFR_SERVICE_NAME = "afr";
export const AFR_SERVICE_VERSION = "afr/1";

export interface Service {
  name: string;
  endpoint: string;
  version?: string;
  [k: string]: unknown;
}

export interface Registration {
  type: string;
  name?: string;
  description?: string;
  services: Service[];
  registrations?: { agentId: number; agentRegistry: string }[];
  [k: string]: unknown;
}

/** The `afr` service entry of a registration file. */
export interface AfrService {
  name: typeof AFR_SERVICE_NAME;
  endpoint: string;
  version: typeof AFR_SERVICE_VERSION;
  afr: {
    agentKey: Hex;
    arkiv: { chainId: number; schemas: string[]; writers: Hex[] };
    anchor?: { chainId: number; address: Hex; fromBlock: number };
    verifier?: string;
  };
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const invalid = (msg: string) => new AfrError("REGISTRATION_INVALID", msg);
const HEX32 = /^0x[0-9a-f]{64}$/;
const ADDR = /^0x[0-9a-fA-F]{40}$/;
const uint = (v: unknown) => Number.isSafeInteger(v) && (v as number) >= 0;

/** Checks the shape we rely on. `endpoints` (older drafts) is read as `services`. */
export function parseRegistration(raw: unknown): Registration {
  if (!isObj(raw)) throw invalid("registration must be a JSON object");
  if (typeof raw.type !== "string") throw invalid("type missing");
  const services = raw.services ?? raw.endpoints;
  if (!Array.isArray(services)) throw invalid("services missing");
  for (const s of services)
    if (!isObj(s) || typeof s.name !== "string" || typeof s.endpoint !== "string")
      throw invalid("each service needs a string name and endpoint");
  const { endpoints: _old, ...rest } = raw;
  return { ...rest, type: raw.type, services: services as Service[] };
}

/** The `afr` service entry, or undefined when there is none. Throws AFR_SERVICE_INVALID if it's malformed. */
export function findAfrService(reg: Registration): AfrService | undefined {
  const s = reg.services.find((x) => x.name === AFR_SERVICE_NAME);
  if (!s) return undefined;
  const bad = (msg: string) => new AfrError("AFR_SERVICE_INVALID", msg);
  const a = s.afr;
  if (s.version !== AFR_SERVICE_VERSION) throw bad(`version must be ${AFR_SERVICE_VERSION}`);
  if (!isObj(a) || typeof a.agentKey !== "string" || !HEX32.test(a.agentKey))
    throw bad("afr.agentKey must be lowercase 32-byte hex");
  const k = a.arkiv;
  if (
    !isObj(k) ||
    !uint(k.chainId) ||
    !Array.isArray(k.schemas) ||
    !k.schemas.every((x) => typeof x === "string") ||
    !Array.isArray(k.writers) ||
    !k.writers.every((w) => typeof w === "string" && ADDR.test(w))
  )
    throw bad("afr.arkiv needs chainId, schemas[] and writers[]");
  const n = a.anchor;
  if (
    n !== undefined &&
    (!isObj(n) ||
      !uint(n.chainId) ||
      typeof n.address !== "string" ||
      !ADDR.test(n.address) ||
      !uint(n.fromBlock))
  )
    throw bad("afr.anchor needs chainId, address and fromBlock");
  if (a.verifier !== undefined && typeof a.verifier !== "string")
    throw bad("afr.verifier must be a string");
  return s as unknown as AfrService;
}

/** A copy of `existing` with exactly one `afr` service: `afr`. Older `endpoints` files are rewritten as `services`. */
export function buildRegistrationWithAfr(existing: Registration, afr: AfrService): Registration {
  const reg = parseRegistration(existing);
  return {
    ...reg,
    type: REGISTRATION_TYPE,
    services: [...reg.services.filter((s) => s.name !== AFR_SERVICE_NAME), { ...afr }],
  };
}
