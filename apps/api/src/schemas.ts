// Zod schemas shared by the route modules. They validate requests (strict: unknown fields → 400, §8),
// serialize responses, and generate OpenAPI (§1 contract-first).
import { z } from "zod";

export const Hex32 = z.string().regex(/^0x[0-9a-f]{64}$/);
export const Addr = z
  .string()
  .regex(/^0x[0-9a-fA-F]{40}$/)
  .transform((a) => a.toLowerCase());
export const AddrOut = z.string().regex(/^0x[0-9a-f]{40}$/);
export const U64 = z.string().regex(/^\d{1,20}$/);
export const Lane = z.number().int().min(0).max(65_535);
export const Role = z.enum(["owner", "admin", "engineer", "viewer", "auditor"]);

export const Ok = z.strictObject({ ok: z.literal(true) });

export const OrgParam = z.strictObject({ org: z.uuid() });
export const AgentParam = z.strictObject({ id: z.uuid() });
