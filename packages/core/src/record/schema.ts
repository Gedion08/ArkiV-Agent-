// Zod schemas for L1 §3 records and §5.4 batch public section [NORMATIVE].
import { stringToBytes } from "viem";
import { z } from "zod";

const U64_MAX = 2n ** 64n - 1n;
const utf8Len = (s: string) => stringToBytes(s).length;

export const HexSchema = z.string().regex(/^0x([0-9a-f]{2})*$/, "lowercase 0x hex");
export const Bytes32Schema = z.string().regex(/^0x[0-9a-f]{64}$/, "bytes32 lowercase hex");
export const Bytes16Schema = z.string().regex(/^0x[0-9a-f]{32}$/, "bytes16 lowercase hex");
export const Bytes4Schema = z.string().regex(/^0x[0-9a-f]{8}$/, "bytes4 lowercase hex");
export const AddressSchema = z.string().regex(/^0x[0-9a-f]{40}$/, "lowercase address");
export const SigSchema = z.string().regex(/^0x[0-9a-f]{128}(1b|1c)$/, "65-byte r‖s‖v signature");
export const U64Schema = z
  .string()
  .regex(/^(0|[1-9][0-9]*)$/, "decimal string without leading zeros")
  // the regex guard runs again: zod still runs refinements after a failed regex, and BigInt(";0") throws
  .refine((s) => /^[0-9]{1,20}$/.test(s) && BigInt(s) <= U64_MAX, "exceeds uint64");
/** JSON integers in hashed objects must be < 2^31 (L1 §3.5). */
export const SmallUintSchema = z
  .number()
  .int()
  .min(0)
  .max(2 ** 31 - 1);

export const ACTION_TYPES = [
  "session_start",
  "session_end",
  "model_call",
  "tool_call",
  "tool_result",
  "tx_sign",
  "tx_broadcast",
  "msg_sign",
  "approval_request",
  "approval",
  "policy_block",
  "gap",
  "note",
] as const;
export const ActionTypeSchema = z.enum(ACTION_TYPES);

export const ModelInfoSchema = z.strictObject({
  provider: z.string().min(1),
  id: z.string().min(1),
  version: z.string().optional(),
  params_hash: Bytes32Schema.optional(),
  tokens_in: U64Schema.optional(),
  tokens_out: U64Schema.optional(),
});

export const ToolInfoSchema = z.strictObject({
  server: z.string().min(1),
  name: z.string().min(1),
  is_error: z.boolean().optional(),
  duration_ms: U64Schema.optional(),
});

export const TxInfoSchema = z.strictObject({
  chain_id: U64Schema,
  from: AddressSchema,
  to: AddressSchema.optional(),
  nonce: U64Schema,
  value: U64Schema,
  data_commit: Bytes32Schema,
  selector: Bytes4Schema.optional(),
  tx_hash: Bytes32Schema.optional(),
  kind: z.enum(["eoa", "userop", "safe"]).optional(),
  user_op_hash: Bytes32Schema.optional(),
  status: z.enum(["sent", "rejected", "error"]).optional(),
  value_usd_cents: U64Schema.optional(),
});

export const PolicyInfoSchema = z.strictObject({
  policy_hash: Bytes32Schema,
  decision: z.enum(["allow", "warn", "require_approval", "deny", "violated"]),
  rule_id: z.string().optional(),
  mode: z.enum(["enforce", "warn_only"]),
});

export const ApprovalInfoSchema = z.strictObject({
  request_seq: U64Schema,
  decision: z.enum(["approved", "rejected", "expired"]),
  method: z.enum(["attested", "eip712"]),
  approver: z.string().min(1),
  sig: SigSchema,
  attestor: AddressSchema.optional(),
});

export const CommitmentsSchema = z.strictObject({
  args: Bytes32Schema.optional(),
  result: Bytes32Schema.optional(),
  context: Bytes32Schema.optional(),
  output: Bytes32Schema.optional(),
  calldata: Bytes32Schema.optional(),
});

export const MetaSchema = z
  .record(
    z.string().refine((k) => utf8Len(k) <= 128, "meta key ≤ 128 B"),
    z.string().refine((v) => utf8Len(v) <= 128, "meta value ≤ 128 B"),
  )
  .refine((m) => Object.keys(m).length <= 16, "meta ≤ 16 keys");

const AgentIdSchema = z
  .string()
  .regex(
    /^(eip155:(0|[1-9][0-9]*):0x[0-9a-f]{40}:(0|[1-9][0-9]*)|local:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/,
    "agent_id",
  );

const HeaderBase = z.strictObject({
  v: z.literal(1),
  agent_id: AgentIdSchema,
  lane: SmallUintSchema,
  seq: U64Schema,
  session_id: Bytes16Schema,
  ts: U64Schema,
  type: ActionTypeSchema,
  prev_hash: Bytes32Schema,
  ref_seq: U64Schema.optional(),
  model: ModelInfoSchema.optional(),
  tool: ToolInfoSchema.optional(),
  tx: TxInfoSchema.optional(),
  policy: PolicyInfoSchema.optional(),
  approval: ApprovalInfoSchema.optional(),
  commit: CommitmentsSchema,
  meta: MetaSchema.optional(),
});

type HeaderShape = z.infer<typeof HeaderBase>;

/** Per-type required fields (L1 §3.1 table). Paths are dotted, e.g. "commit.args", "meta.signer". */
export const REQUIRED_FIELDS: Record<HeaderShape["type"], readonly string[]> = {
  session_start: [
    "meta.recorder_version",
    "meta.config_hash",
    "meta.delegation_hash",
    "meta.session_key",
  ],
  session_end: [],
  model_call: ["model", "commit.context", "commit.output"],
  tool_call: ["tool", "commit.args"],
  tool_result: ["tool", "ref_seq", "commit.result"],
  tx_sign: ["tx", "commit.calldata"],
  tx_broadcast: ["tx.tx_hash", "tx.status", "ref_seq"],
  msg_sign: ["meta.signer", "meta.kind", "commit.args"],
  approval_request: ["ref_seq", "policy"],
  approval: ["approval", "ref_seq"],
  policy_block: ["policy", "ref_seq"],
  gap: ["meta.from_seq", "meta.to_seq", "meta.reason"],
  note: ["commit.args"],
};

function has(obj: unknown, path: string): boolean {
  let cur: unknown = obj;
  for (const p of path.split(".")) {
    if (cur === null || typeof cur !== "object" || !Object.hasOwn(cur, p)) return false;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur !== undefined;
}

export const RecordHeaderV1Schema = HeaderBase.superRefine((h, ctx) => {
  for (const path of REQUIRED_FIELDS[h.type]) {
    if (!has(h, path)) {
      ctx.addIssue({
        code: "custom",
        path: path.split("."),
        message: `required for type ${h.type}`,
      });
    }
  }
  if (
    h.type === "msg_sign" &&
    h.meta?.kind !== undefined &&
    !["personal", "typed"].includes(h.meta.kind)
  ) {
    ctx.addIssue({ code: "custom", path: ["meta", "kind"], message: "personal | typed" });
  }
});

const TruncatedSchema = z.strictObject({
  field: z.string(),
  original_hash: Bytes32Schema,
  original_bytes: z.number().int().min(0),
});
const RedactedSchema = z.strictObject({ field: z.string(), path: z.string(), reason: z.string() });

export const RecordBodyV1Schema = z.strictObject({
  salt: Bytes32Schema,
  args: z.unknown().optional(),
  result: z.unknown().optional(),
  context: z.unknown().optional(),
  output: z.unknown().optional(),
  calldata: HexSchema.optional(),
  truncated: z.array(TruncatedSchema).optional(),
  redacted: z.array(RedactedSchema).optional(),
});

export const BatchPublicV1Schema = z.strictObject({
  v: z.literal(1),
  agent_id: AgentIdSchema,
  lane: SmallUintSchema,
  seq_from: U64Schema,
  seq_to: U64Schema,
  prev_chain_root: Bytes32Schema,
  chain_root: Bytes32Schema,
  batch_root: Bytes32Schema,
  session_keys: z.array(AddressSchema).min(1),
  records: z
    .array(
      z.strictObject({ seq: U64Schema, hash: Bytes32Schema, sig: SigSchema, sk: SmallUintSchema }),
    )
    .min(1),
  tx_commitments: z.array(Bytes32Schema),
  nonce_commitments: z.array(Bytes32Schema),
  flags: z
    .strictObject({
      has_tx: z.boolean(),
      has_block: z.boolean(),
      has_unapproved_tx: z.boolean(),
      has_violation: z.boolean(),
    })
    .optional(),
  epoch_id: SmallUintSchema,
  kek_id: Bytes32Schema,
  wrapped_dek: HexSchema,
  iv: HexSchema,
  payload_ct_hash: Bytes32Schema,
  batch_sig: SigSchema,
});
