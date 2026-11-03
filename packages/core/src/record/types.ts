// Record types (L1 §3), derived from the Zod schemas so they cannot drift.
import type { z } from "zod";
import type {
  ActionTypeSchema,
  ApprovalInfoSchema,
  BatchPublicV1Schema,
  CommitmentsSchema,
  ModelInfoSchema,
  PolicyInfoSchema,
  RecordBodyV1Schema,
  RecordHeaderV1Schema,
  ToolInfoSchema,
  TxInfoSchema,
} from "./schema.js";

export type U64 = string;
export type ActionType = z.infer<typeof ActionTypeSchema>;
export type ModelInfo = z.infer<typeof ModelInfoSchema>;
export type ToolInfo = z.infer<typeof ToolInfoSchema>;
export type TxInfo = z.infer<typeof TxInfoSchema>;
export type PolicyInfo = z.infer<typeof PolicyInfoSchema>;
export type ApprovalInfo = z.infer<typeof ApprovalInfoSchema>;
export type Commitments = z.infer<typeof CommitmentsSchema>;
export type RecordHeaderV1 = z.infer<typeof RecordHeaderV1Schema>;
export type RecordBodyV1 = z.infer<typeof RecordBodyV1Schema>;
export type BatchPublicV1 = z.infer<typeof BatchPublicV1Schema>;
