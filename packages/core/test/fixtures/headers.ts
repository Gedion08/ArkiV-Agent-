import type { BuildInput } from "../../src/index.js";

export const AGENT_ID = "eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:42";
export const SESSION_ID = `0x${"ab".repeat(16)}` as const;
export const SALT = `0x${"11".repeat(32)}` as const;
export const H32 = (b: string) => `0x${b.repeat(32)}` as `0x${string}`;
export const SESSION_KEY_PK = `0x${"00".repeat(31)}01` as const;
export const OPERATOR_PK = `0x${"00".repeat(31)}02` as const;
export const SESSION_KEY_ADDR = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";

export const base = { agent_id: AGENT_ID, lane: 0, session_id: SESSION_ID, ts: "1793577600000" };

export function toolCall(): BuildInput {
  return {
    ...base,
    type: "tool_call",
    tool: { server: "everything", name: "echo" },
    commit: { args: H32("aa") },
  };
}

export function sessionStart(sessionKey = SESSION_KEY_ADDR): BuildInput {
  return {
    ...base,
    type: "session_start",
    commit: {},
    meta: {
      recorder_version: "0.0.0",
      config_hash: H32("01"),
      delegation_hash: H32("02"),
      session_key: sessionKey,
    },
  };
}
