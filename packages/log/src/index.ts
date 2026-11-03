// pino wrapper with redaction + canary-test helper. Services only: packages/core stays pure.
import { randomBytes } from "node:crypto";
import { type DestinationStream, type Logger, pino } from "pino";

export const PACKAGE_NAME = "@afr/log";

/** Fields that may carry plaintext or secrets (CLAUDE.md rule 2). Redacted at any depth pino supports. */
export const REDACT_PATHS = [
  "body",
  "args",
  "result",
  "context",
  "plaintext",
  "privateKey",
  "secret",
  "password",
  "token",
  "authorization",
  "*.body",
  "*.args",
  "*.result",
  "*.context",
  "*.plaintext",
  "*.privateKey",
  "*.secret",
  "*.password",
  "*.token",
  "*.authorization",
  'headers["x-api-key"]',
];

export interface LoggerOptions {
  name: string;
  level?: string;
  destination?: DestinationStream;
}

export type { Logger };

export function createLogger({ name, level = "info", destination }: LoggerOptions): Logger {
  const opts = { name, level, redact: { paths: REDACT_PATHS, censor: "[redacted]" } };
  return destination ? pino(opts, destination) : pino(opts);
}

/** In-memory destination for tests. */
export function memoryDestination(): DestinationStream & { output(): string } {
  const chunks: string[] = [];
  return {
    write: (s: string) => {
      chunks.push(s);
    },
    output: () => chunks.join(""),
  };
}

export interface Canary {
  readonly value: string;
  /** Throws if the canary appears in any of the given outputs (logs, DB dumps, request bodies). */
  assertAbsent(...outputs: string[]): void;
}

/** Plant `value` in plaintext inputs, then assert it never reaches an I/O path. */
export function createCanary(): Canary {
  const value = `afr-canary-${randomBytes(8).toString("hex")}`;
  return {
    value,
    assertAbsent(...outputs) {
      for (const o of outputs) {
        if (o.includes(value)) throw new Error("canary leaked into an output path");
      }
    },
  };
}
