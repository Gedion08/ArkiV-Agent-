// Shared HTTP types and helpers for apps/api (server bootstrap + route modules).
import { createHash } from "node:crypto";
import type { Logger } from "@afr/log";
import type { FastifyReply, FastifyRequest } from "fastify";
import type { Pool } from "pg";

/** Envelope for secrets at rest (watch keys, pre-signed revocations). */
export interface KeyWrapper {
  wrap(plain: Uint8Array, aad: Uint8Array): Uint8Array;
  unwrap(wrapped: Uint8Array, aad: Uint8Array): Uint8Array;
}

export interface ApiOptions {
  pool: Pool;
  /** SIWE (EIP-4361): the dashboard host the messages must name. */
  siweDomain: string;
  keys: KeyWrapper;
  /** ms clock (tests). */
  now?: () => number;
  /** 5xx are logged by code and route only (never request content). */
  logger?: Logger;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message = code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export interface SessionUser {
  id: string;
  wallet: string;
}

declare module "fastify" {
  interface FastifyRequest {
    rawBody?: Buffer;
    user?: SessionUser;
  }
}

export const SESSION_COOKIE = "__Host-afr";
export const CSRF_COOKIE = "__Host-afr-csrf";
export const SESSION_TTL_MS = 12 * 3600_000;
export const sha256 = (s: string | Buffer) => createHash("sha256").update(s).digest();
export const hexBuf = (h: string) => Buffer.from(h.slice(2), "hex");
export const bufHex = (b: Buffer) => `0x${b.toString("hex")}`;

export type RequireUser = (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
