// L8 §4.1 SIWE auth (EIP-4361) → session cookie + CSRF token. EOA signatures verify locally; smart-account
// wallets (ERC-1271, counterfactual ERC-6492) verify through `siweClient` on its chain.
import { randomBytes } from "node:crypto";
import { type Hex, verifyMessage } from "viem";
import { verifyMessage as verifyOnChain } from "viem/actions";
import { generateSiweNonce, parseSiweMessage, validateSiweMessage } from "viem/siwe";
import { z } from "zod";
import {
  ApiError,
  type ApiOptions,
  bufHex,
  CSRF_COOKIE,
  hexBuf,
  LIMITS,
  type RequireUser,
  SESSION_COOKIE,
  SESSION_TTL_MS,
  sha256,
  type ZodPlugin,
} from "../http.js";
import { AddrOut, Ok, Role } from "../schemas.js";

const NONCE_TTL_MS = 10 * 60_000;

const Siwe = z.strictObject({
  message: z.string().max(4096),
  // 65 bytes for an EOA; ERC-1271 / ERC-6492 signatures are longer (wrapped factory calldata)
  signature: z
    .string()
    .max(2 + 2 * 8192)
    .regex(/^0x(?:[0-9a-fA-F]{2})+$/),
});
const User = z.strictObject({ id: z.uuid(), wallet: AddrOut });

export const authRoutes: ZodPlugin<
  ApiOptions & { now: () => number; requireUser: RequireUser }
> = async (app, o) => {
  const { pool, now } = o;
  const ts = (ms: number) => new Date(ms);
  const auth = { preHandler: o.requireUser };

  const signedBy = async (address: Hex, message: string, signature: Hex, chainId: number) => {
    try {
      if (await verifyMessage({ address, message, signature })) return true;
    } catch {} // not a 65-byte ECDSA signature: maybe a contract wallet's
    const client = o.siweClient;
    if (!client || client.chain?.id !== chainId) return false;
    try {
      return await verifyOnChain(client, { address, message, signature });
    } catch {
      throw new ApiError(503, "SIWE_UNAVAILABLE"); // RPC down: don't report a bad signature
    }
  };

  app.get(
    "/v1/auth/nonce",
    {
      config: { rateLimit: LIMITS.nonce },
      schema: { response: { 200: z.strictObject({ nonce: z.string() }) } },
    },
    async () => {
      const nonce = generateSiweNonce();
      await pool.query("INSERT INTO siwe_nonces (nonce, expires_at) VALUES ($1, $2)", [
        nonce,
        ts(now() + NONCE_TTL_MS),
      ]);
      return { nonce };
    },
  );

  app.post(
    "/v1/auth/siwe",
    {
      config: { rateLimit: LIMITS.nonce },
      schema: { body: Siwe, response: { 200: z.strictObject({ user: User, csrf: z.string() }) } },
    },
    async (req, reply) => {
      const b = req.body;
      const msg = parseSiweMessage(b.message);
      if (!msg.address || !msg.nonce || !msg.chainId) throw new ApiError(401, "SIWE_INVALID");
      // nonces are single-use: consumed before verifying, so a failed attempt can't reuse one
      const used = await pool.query(
        "DELETE FROM siwe_nonces WHERE nonce = $1 AND expires_at > $2 RETURNING nonce",
        [msg.nonce, ts(now())],
      );
      if (!used.rowCount) throw new ApiError(401, "SIWE_NONCE");
      if (!validateSiweMessage({ message: msg, domain: o.siweDomain, time: ts(now()) }))
        throw new ApiError(401, "SIWE_INVALID");
      if (!(await signedBy(msg.address, b.message, b.signature as Hex, msg.chainId)))
        throw new ApiError(401, "SIWE_SIGNATURE");
      const wallet = hexBuf(msg.address.toLowerCase());
      const { rows } = await pool.query<{ id: string }>(
        "INSERT INTO users (wallet) VALUES ($1) ON CONFLICT (wallet) DO UPDATE SET wallet = excluded.wallet RETURNING id",
        [wallet],
      );
      const userId = rows[0]?.id as string;
      const token = randomBytes(32).toString("hex");
      const csrf = randomBytes(32).toString("hex");
      await pool.query(
        "INSERT INTO sessions (token_hash, user_id, csrf_hash, expires_at) VALUES ($1, $2, $3, $4)",
        [sha256(token), userId, sha256(csrf), ts(now() + SESSION_TTL_MS)],
      );
      const base = {
        path: "/",
        secure: true,
        sameSite: "strict" as const,
        maxAge: SESSION_TTL_MS / 1000,
      };
      reply.setCookie(SESSION_COOKIE, token, { ...base, httpOnly: true });
      reply.setCookie(CSRF_COOKIE, csrf, base); // readable by the dashboard, echoed as X-CSRF-Token
      return { user: { id: userId, wallet: bufHex(wallet) }, csrf };
    },
  );

  app.post(
    "/v1/auth/logout",
    { ...auth, schema: { response: { 200: Ok } } },
    async (req, reply) => {
      await pool.query("DELETE FROM sessions WHERE token_hash = $1", [
        sha256(req.cookies[SESSION_COOKIE] as string),
      ]);
      reply.clearCookie(SESSION_COOKIE, { path: "/" }).clearCookie(CSRF_COOKIE, { path: "/" });
      return { ok: true as const };
    },
  );

  app.get(
    "/v1/me",
    {
      ...auth,
      schema: {
        response: {
          200: z.strictObject({
            user: User,
            memberships: z.array(z.strictObject({ org_id: z.uuid(), role: Role })),
          }),
        },
      },
    },
    async (req) => {
      const u = req.user as NonNullable<typeof req.user>;
      const { rows } = await pool.query(
        "SELECT org_id, role FROM memberships WHERE user_id = $1 ORDER BY org_id",
        [u.id],
      );
      return { user: u, memberships: rows };
    },
  );
};
