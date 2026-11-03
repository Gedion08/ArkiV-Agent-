// Batch encryption and DEK wrapping (L4 §3–§4) [NORMATIVE].
import { DOMAIN } from "@afr/core";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import {
  concat,
  encodeAbiParameters,
  type Hex,
  keccak256,
  numberToBytes,
  stringToBytes,
  toBytes,
} from "viem";
import { aesGcmOpen, aesGcmSeal, CryptoError } from "./aes.js";

/** L4 §4 domain string. Not yet in the Arch §21 registry; adding it there needs an ADR (CLAUDE.md rule 1). */
const KEK_ID_DOMAIN = "AFR_KEK_ID_V1";
/** L4 §4 IV budget: the recorder rotates the epoch before a KEK wraps more DEKs than this. */
export const KEK_MAX_WRAPS = 2 ** 20;
const WRAPPED_DEK_BYTES = 12 + 32 + 16;

export interface EpochKek {
  epochId: number;
  kekId: Hex;
  key: Uint8Array;
}

/** Batch position the ciphertext is bound to (from the batch public section). */
export interface BatchCtx {
  agentKey: Hex;
  lane: number;
  seqFrom: bigint;
  seqTo: bigint;
  batchRoot: Hex;
}

export interface SealedBatch {
  ct: Uint8Array;
  iv: Uint8Array;
  wrappedDek: Uint8Array;
  payloadCtHash: Hex;
}

type Random = (n: number) => Uint8Array;

const u32 = (n: number) => numberToBytes(n, { size: 4 });

function agentBytes(agentKey: Hex): Uint8Array {
  const b = toBytes(agentKey);
  if (b.length !== 32) throw new CryptoError("INVALID_KEY", "agent_key must be 32 bytes");
  return b;
}

/** kek_id = keccak256("AFR_KEK_ID_V1" ‖ agent_key ‖ u32be(epoch_id) ‖ HMAC-SHA256(KEK, "AFR_KEK_ID_V1")). */
export function kekIdFor(agentKey: Hex, epochId: number, key: Uint8Array): Hex {
  if (key.length !== 32) throw new CryptoError("INVALID_KEY", "KEK must be 32 bytes");
  const tag = hmac(sha256, key, stringToBytes(KEK_ID_DOMAIN));
  return keccak256(concat([stringToBytes(KEK_ID_DOMAIN), agentBytes(agentKey), u32(epochId), tag]));
}

export function newEpochKek(
  agentKey: Hex,
  epochId: number,
  random: Random = randomBytes,
): EpochKek {
  const key = random(32);
  return { epochId, kekId: kekIdFor(agentKey, epochId, key), key };
}

/** batch_aad = keccak256(abi.encode("AFR_BATCH_AAD_V1", agent_key, lane, seq_from, seq_to, batch_root, epoch_id, kek_id)). */
export function batchAad(ctx: BatchCtx, epochId: number, kekId: Hex): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "string" },
        { type: "bytes32" },
        { type: "uint32" },
        { type: "uint64" },
        { type: "uint64" },
        { type: "bytes32" },
        { type: "uint32" },
        { type: "bytes32" },
      ],
      [
        DOMAIN.BATCH_AAD,
        ctx.agentKey,
        ctx.lane,
        ctx.seqFrom,
        ctx.seqTo,
        ctx.batchRoot,
        epochId,
        kekId,
      ],
    ),
  );
}

/** dek_aad = "AFR_DEK_V1" ‖ agent_key ‖ u32be(epoch_id) ‖ batch_aad. */
function dekAad(agentKey: Hex, epochId: number, aad: Hex): Uint8Array {
  return concat([stringToBytes(DOMAIN.DEK), agentBytes(agentKey), u32(epochId), toBytes(aad)]);
}

/** Encrypts a padded batch plaintext (L3 §4) under a fresh DEK, wrapped by the epoch KEK. */
export function encryptBatch(
  plain: Uint8Array,
  ctx: BatchCtx,
  kek: EpochKek,
  random: Random = randomBytes,
): SealedBatch {
  const aad = batchAad(ctx, kek.epochId, kek.kekId);
  const dek = random(32);
  const iv = random(12);
  const wiv = random(12);
  const ct = aesGcmSeal(dek, iv, plain, toBytes(aad));
  const wrappedDek = concat([
    wiv,
    aesGcmSeal(kek.key, wiv, dek, dekAad(ctx.agentKey, kek.epochId, aad)),
  ]);
  return { ct, iv, wrappedDek, payloadCtHash: keccak256(ct) };
}

/**
 * Decrypts a batch. `sealed.epochId`/`kekId` are the values the frame declares; they must match the KEK.
 * KEK_ID_MISMATCH: wrong KEK. AAD_MISMATCH: the wrapped DEK isn't bound to this batch. DECRYPT_FAILED: payload.
 */
export function decryptBatch(
  sealed: { ct: Uint8Array; iv: Uint8Array; wrappedDek: Uint8Array; epochId: number; kekId: Hex },
  ctx: BatchCtx,
  kek: EpochKek,
): Uint8Array {
  if (
    sealed.epochId !== kek.epochId ||
    sealed.kekId.toLowerCase() !== kek.kekId.toLowerCase() ||
    kekIdFor(ctx.agentKey, kek.epochId, kek.key) !== kek.kekId.toLowerCase()
  ) {
    throw new CryptoError("KEK_ID_MISMATCH", "KEK does not match the batch's epoch/kek_id");
  }
  if (sealed.wrappedDek.length !== WRAPPED_DEK_BYTES || sealed.iv.length !== 12) {
    throw new CryptoError("DECRYPT_FAILED", "malformed iv or wrapped DEK");
  }
  const aad = batchAad(ctx, kek.epochId, kek.kekId);
  let dek: Uint8Array;
  try {
    dek = aesGcmOpen(
      kek.key,
      sealed.wrappedDek.subarray(0, 12),
      sealed.wrappedDek.subarray(12),
      dekAad(ctx.agentKey, kek.epochId, aad),
    );
  } catch {
    throw new CryptoError("AAD_MISMATCH", "wrapped DEK is not bound to this batch");
  }
  return aesGcmOpen(dek, sealed.iv, sealed.ct, toBytes(aad));
}
