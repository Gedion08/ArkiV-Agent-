// Calldata for the dashboard to hand to the operator's wallet (L5 §4.4). Nothing is signed or sent here.
import { AfrError } from "@afr/core";
import { encodeFunctionData, type Hex } from "viem";
import { IDENTITY_REGISTRY_ABI } from "./abis/identity.js";
import { VALIDATION_REGISTRY_ABI } from "./abis/validation.js";

export function encodeRegister(
  agentURI: string,
  metadata: { metadataKey: string; metadataValue: Hex }[] = [],
): Hex {
  return metadata.length
    ? encodeFunctionData({
        abi: IDENTITY_REGISTRY_ABI,
        functionName: "register",
        args: [agentURI, metadata],
      })
    : encodeFunctionData({
        abi: IDENTITY_REGISTRY_ABI,
        functionName: "register",
        args: [agentURI],
      });
}

export function encodeSetAgentURI(agentId: bigint, uri: string): Hex {
  return encodeFunctionData({
    abi: IDENTITY_REGISTRY_ABI,
    functionName: "setAgentURI",
    args: [agentId, uri],
  });
}

export function encodeValidationResponse(v: {
  requestHash: Hex;
  response: number;
  responseURI: string;
  responseHash: Hex;
  tag: string;
}): Hex {
  if (!Number.isInteger(v.response) || v.response < 0 || v.response > 100)
    throw new AfrError("VALIDATION_RESPONSE_RANGE", "response must be an integer 0..100");
  return encodeFunctionData({
    abi: VALIDATION_REGISTRY_ABI,
    functionName: "validationResponse",
    args: [v.requestHash, v.response, v.responseURI, v.responseHash, v.tag],
  });
}
