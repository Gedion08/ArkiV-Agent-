import { TypedDataEncoder } from "ethers";
import { privateKeyToAccount } from "viem/accounts";
import { expect, test } from "vitest";
import {
  EIP712_TYPES,
  eip712Domain,
  hashTyped,
  type StatementType,
  typedData,
  verifyTyped,
} from "../src/index.js";
import { OPERATOR_PK } from "./fixtures/headers.js";
import { STATEMENTS } from "./fixtures/statements.js";

const operator = privateKeyToAccount(OPERATOR_PK);

test.each(Object.keys(STATEMENTS) as StatementType[])(
  "T7 %s digest matches ethers; signature verifies",
  async (t) => {
    const msg = STATEMENTS[t];
    const ethersDigest = TypedDataEncoder.hash(
      { name: "AgentFlightRecorder", version: "1", chainId: 8453 },
      { [t]: EIP712_TYPES[t].map((f) => ({ ...f })) },
      msg,
    );
    expect(hashTyped(8453, t, msg)).toBe(ethersDigest);

    const sig = await operator.signTypedData(typedData(8453, t, msg) as never);
    expect(await verifyTyped(8453, t, msg, sig, operator.address)).toBe(true);
    expect(await verifyTyped(84532, t, msg, sig, operator.address)).toBe(false);
  },
);

test("domain has no verifyingContract", () => {
  expect(eip712Domain(8453)).toEqual({ name: "AgentFlightRecorder", version: "1", chainId: 8453n });
});
