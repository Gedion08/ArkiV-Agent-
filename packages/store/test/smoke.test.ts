import { expect, test } from "vitest";
import { PACKAGE_NAME } from "../src/index.js";

test("package loads", () => {
  expect(PACKAGE_NAME).toBe("@afr/store");
});
