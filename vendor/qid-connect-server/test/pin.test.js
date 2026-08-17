// The verifier and the test vectors are frozen v1 artifacts. This test fails
// if either file changes by a single byte.

import { test, expect } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

const PINS = {
  "../src/verifier/btx-ownership-verify.js":
    "0eeeec62383b63013283de52338cd6915e2fab638fc8988ad99640166b3a23b0",
  "../test-vectors/vectors.json":
    "a7d8d6bf5322d09f6f3f06d2a876285c9fdfd48ca8ad4377ab47f4a61b70be38",
};

for (const [rel, expected] of Object.entries(PINS)) {
  test(`frozen: ${rel}`, () => {
    const digest = createHash("sha256").update(readFileSync(join(here, rel))).digest("hex");
    expect(digest).toBe(expected);
  });
}
