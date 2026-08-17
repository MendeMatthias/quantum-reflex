// Runs the complete frozen qID Sign-In v1 vector set against the pinned
// verifier copy, exactly as qID-signin-v1/test-vectors/run-vectors.mjs does,
// including the signer equivalence check (the shipped signer must reproduce
// the wallet-authentic address and a proof the verifier accepts).

import { test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  verifyOwnership,
  verifySignIn,
  MemoryNonceStore,
} from "../src/verifier/btx-ownership-verify.js";
import { buildProof } from "../../../tools/signer/btx-sign-ownership.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "../test-vectors/vectors.json"), "utf8"));

for (const c of vectors.cases) {
  test(`verifyOwnership: ${c.name}`, () => {
    expect(verifyOwnership(c.args.address, c.args.challenge, c.args.proof)).toBe(
      c.expect_verifyOwnership
    );
  });

  if (c.signIn) {
    test(`verifySignIn: ${c.name}`, () => {
      const r = verifySignIn(c.args.proof, c.signIn.opts);
      expect({ ok: r.ok, reason: r.reason }).toEqual(c.signIn.expect);
    });
  }

  if (c.signIn_replay) {
    test(`verifySignIn replay: ${c.name}`, () => {
      const store = new MemoryNonceStore();
      const r1 = verifySignIn(c.args.proof, { ...c.signIn_replay.opts, nonceStore: store });
      const r2 = verifySignIn(c.args.proof, { ...c.signIn_replay.opts, nonceStore: store });
      expect({ ok: r1.ok, reason: r1.reason }).toEqual(c.signIn_replay.first);
      expect({ ok: r2.ok, reason: r2.reason }).toEqual(c.signIn_replay.second);
    });
  }
}

test("signer reproduces the wallet-authentic address and a verifiable proof", () => {
  const valid = vectors.cases.find((c) => c.name === "valid");
  const masterHex = vectors.master_seed_A_hex_TESTONLY;
  const seed = Uint8Array.from(masterHex.match(/../g).map((h) => parseInt(h, 16)));
  const proof = buildProof(seed, valid.args.challenge);
  expect(proof.address).toBe(valid.args.address);
  expect(verifyOwnership(proof.address, valid.args.challenge, proof)).toBe(true);
});
