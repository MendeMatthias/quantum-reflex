// Why recovery_leaf_hash is not an identity key.
//
// The integration guide used to call it "the right identity key for
// one-per-wallet rules". It is not: the value is signer-chosen, not a key the
// signer proved control of. These tests pin the two facts an integrator has to
// know, so the claim cannot quietly come back.

import { test, expect } from "bun:test";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import {
  verifyOwnership,
  deriveAddress,
  challengeBytes,
} from "../src/verifier/btx-ownership-verify.js";
import { createQidConnect } from "../src/core.js";
import { buildProof } from "../../../tools/signer/btx-sign-ownership.mjs";

const CHALLENGE = {
  nonce: "a".repeat(64),
  rp_origin: "https://demo.qid.example",
  ts: 1753500000,
};

function freshSeed() {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  return seed;
}

function toHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

test("one seed, many login indexes: different addresses, one recovery leaf hash", () => {
  const seed = freshSeed();
  const proofs = [0, 1, 2].map((index) => buildProof(seed, CHALLENGE, { index }));

  for (const p of proofs) expect(verifyOwnership(p.address, CHALLENGE, p)).toBe(true);

  // Rotation/derivation yields a new address every time...
  expect(new Set(proofs.map((p) => p.address)).size).toBe(3);
  // ...while the recovery leaf hash stays put. Stable, and therefore tempting.
  expect(new Set(proofs.map((p) => p.recovery_leaf_hash)).size).toBe(1);
});

test("an unrelated key can pair itself with someone else's recovery leaf hash", () => {
  const victim = buildProof(freshSeed(), CHALLENGE);
  expect(verifyOwnership(victim.address, CHALLENGE, victim)).toBe(true);

  // The leaf hash is public: every P2MR spend reveals it in the control block,
  // and it rides in every proof. An attacker needs nothing else.
  const leaf = Uint8Array.from(victim.recovery_leaf_hash.match(/../g).map((h) => parseInt(h, 16)));
  const attacker = ml_dsa44.keygen(freshSeed());
  const forgedAddress = deriveAddress(attacker.publicKey, leaf);

  const forged = {
    v: 1,
    alg: "ML-DSA-44",
    address: forgedAddress,
    challenge: CHALLENGE,
    login_pubkey: toHex(attacker.publicKey),
    recovery_leaf_hash: victim.recovery_leaf_hash,
    signature: toHex(ml_dsa44.sign(challengeBytes(CHALLENGE), attacker.secretKey)),
  };

  // A different address, so nothing about address-keyed accounts is broken...
  expect(forged.address).not.toBe(victim.address);
  // ...but the proof is entirely valid and carries the victim's leaf hash.
  expect(verifyOwnership(forged.address, CHALLENGE, forged)).toBe(true);
  expect(forged.recovery_leaf_hash).toBe(victim.recovery_leaf_hash);

  // Hence: an RP that looks accounts up by recovery_leaf_hash hands the
  // victim's account to this proof. The address is the account.
});

test("an accounts adapter keyed on recoveryLeafHash loses the account", async () => {
  // The exploit at the level an integrator experiences it: the full public
  // server path, with an adapter written the way the guide used to advise.
  const byLeafHash = new Map();
  const accounts = {
    async getOrCreate(address, now, context) {
      const key = context?.recoveryLeafHash ?? `addr:${address}`;
      let acct = byLeafHash.get(key);
      if (!acct) {
        acct = { id: `user_${byLeafHash.size + 1}`, firstAddress: address };
        byLeafHash.set(key, acct);
      }
      return acct;
    },
    async get() {
      return null;
    },
  };

  const qid = createQidConnect({
    origin: "https://demo.qid.example",
    sessionSecret: "x".repeat(40),
    accounts,
  });

  const c1 = await qid.challenge();
  const victim = buildProof(freshSeed(), c1.challenge);
  const asVictim = await qid.verify(victim);
  expect(asVictim.ok).toBe(true);

  const c2 = await qid.challenge();
  const attacker = ml_dsa44.keygen(freshSeed());
  const leaf = Uint8Array.from(victim.recovery_leaf_hash.match(/../g).map((h) => parseInt(h, 16)));
  const asAttacker = await qid.verify({
    v: 1,
    alg: "ML-DSA-44",
    address: deriveAddress(attacker.publicKey, leaf),
    challenge: c2.challenge,
    login_pubkey: toHex(attacker.publicKey),
    recovery_leaf_hash: victim.recovery_leaf_hash,
    signature: toHex(ml_dsa44.sign(challengeBytes(c2.challenge), attacker.secretKey)),
  });

  // The proof is legitimate: it really does control the address it claims.
  expect(asAttacker.ok).toBe(true);
  expect(asAttacker.address).not.toBe(asVictim.address);
  // And the adapter just handed a stranger the victim's account.
  expect(asAttacker.account.id).toBe(asVictim.account.id);
});
