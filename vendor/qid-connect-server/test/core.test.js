// End-to-end core flow: a wallet-authentic signer produces a real proof for a
// challenge this server issued, and the server verifies it, creates the
// account by address, and issues a working session. Plus the negative set.

import { test, expect } from "bun:test";
import { createQidConnect } from "../src/core.js";
import { IssuedNonceStore } from "../src/stores.js";
import { buildProof } from "../../../tools/signer/btx-sign-ownership.mjs";

const ORIGIN = "https://demo.qid.example";
const secret = "test-secret-test-secret-test-secret-test";

function freshSeed() {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  return seed;
}

function makeQid(overrides = {}) {
  return createQidConnect({ origin: ORIGIN, sessionSecret: secret, ...overrides });
}

test("full sign-in flow: challenge, sign, verify, session", async () => {
  const qid = makeQid();
  const seed = freshSeed();

  const { challenge, request, pollSecret } = await qid.challenge();
  expect(request).toEqual({
    v: 1,
    type: "signin",
    challenge,
    proof_url: `${ORIGIN}/qid/proof`,
  });
  expect(challenge.rp_origin).toBe(ORIGIN);
  expect(challenge.nonce).toMatch(/^[0-9a-f]{64}$/);
  expect(pollSecret).toMatch(/^[0-9a-f]{32}$/);

  const proof = buildProof(seed, challenge);
  const result = await qid.verify(proof);
  expect(result.ok).toBe(true);
  expect(result.address).toBe(proof.address);
  expect(result.account.address).toBe(proof.address);
  expect(typeof result.token).toBe("string");

  const s = await qid.session(result.token);
  expect(s.address).toBe(proof.address);
  expect(s.account.address).toBe(proof.address);
});

test("second sign-in finds the same account, not a new one", async () => {
  const qid = makeQid();
  const seed = freshSeed();

  const a = await qid.challenge();
  const r1 = await qid.verify(buildProof(seed, a.challenge));
  const b = await qid.challenge();
  const r2 = await qid.verify(buildProof(seed, b.challenge));

  expect(r1.ok).toBe(true);
  expect(r2.ok).toBe(true);
  expect(r2.account).toBe(r1.account);
  expect(r2.account.createdAt).toBe(r1.account.createdAt);
});

test("replaying the same proof fails", async () => {
  const qid = makeQid();
  const { challenge } = await qid.challenge();
  const proof = buildProof(freshSeed(), challenge);
  expect((await qid.verify(proof)).ok).toBe(true);
  const replay = await qid.verify(proof);
  expect(replay.ok).toBe(false);
  expect(replay.reason).toBe("nonce_unknown");
});

test("a nonce this server never issued fails before any crypto", async () => {
  const qid = makeQid();
  const foreign = {
    nonce: "ab".repeat(32),
    rp_origin: ORIGIN,
    ts: Date.now(),
  };
  const proof = buildProof(freshSeed(), foreign);
  const r = await qid.verify(proof);
  expect(r.ok).toBe(false);
  expect(r.reason).toBe("nonce_unknown");
});

test("a proof made for another site fails", async () => {
  const qid = makeQid();
  const { challenge } = await qid.challenge();
  const stolen = { ...challenge, rp_origin: "https://evil.example" };
  const proof = buildProof(freshSeed(), stolen);
  const r = await qid.verify(proof);
  expect(r.ok).toBe(false);
  expect(r.reason).toBe("origin_mismatch");
});

test("an expired challenge fails", async () => {
  const qid = makeQid();
  const { challenge } = await qid.challenge();
  const proof = buildProof(freshSeed(), challenge);
  const r = await qid.verify(proof, { now: challenge.ts + 6 * 60 * 1000 });
  expect(r.ok).toBe(false);
  // the nonce store TTL also lapses by then, which is the same protection
  expect(["expired", "nonce_unknown"]).toContain(r.reason);
});

test("a tampered signature fails", async () => {
  const qid = makeQid();
  const { challenge } = await qid.challenge();
  const proof = buildProof(freshSeed(), challenge);
  const flipped = (parseInt(proof.signature.slice(0, 2), 16) ^ 0xff)
    .toString(16)
    .padStart(2, "0");
  proof.signature = flipped + proof.signature.slice(2);
  const r = await qid.verify(proof);
  expect(r.ok).toBe(false);
  expect(r.reason).toBe("bad_signature");
});

test("QR flow: phone submits proof, browser claims session by poll secret", async () => {
  const qid = makeQid();
  const { challenge, pollSecret } = await qid.challenge();

  // browser polls before the phone signed: pending
  expect((await qid.poll(challenge.nonce, pollSecret)).status).toBe("pending");

  // phone signs and submits; it learns success but gets no session
  const proof = buildProof(freshSeed(), challenge);
  const submitted = await qid.submitProof(proof);
  expect(submitted).toEqual({ ok: true, address: proof.address });

  // wrong secret cannot steal the session
  expect((await qid.poll(challenge.nonce, "00".repeat(16))).status).toBe("expired");

  // The issuing browser claims it — but the FIRST claim only reports the address.
  // Nothing binds complete() to this browser (a bystander who read the nonce off the
  // QR can park their own verified address under it), so the human has to accept the
  // address before any session exists. See the confirmation gate in core.js.
  const pending = await qid.poll(challenge.nonce, pollSecret);
  expect(pending.status).toBe("confirm");
  expect(pending.address).toBe(proof.address);
  expect(pending.token).toBeUndefined();

  const done = await qid.poll(challenge.nonce, pollSecret, { confirm: true });
  expect(done.status).toBe("done");
  expect(done.address).toBe(proof.address);
  expect(done.account.address).toBe(proof.address);
  const s = await qid.session(done.token);
  expect(s.address).toBe(proof.address);

  // a done claim is idempotent within the grace window: a 'done' response lost
  // in transit can be re-claimed by the same secret rather than losing the
  // sign-in. (A different secret still never gets 'done'.)
  const reclaim = await qid.poll(challenge.nonce, pollSecret, { confirm: true });
  expect(reclaim.status).toBe("done");
  expect(reclaim.address).toBe(proof.address);
  expect((await qid.poll(challenge.nonce, "00".repeat(16))).status).toBe("expired");
});

test("QR flow: submitted proof still passes full verification", async () => {
  const qid = makeQid();
  const { challenge } = await qid.challenge();
  const stolen = { ...challenge, rp_origin: "https://evil.example" };
  const bad = await qid.submitProof(buildProof(freshSeed(), stolen));
  expect(bad.ok).toBe(false);
  expect(bad.reason).toBe("origin_mismatch");
});

test("rotation rescue: a proof parked just before rotation is still claimable after retire (B1)", async () => {
  const qid = makeQid();
  const a = await qid.challenge();

  // Phone submits its proof: verify consumes nonce A and parks the address.
  const proof = buildProof(freshSeed(), a.challenge);
  expect((await qid.submitProof(proof)).ok).toBe(true);

  // The widget rotates in the same instant, retiring A and minting B — it has
  // not yet polled A for the just-landed completion.
  const b = await qid.challenge(undefined, { retire: a.challenge.nonce, retireSecret: a.pollSecret });
  expect(b.challenge.nonce).not.toBe(a.challenge.nonce);

  // renewSession's last-chance poll of the OLD nonce still returns done, so the
  // browser finishes the sign-in instead of stranding on the fresh QR.
  const rescued = await qid.poll(a.challenge.nonce, a.pollSecret, { confirm: true });
  expect(rescued.status).toBe("done");
  expect(rescued.address).toBe(proof.address);
});

test("config validation", () => {
  expect(() => createQidConnect({ origin: "yourapp.com", sessionSecret: secret })).toThrow();
  expect(() =>
    createQidConnect({ origin: "https://a.example/", sessionSecret: secret })
  ).toThrow();
  expect(() => createQidConnect({ origin: ORIGIN, sessionSecret: "short" })).toThrow();
});

test("accounts adapter receives the verified proof as context", async () => {
  const calls = [];
  const accounts = {
    async getOrCreate(address, now, context) {
      calls.push({ address, context });
      return { address, createdAt: now };
    },
    async get(address) {
      return { address, createdAt: 0 };
    },
  };
  const qid = makeQid({ accounts });
  const seed = freshSeed();

  // Paste flow: verify() passes { proof, recoveryLeafHash }.
  const a = await qid.challenge();
  const proofA = buildProof(seed, a.challenge);
  expect((await qid.verify(proofA)).ok).toBe(true);
  expect(calls.length).toBe(1);
  expect(calls[0].address).toBe(proofA.address);
  // The adapter receives the VERIFIED SNAPSHOT, not the caller's object. verify()
  // deep-clones the proof at the boundary so every read — the frozen verifier's,
  // submitProof's, and the adapter's — sees one immutable set of bytes. Handing an
  // adapter the caller's live object would re-open the TOCTOU class one layer down:
  // an accessor could show honest values to the signature check and hostile ones to
  // whatever the adapter persists. Equal by value, deliberately not the same object.
  expect(calls[0].context.proof).toEqual(proofA);
  expect(calls[0].context.proof).not.toBe(proofA);
  expect(calls[0].context.recoveryLeafHash).toBe(proofA.recovery_leaf_hash.toLowerCase());

  // QR flow: submitProof() verifies with the same context; the later poll()
  // resolves the account without context (the row already exists).
  const b = await qid.challenge();
  const proofB = buildProof(seed, b.challenge);
  expect((await qid.submitProof(proofB)).ok).toBe(true);
  expect(calls.length).toBe(2);
  expect(calls[1].context.recoveryLeafHash).toBe(proofB.recovery_leaf_hash.toLowerCase());

  const polled = await qid.poll(b.challenge.nonce, b.pollSecret, { confirm: true });
  expect(polled.status).toBe("done");
  expect(calls.length).toBe(3);
  expect(calls[2].context).toBeUndefined();
});

test("F2 regression: concurrent replay against an ASYNC nonce store is caught (only one succeeds)", async () => {
  // The consume() bug only bit async stores (Postgres/Redis): the sync verifier
  // treated the returned Promise as always-truthy and never rejected a replay.
  // This wraps the store so has/consume are async with a forced microtask hop,
  // widening the race window, and asserts single-use holds.
  const inner = new IssuedNonceStore({ ttlMs: 10 * 60 * 1000 });
  const asyncStore = {
    issue: (...a) => inner.issue(...a),
    has: async (n, now) => { await Promise.resolve(); return inner.has(n, now); },
    consume: async (n, now) => { await Promise.resolve(); return inner.consume(n, now); },
    complete: (...a) => inner.complete(...a),
    claim: (...a) => inner.claim(...a),
  };
  const qid = createQidConnect({ origin: ORIGIN, sessionSecret: secret, nonceStore: asyncStore });
  const { challenge } = await qid.challenge();
  const proof = buildProof(freshSeed(), challenge);

  const results = await Promise.all(
    Array.from({ length: 8 }, () => qid.verify(proof))
  );
  const ok = results.filter((r) => r.ok);
  const replayed = results.filter((r) => !r.ok && r.reason === "nonce_used");
  expect(ok.length).toBe(1);
  expect(replayed.length).toBe(7);
});

test("rotation retires the superseded nonce so a burned request no longer verifies (v2 Job A)", async () => {
  const qid = makeQid();

  // First request.
  const a = await qid.challenge();
  expect(await qid.nonceStore.has(a.challenge.nonce)).toBe(true);

  // A bystander who only SAW the nonce (no poll secret) cannot burn it.
  const griefed = await qid.challenge(undefined, { retire: a.challenge.nonce, retireSecret: "00".repeat(16) });
  expect(await qid.nonceStore.has(a.challenge.nonce)).toBe(true); // still live
  expect(griefed.challenge.nonce).not.toBe(a.challenge.nonce);

  // The rotating widget mints a fresh request and asks the server to retire the old nonce,
  // proving ownership with that nonce's poll secret.
  const b = await qid.challenge(undefined, { retire: a.challenge.nonce, retireSecret: a.pollSecret });
  expect(b.challenge.nonce).not.toBe(a.challenge.nonce);

  // The retired nonce is gone: a wallet-authentic proof made for it is rejected as unknown,
  // so a screenshotted / stale request cannot be reused after rotation.
  expect(await qid.nonceStore.has(a.challenge.nonce)).toBe(false);
  const stale = await qid.verify(buildProof(freshSeed(), a.challenge));
  expect(stale.ok).toBe(false);
  expect(stale.reason).toBe("nonce_unknown");

  // The fresh nonce still works.
  expect((await qid.verify(buildProof(freshSeed(), b.challenge))).ok).toBe(true);

  // Retiring an unknown nonce is a harmless no-op: it does not throw and does not affect the new one.
  const c = await qid.challenge(undefined, { retire: "deadbeef".repeat(8), retireSecret: "00".repeat(16) });
  expect(await qid.nonceStore.has(c.challenge.nonce)).toBe(true);
});
