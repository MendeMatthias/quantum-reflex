// Regression tests for the 2026-08-11 flow-hardening round.
//
// Each test below corresponds to a defect that was reproduced BY EXECUTION before
// it was fixed. They are written to sweep the input SHAPE rather than one flip
// point: a single-point test passed a broken "snapshot" earlier in this series.
import { test, expect } from "bun:test";
import { createQidConnect } from "../src/core.js";
import { IssuedNonceStore, MemoryAccounts } from "../src/stores.js";
import { buildProof } from "../../../tools/signer/btx-sign-ownership.mjs";

const ORIGIN = "https://app.example";
const SECRET = "s".repeat(40);
const makeQid = (opts = {}) => createQidConnect({ origin: ORIGIN, sessionSecret: SECRET, ...opts });
const freshSeed = () => crypto.getRandomValues(new Uint8Array(32));

// ---------------------------------------------------------------------------
// NEW-1: the address is the primary key, so it must be case-canonical.
// bech32m is case-insensitive and BIP-173 explicitly permits the all-uppercase
// form for QR alphanumeric mode — the exact mode this product's flagship flow
// uses. Uppercase used to mint a SECOND account for the same wallet.
// ---------------------------------------------------------------------------
test("NEW-1: an uppercase address canonicalizes and does not fork the account", async () => {
  const accounts = new MemoryAccounts();
  const qid = makeQid({ accounts });
  const seed = freshSeed();

  const a = await qid.challenge();
  const lower = buildProof(seed, a.challenge);
  const r1 = await qid.verify(lower);
  expect(r1.ok).toBe(true);
  expect(r1.address).toBe(lower.address.toLowerCase());

  // Same wallet, same key, address re-cased. The frozen verifier accepts the
  // all-uppercase form (mixed case it rejects outright), so this reaches us.
  const b = await qid.challenge();
  const upper = { ...buildProof(seed, b.challenge), address: lower.address.toUpperCase() };
  const r2 = await qid.verify(upper);

  if (r2.ok) {
    // Canonicalized, and crucially NOT a second account.
    expect(r2.address).toBe(lower.address.toLowerCase());
    expect(await accounts.get(lower.address.toUpperCase())).toBe(null);
    expect((await accounts.get(lower.address.toLowerCase())).address).toBe(lower.address.toLowerCase());
    // The session must survive its own round trip — the old uppercase sub
    // ("BTX1…") failed verifySessionToken's "btx1" prefix check, so /verify set a
    // cookie that /session immediately 401'd.
    const s = await qid.session(r2.token);
    expect(s).not.toBe(null);
    expect(s.address).toBe(lower.address.toLowerCase());
  } else {
    // If the frozen verifier rejects the re-cased address outright, that is also
    // a fine outcome — what must never happen is acceptance under a second key.
    expect(await accounts.get(lower.address.toUpperCase())).toBe(null);
  }
});

// ---------------------------------------------------------------------------
// Boundary snapshot: verify() deep-clones the proof before the frozen verifier
// sees it, so no caller-supplied accessor can split a field between the
// signature check and the policy/persistence decisions.
// ---------------------------------------------------------------------------
test("boundary snapshot: verify() reads a caller's proof field exactly once", async () => {
  const qid = makeQid();
  const seed = freshSeed();
  const { challenge } = await qid.challenge();
  const honest = buildProof(seed, challenge);

  let addressReads = 0;
  let nonceReads = 0;
  const hostile = {
    ...honest,
    get address() { addressReads++; return honest.address; },
    challenge: {
      ...honest.challenge,
      get nonce() { nonceReads++; return honest.challenge.nonce; },
    },
  };

  const r = await qid.verify(hostile);
  expect(r.ok).toBe(true);
  // The clone reads each accessor once and everything downstream reads the copy.
  expect(addressReads).toBe(1);
  expect(nonceReads).toBe(1);
});

test("boundary snapshot: submitProof parks under the verified nonce, not a re-read", async () => {
  const qid = makeQid();
  const seed = freshSeed();
  const live = await qid.challenge();   // the nonce the victim's browser polls
  const other = await qid.challenge();  // a second, still-live nonce
  const honest = buildProof(seed, live.challenge);

  // A proof whose nonce flips AFTER verification: pre-fix there were exactly five
  // reads of proof.challenge.nonce — four inside verify() (the has() pre-check
  // plus the frozen verifier's digest reads) and a fifth in submitProof's
  // complete(). Flipping only the FIFTH was verified against the pre-fix tree to
  // reproduce the redirect exactly: submitProof returned ok, the verified nonce
  // got nothing, and the unrelated nonce the attacker was polling went "done".
  // The threshold is deliberately pinned to that reproduction — a looser flip
  // (reads > 0..3) merely corrupts the digest and fails closed, which would make
  // this test pass for the wrong reason.
  let reads = 0;
  const hostile = {
    ...honest,
    challenge: {
      ...honest.challenge,
      get nonce() {
        reads++;
        return reads > 4 ? other.challenge.nonce : honest.challenge.nonce;
      },
    },
  };

  const sub = await qid.submitProof(hostile);
  expect(sub.ok).toBe(true);

  // The address must land under the nonce that was actually verified...
  // ("confirm" rather than "done": poll now reports the address for the user to accept
  // before any session is minted — see the confirmation gate in core.js.)
  const claimed = await qid.poll(live.challenge.nonce, live.pollSecret);
  expect(claimed.status).toBe("confirm");
  // ...and the unrelated nonce must be untouched.
  const bystander = await qid.poll(other.challenge.nonce, other.pollSecret);
  expect(bystander.status).toBe("pending");
});

test("verify() stays total: unclonable and malformed proofs return a reason, never throw", async () => {
  const qid = makeQid();
  const circular = { challenge: {} };
  circular.self = circular;
  const throwingGetter = { get challenge() { throw new Error("boom"); } };

  for (const bad of [
    null, undefined, 0, "", "not-a-proof", [], true,
    {}, { challenge: null }, { challenge: {} }, { challenge: { nonce: 123 } },
    circular, throwingGetter, { challenge: { nonce: "a" }, sig: () => {} },
    { challenge: { get nonce() { throw new Error("boom"); } } },
  ]) {
    const r = await qid.verify(bad);
    expect(r.ok).toBe(false);
    expect(typeof r.reason).toBe("string");
  }
});

// ---------------------------------------------------------------------------
// NEW-B: _sweep walked the entire live map on every unauthenticated
// POST /challenge. The early exit must delete exactly the same set.
// ---------------------------------------------------------------------------
test("NEW-B: the early-exit sweep evicts exactly what the full walk did", () => {
  const ttlMs = 1000;
  const oNew = new IssuedNonceStore({ ttlMs });
  const oOld = new IssuedNonceStore({ ttlMs });
  // Reference implementation: the pre-fix full walk.
  oOld._sweep = function (now) {
    for (const [k, v] of this._map) if (now - v.at > this.ttlMs) this._map.delete(k);
  };

  const t0 = 1_000_000;
  for (let i = 0; i < 200; i++) {
    oNew.issue("n" + i, "s" + i, t0 + i * 10);
    oOld.issue("n" + i, "s" + i, t0 + i * 10);
  }
  for (const dt of [0, 500, 900, 1000, 1001, 1500, 2000, 5000]) {
    oNew.issue("probe" + dt, "s", t0 + 2000 + dt);
    oOld.issue("probe" + dt, "s", t0 + 2000 + dt);
    expect([...oNew._map.keys()]).toEqual([...oOld._map.keys()]);
  }
});

test("NEW-B: a re-issued nonce keeps insertion order aligned with its timestamp", () => {
  const s = new IssuedNonceStore({ ttlMs: 1000 });
  const t0 = 1_000_000;
  s.issue("a", "s1", t0);
  s.issue("b", "s2", t0 + 10);
  s.issue("a", "s3", t0 + 20); // re-issue: must move to the END, not update in place
  expect([...s._map.keys()]).toEqual(["b", "a"]);
  // and the refreshed entry must outlive the older one
  s.issue("c", "s4", t0 + 1015);
  expect(s.has("b", t0 + 1015)).toBe(false);
  expect(s.has("a", t0 + 1015)).toBe(true);
});

test("NEW-B: an expired entry surviving a non-monotonic sweep is still rejected", () => {
  const s = new IssuedNonceStore({ ttlMs: 1000 });
  const t0 = 1_000_000;
  s.issue("late", "s", t0 + 10_000); // clock jumps forward
  s.issue("early", "s", t0);         // then back: order is now decreasing
  // The early exit may leave "early" in the map, but _live() is the gate.
  expect(s.has("early", t0 + 10_001)).toBe(false);
  expect(s.consume("early", t0 + 10_001)).toBe(false);
  expect(s.claim("early", "s", t0 + 10_001).status).toBe("expired");
});

// ---------------------------------------------------------------------------
// NEW-A: QR sign-in address confirmation. Nothing binds complete() to the
// browser that requested the challenge, and nothing can — the QR must carry the
// whole challenge, so a bystander who sees it holds what the signer holds. The
// only sound defence is showing the address to a human before minting anything.
// ---------------------------------------------------------------------------
test("NEW-A: a bystander's proof cannot silently sign the victim's browser in", async () => {
  const qid = makeQid();
  const victimSeed = freshSeed();
  const attackerSeed = freshSeed();
  const { challenge, pollSecret } = await qid.challenge();

  // The bystander read the nonce off the victim's screen and submits their OWN
  // valid proof. It verifies — it is a genuine proof, just for a different wallet.
  const attackerProof = buildProof(attackerSeed, challenge);
  expect((await qid.submitProof(attackerProof)).ok).toBe(true);
  // The victim's own wallet is now rejected: consume() already burned the nonce.
  // This is why first-writer-wins does NOT fix this — the attacker IS first.
  expect((await qid.submitProof(buildProof(victimSeed, challenge))).ok).toBe(false);

  // The victim's browser polls with its own secret and must NOT get a session.
  const polled = await qid.poll(challenge.nonce, pollSecret);
  expect(polled.status).toBe("confirm");
  expect(polled.address).toBe(attackerProof.address);
  expect(polled.token).toBeUndefined();
  expect(polled.account).toBeUndefined();

  // Declining simply never confirms; no session is ever minted.
  expect((await qid.poll(challenge.nonce, pollSecret)).status).toBe("confirm");

  // And confirming is an explicit, separate act.
  const done = await qid.poll(challenge.nonce, pollSecret, { confirm: true });
  expect(done.status).toBe("done");
  expect(typeof done.token).toBe("string");
});

test("NEW-A: same-device /verify is unaffected — it mints to the origin-guarded caller", async () => {
  // The gate is for the cross-device rendezvous only. /verify hands the session to
  // the caller that just proved possession, so there is no third party to confuse.
  const qid = makeQid();
  const { challenge } = await qid.challenge();
  const r = await qid.verify(buildProof(freshSeed(), challenge));
  expect(r.ok).toBe(true);
  expect(typeof r.token).toBe("string");
});

test("NEW-A: the gate can be opted out of, and says so", async () => {
  // Escape hatch for a deployment that has its own confirmation UX. Off by default
  // would have made the fix decorative, so it is on unless explicitly disabled.
  const qid = makeQid({ confirmAddress: false });
  const { challenge, pollSecret } = await qid.challenge();
  const proof = buildProof(freshSeed(), challenge);
  expect((await qid.submitProof(proof)).ok).toBe(true);
  const done = await qid.poll(challenge.nonce, pollSecret);
  expect(done.status).toBe("done");
  expect(typeof done.token).toBe("string");
});

test("NEW-A: a pre-1.7.0 client that never sends confirm=1 is warned about, not silently broken", async () => {
  // The worst way for a breaking change to land is silently. An un-upgraded widget polls a
  // completed nonce forever with no error anywhere, so the server says so once.
  const qid = makeQid();
  const { challenge, pollSecret } = await qid.challenge();
  expect((await qid.submitProof(buildProof(freshSeed(), challenge))).ok).toBe(true);
  const warnings = [];
  const orig = console.warn;
  console.warn = (...a) => warnings.push(a.join(" "));
  try {
    for (let i = 0; i < 12; i++) {
      const r = await qid.poll(challenge.nonce, pollSecret);   // never confirms
      expect(r.status).toBe("confirm");
    }
  } finally { console.warn = orig; }
  expect(warnings.length).toBe(1);                       // exactly one, not one per poll
  expect(warnings[0]).toContain("confirm=1");
  expect(warnings[0]).toContain("1.7.0");
  // and confirming still works afterwards
  expect((await qid.poll(challenge.nonce, pollSecret, { confirm: true })).status).toBe("done");
});
