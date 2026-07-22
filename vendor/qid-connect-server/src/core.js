// core.js
//
// qID Connect server core. Framework agnostic: four async functions that the
// Express middleware and the Next.js handlers both call. All cryptography is
// the frozen qID Sign-In v1 reference verifier, used verbatim (see
// verifier/VERIFIER-PIN.md). This file adds only policy and plumbing:
// nonce issuance, account lookup by address, session tokens.
//
// SPDX-License-Identifier: MIT

import { makeChallenge, verifySignIn } from "./verifier/btx-ownership-verify.js";
import { signSession, verifySessionToken } from "./session.js";
import { IssuedNonceStore, MemoryAccounts } from "./stores.js";

const MINUTE = 60 * 1000;
const DAY = 24 * 60 * MINUTE;

function randomHex(bytes) {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

// createQidConnect(options) -> qid
//
// options:
//   origin           required. Your exact web origin, e.g. "https://yourapp.com".
//                    Lowercase scheme and host, no path, no trailing slash.
//                    Challenges are bound to it; proofs made for any other
//                    origin are rejected.
//   sessionSecret    required. A random string, at least 32 characters. Signs
//                    session tokens. Rotating it signs everyone out.
//   ttlMs            challenge freshness window, default 5 minutes.
//   skewMs           tolerated clock skew, default 60 seconds.
//   sessionMaxAgeMs  session lifetime, default 30 days.
//   nonceStore       optional, defaults to in-memory. See stores.js for the
//                    Redis/SQL interface. Use a shared store when you run
//                    more than one server instance.
//   accounts         optional, defaults to in-memory. getOrCreate(address)
//                    and get(address). The address is the primary key.
//   cookieName       default "qid_session".
//   apiPath          public path where the endpoints are mounted, default
//                    "/qid" ("/api/qid" on Next). Used to build the proof_url
//                    that QR sign-in embeds so a phone wallet knows where to
//                    send the proof.
export function createQidConnect(options = {}) {
  const {
    origin: originOption,
    sessionSecret,
    ttlMs = 5 * MINUTE,
    skewMs = 1 * MINUTE,
    sessionMaxAgeMs = 30 * DAY,
    nonceStore = new IssuedNonceStore({ ttlMs: ttlMs + skewMs }),
    accounts = new MemoryAccounts(),
    cookieName = "qid_session",
    apiPath = "/qid",
  } = options;

  if (typeof originOption !== "string" || !/^https?:\/\/[^\s/]+$/.test(originOption)) {
    throw new Error(
      'createQidConnect: origin must be your exact web origin, for example "https://yourapp.com" (no path, no trailing slash)'
    );
  }
  // Canonicalize: lowercase scheme+host and drop a default port. Browsers always
  // send the Origin header lowercased with :80/:443 stripped, so a config typo
  // like "https://YourApp.com" (which passes the regex above) would otherwise
  // 403 every browser sign-in with bad_origin while QR still worked — the worst
  // kind of asymmetric failure. Canonicalizing here makes the guard match.
  const origin = new URL(originOption).origin;
  if (typeof sessionSecret !== "string" || sessionSecret.length < 32) {
    throw new Error(
      "createQidConnect: sessionSecret must be a random string of at least 32 characters"
    );
  }

  const secureCookies = origin.startsWith("https:");

  // Step 1: issue a challenge. Returns the sign-in request the frontend hands
  // to the wallet. `request` is the transport envelope: the frozen v1
  // challenge plus proof_url, which tells a remote signer (phone wallet
  // scanning a QR) where to send the proof. pollSecret stays in the browser
  // that asked; it is what lets that browser, and only that browser, claim
  // the session once the proof arrives. The wallet's challenge parser drops
  // the extra envelope fields, so the same request works pasted or scanned.
  async function challenge(now = Date.now(), { retire, retireSecret } = {}) {
    // Dynamic connector rotation (v2 Job A): when the widget rotates the request it
    // passes the superseded nonce as `retire` PLUS that nonce's poll secret so we burn
    // it here. This keeps the real acceptance window tied to the client's short display
    // lifetime instead of the full TTL ceiling, closing the screenshot/stale-request
    // replay gap. retire() requires the matching secret, so only the browser that was
    // issued the nonce can burn it — a bystander who merely SEES the QR cannot grief a
    // victim's in-flight sign-in. It only ever tightens: retire() is a no-op on an
    // unknown, expired, already-used, or wrong-secret nonce.
    if (
      typeof retire === "string" && retire.length > 0 && retire.length <= 128 &&
      typeof retireSecret === "string" && retireSecret.length > 0
    ) {
      await nonceStore.retire(retire, retireSecret, now);
    }
    const ch = makeChallenge(origin, { ts: now });
    const pollSecret = randomHex(16);
    await nonceStore.issue(ch.nonce, pollSecret, now);
    return {
      challenge: ch,
      request: { v: 1, type: "signin", challenge: ch, proof_url: `${origin}${apiPath}/proof` },
      pollSecret,
    };
  }

  // Step 2: verify a proof bundle. On success returns the account and a
  // session token. All verdicts come from the frozen verifier; the only
  // pre-check added here is "did we issue this nonce", so unknown-nonce spam
  // is rejected before any post-quantum math runs.
  async function verify(proof, { now = Date.now() } = {}) {
    const nonce = proof?.challenge?.nonce;
    if (typeof nonce !== "string" || !(await nonceStore.has(nonce, now))) {
      return { ok: false, reason: "nonce_unknown" };
    }

    // NOTE: verifySignIn is synchronous. We deliberately do NOT hand it the
    // nonceStore, because our store's consume is ASYNC (returns a Promise, which
    // the sync verifier would treat as always-truthy and never reject a replay).
    // Instead the verifier does every check except replay, and we consume the
    // nonce ourselves in an awaited, atomic step below. This keeps the frozen
    // verifier untouched while making single-use enforcement real.
    const result = verifySignIn(proof, {
      expectedOrigin: origin,
      ttlMs,
      skewMs,
      now,
    });
    if (!result.ok) return { ok: false, reason: result.reason };

    // Replay: consume the nonce LAST, only after the signature verified, and
    // atomically. A lost race (a concurrent replay) makes consume return false
    // for all but one caller, so it fails closed. This is the only replay gate
    // that runs; the has() pre-check above is a fast unknown-nonce reject, not
    // the atomic guarantee.
    if (!(await nonceStore.consume(nonce, now))) {
      return { ok: false, reason: "nonce_used" };
    }

    // The verified proof rides along as context so an accounts adapter can
    // persist proof-derived identity fields. recovery_leaf_hash is safe to
    // trust here: the verifier rebuilt the address from login_pubkey plus
    // recovery_leaf_hash, so a wrong hash cannot have verified. Adapters that
    // only need the address ignore the third argument (both built-ins do).
    const recoveryLeafHash =
      typeof proof.recovery_leaf_hash === "string"
        ? proof.recovery_leaf_hash.toLowerCase()
        : null;
    const account = await accounts.getOrCreate(result.address, now, {
      proof,
      recoveryLeafHash,
    });
    const token = signSession({
      address: result.address,
      secret: sessionSecret,
      maxAgeMs: sessionMaxAgeMs,
      now,
    });
    return { ok: true, address: result.address, account, token };
  }

  // Step 2, cross-device variant: a remote signer (phone wallet) submits the
  // proof it made from a scanned QR. Same verification as verify(), but no
  // session is handed to the caller; the verified address is parked under the
  // nonce for the browser that issued the challenge to claim. The signer only
  // learns whether its proof was accepted.
  async function submitProof(proof, { now = Date.now() } = {}) {
    const result = await verify(proof, { now });
    if (!result.ok) return { ok: false, reason: result.reason };
    await nonceStore.complete(proof.challenge.nonce, result.address, now);
    return { ok: true, address: result.address };
  }

  // Step 2b: the browser polls with the nonce and its poll secret. When the
  // proof has arrived, it gets the session. A done claim is single use.
  async function poll(nonce, pollSecret, { now = Date.now() } = {}) {
    if (typeof nonce !== "string" || typeof pollSecret !== "string") {
      return { status: "expired" };
    }
    const claimed = await nonceStore.claim(nonce, pollSecret, now);
    if (claimed.status !== "done") return { status: claimed.status };
    const account = await accounts.getOrCreate(claimed.address, now);
    const token = signSession({
      address: claimed.address,
      secret: sessionSecret,
      maxAgeMs: sessionMaxAgeMs,
      now,
    });
    return { status: "done", address: claimed.address, account, token };
  }

  // Step 3: resolve a session token back to the account. Returns
  // { address, account, expiresAt } or null.
  async function session(token, { now = Date.now() } = {}) {
    const s = verifySessionToken(token, { secret: sessionSecret, now });
    if (!s) return null;
    const account = await accounts.get(s.address);
    return { address: s.address, account, expiresAt: s.expiresAt };
  }

  return {
    origin,
    apiPath,
    cookieName,
    secureCookies,
    sessionMaxAgeMs,
    challenge,
    verify,
    submitProof,
    poll,
    session,
    accounts,
    nonceStore,
  };
}
