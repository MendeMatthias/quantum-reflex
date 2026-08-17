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
    confirmAddress = true,
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
  let warnedStaleClient = false;            // one warning per process, not per poll
  const staleClientPolls = new Map();       // nonce -> confirm-stage polls, bounded below

  // Production footgun guard (audit I4, 2026-07-25). The in-memory stores are
  // reference implementations: they are per-process, so on a multi-instance or
  // serverless deployment a nonce issued by instance A is unknown to instance B
  // — replay protection stops being global and accounts vanish on restart. That
  // failure is silent and looks like flaky sign-ins, not like a security bug.
  // Warn loudly in production unless the operator explicitly opted in.
  if (
    typeof process !== "undefined" &&
    process.env?.NODE_ENV === "production" &&
    process.env?.QID_ALLOW_MEMORY_STORES !== "1"
  ) {
    const inMemory = [
      options.nonceStore == null && "nonceStore",
      options.accounts == null && "accounts",
    ].filter(Boolean);
    if (inMemory.length) {
      console.warn(
        `[qid-connect] WARNING: using the in-memory ${inMemory.join(" + ")} in production. ` +
          "These are per-process: with more than one instance, replay protection is not shared " +
          "and sessions/accounts are lost on restart. Pass a shared store (SqliteNonceStore, or " +
          "Redis/SQL implementing the interfaces in stores.js). Set QID_ALLOW_MEMORY_STORES=1 to " +
          "silence this if you are deliberately running a single process."
      );
    }
  }

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
  async function verify(proofInput, { now = Date.now() } = {}) {
    // BOUNDARY SNAPSHOT — everything below reads `proof`, never `proofInput`.
    //
    // The frozen verifier reads the same fields repeatedly (proof.address 5x,
    // proof.challenge.nonce/ts/rp_origin 4-5x each) and it is hash-pinned
    // byte-identical across four repos, so it can never be changed. Worse,
    // submitProof() below re-reads proof.challenge.nonce AFTER verify() already
    // consumed a nonce, so a caller handing us a live accessor object could have
    // the signature verify over one nonce while the verified address is parked
    // under a DIFFERENT one — a cross-device takeover primitive.
    //
    // No shipped route can do this today: both HTTP adapters feed JSON.parse
    // output and parsed JSON cannot carry getters. This clone makes the property
    // structural instead of dependent on "every caller always hands us JSON",
    // and it is the only place the fix can live without touching the frozen file.
    //
    // It must be DEEP: a shallow copy keeps the same proof.challenge reference
    // and leaves the nonce split wide open. Totality is preserved — an input
    // that will not clone (circular, BigInt, a throwing getter) returns a
    // discriminated reason rather than propagating, because every caller of
    // verify() treats a throw as a 500.
    let proof;
    try {
      proof = JSON.parse(JSON.stringify(proofInput ?? null));
    } catch {
      return { ok: false, reason: "bad_proof" };
    }
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

    // CANONICALIZE THE PRIMARY KEY. The verifier returns the caller's address
    // string verbatim, and bech32m is case-insensitive (BIP-173 explicitly
    // permits the all-uppercase form, precisely for QR alphanumeric mode — which
    // is this product's flagship flow). "The address is the account", so an
    // uppercase proof otherwise mints a SECOND account for the same wallet: two
    // rows in both shipped stores, split balances and history, and any
    // address-keyed denylist or one-per-wallet rule silently bypassed by
    // re-signing in the other case. It also hands the user a dead session —
    // signSession writes sub:"BTX1…" while verifySessionToken requires a "btx1"
    // prefix, so /session 401s the cookie /verify just set. That asymmetry is
    // itself the proof the lowercase invariant was always intended.
    //
    // Safe unconditionally: the frozen verifier rejects MIXED case outright, so
    // by here the string is all-lower or all-upper and both decode to the same
    // 32-byte witness program. The precedent is directly below — recovery_leaf_hash
    // is already lowercased; this applies the same discipline to the primary key.
    const address = result.address.toLowerCase();

    // Replay: consume the nonce LAST, only after the signature verified, and
    // atomically. A lost race (a concurrent replay) makes consume return false
    // for all but one caller, so it fails closed. This is the only replay gate
    // that runs; the has() pre-check above is a fast unknown-nonce reject, not
    // the atomic guarantee.
    if (!(await nonceStore.consume(nonce, now))) {
      return { ok: false, reason: "nonce_used" };
    }

    // The verified proof rides along as context so an accounts adapter can
    // persist proof-derived fields. What recovery_leaf_hash is: the leaf hash
    // THIS address commits to (the verifier rebuilt the address from
    // login_pubkey plus this hash, so the signer cannot misreport their own).
    // What it is NOT: proof of control of the recovery key, or a wallet-unique
    // identifier. It is signer-chosen and public on chain (a P2MR spend reveals
    // the sibling hash), so anyone can build an address around a leaf hash they
    // saw. Never look accounts up by it, merge on it, or gate one-per-wallet
    // rules on it — that is an account-takeover path. The address is the
    // account. Adapters that only need the address ignore the third argument
    // (both built-ins do).
    const recoveryLeafHash =
      typeof proof.recovery_leaf_hash === "string"
        ? proof.recovery_leaf_hash.toLowerCase()
        : null;
    const account = await accounts.getOrCreate(address, now, {
      proof,
      recoveryLeafHash,
    });
    const token = signSession({
      address,
      secret: sessionSecret,
      maxAgeMs: sessionMaxAgeMs,
      now,
    });
    // `nonce` is echoed back so submitProof() can park the address under the
    // EXACT nonce whose signature was just verified and consumed, instead of
    // re-reading proof.challenge.nonce a third time (see submitProof below).
    return { ok: true, address, account, token, nonce };
  }

  // Step 2, cross-device variant: a remote signer (phone wallet) submits the
  // proof it made from a scanned QR. Same verification as verify(), but no
  // session is handed to the caller; the verified address is parked under the
  // nonce for the browser that issued the challenge to claim. The signer only
  // learns whether its proof was accepted.
  async function submitProof(proof, { now = Date.now() } = {}) {
    const result = await verify(proof, { now });
    if (!result.ok) return { ok: false, reason: result.reason };
    // Park under result.nonce — the nonce verify() actually verified against and
    // consumed — NOT a fresh read of proof.challenge.nonce. The old third read
    // let a live accessor object park a verified address under a different,
    // still-live nonce that an attacker's browser was polling. verify()'s deep
    // snapshot already blocks that; using the returned value makes the two
    // agree by construction rather than by coincidence.
    await nonceStore.complete(result.nonce, result.address, now);
    return { ok: true, address: result.address };
  }

  // Step 2b: the browser polls with the nonce and its poll secret. When the
  // proof has arrived, it gets the session. A done claim is single use.
  async function poll(nonce, pollSecret, { now = Date.now(), confirm = false } = {}) {
    if (typeof nonce !== "string" || typeof pollSecret !== "string") {
      return { status: "expired" };
    }
    const claimed = await nonceStore.claim(nonce, pollSecret, now);
    if (claimed.status !== "done") return { status: claimed.status };

    // ADDRESS CONFIRMATION GATE — the fix for the QR sign-in takeover.
    //
    // Nothing binds complete() to the browser that asked for the challenge, and
    // nothing can: the QR must carry the whole challenge for a wallet to sign it,
    // so a bystander who reads the nonce off the screen holds exactly what the
    // legitimate signer holds. They submit their own valid proof to /proof (which
    // is deliberately exempt from the login-CSRF origin guard because it really is
    // cross-device), and the victim's browser then polls with its own pollSecret
    // and is handed a session for the ATTACKER's address. Reproduced end to end
    // over real HTTP through the shipped middleware: the victim ends up operating
    // inside the attacker's account, which for a wallet means depositing into it.
    //
    // First-writer-wins in complete() does NOT fix this and was tested before it
    // was written: consume() already makes the nonce single-use, so the attacker
    // IS the first writer and the victim's own wallet is rejected with
    // nonce_unknown. The only sound fix is out-of-band: show the address to the
    // human before minting anything, and let them refuse it.
    //
    // So poll() now reports the address WITHOUT minting a session, and the client
    // must come back with confirm:true once the user has accepted it. Same-device
    // /verify is unaffected — it mints to the origin-guarded caller that just
    // proved possession, so there is no third party to confuse.
    if (confirmAddress && confirm !== true) {
      // Make an un-upgraded client LOUD instead of silent. A widget bundle that predates this
      // release never sends confirm=1, so it polls a completed nonce forever and sign-in simply
      // stops working — no error, no log, nothing in the client console. That is the worst way
      // for a breaking change to land. Count repeat confirm-stage polls on one nonce and warn
      // once: a real user takes a few seconds to read an address, not dozens of polls.
      // Counted per-process, not in the store: this is a diagnostic, and a store adapter is not
      // obliged to round-trip an extra field. Undercounting across instances only delays a warning.
      staleClientPolls.set(nonce, (staleClientPolls.get(nonce) || 0) + 1);
      if (staleClientPolls.size > 512) staleClientPolls.clear();   // bounded: never a leak
      if (staleClientPolls.get(nonce) === 8 && !warnedStaleClient) {
        warnedStaleClient = true;
        console.warn(
          "[qid-connect] A client has polled the same completed nonce 8 times without sending " +
          "confirm=1. That is what a pre-1.7.0 widget does: QR sign-in will never complete for it. " +
          "Update @qid/connect-widget, or handle the `confirm` status in your own poll loop " +
          "(GET /qid/poll?...&confirm=1). See CHANGELOG 1.7.0. Set confirmAddress:false only if you " +
          "have your own address-confirmation UX — it re-opens the QR fixation exposure."
        );
      }
      return { status: "confirm", address: claimed.address };
    }
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
