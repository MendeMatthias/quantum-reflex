// btx-ownership-verify.js
//
// BTX Wallet Ownership Proof v1  (Sign-In With BTX)
// Standalone reference verifier for a DApp. No wallet UI, no wallet secrets.
//
// A user proves they control a BTX PQ wallet address by signing a one-time
// challenge with their ML-DSA login key. This module rebuilds the address from
// the proof, matches it, and verifies the signature.
//
// Dependencies (the same audited upstreams the BTX wallet core is built from):
//   @noble/post-quantum  ML-DSA-44 verify   (FIPS 204)
//   @noble/hashes        SHA-256
//   @scure/base          bech32m
//
//   npm i @noble/post-quantum @noble/hashes @scure/base
//
// Do not hand-roll the post-quantum verify. This module uses the standard
// library so the crypto stays audited and interoperable with the wallet.
//
// SPDX-License-Identifier: MIT

import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bech32m } from "@scure/base";

// ----------------------------------------------------------------------------
// Protocol constants. These MUST match the BTX wallet core (qid) exactly.
// ----------------------------------------------------------------------------

export const CONSTANTS = Object.freeze({
  VERSION: 1,
  ALG: "ML-DSA-44",
  LOGIN_TAG: "BTX-qID/login-v1", // domain-separation tag for the signed digest
  LEAF_TAG: "P2MRLeaf",
  BRANCH_TAG: "P2MRBranch",
  HRP: "btx",
  WITNESS_VERSION: 2,
  LEAF_VERSION: 194, // 0xc2
  OP_CHECKSIG_MLDSA: 187, // 0xbb  (login leaf opcode)
  MLDSA44_PUBKEY_LEN: 1312,
  MLDSA44_SIG_LEN: 2420,
  HASH_LEN: 32,
});

// Recommended policy defaults for verifySignIn(). RPs may override.
export const POLICY_DEFAULTS = Object.freeze({
  ttlMs: 5 * 60 * 1000, // challenge is valid for 5 minutes after it was issued
  skewMs: 60 * 1000, // tolerate 60s of clock skew on the "issued in the future" check
});

// ----------------------------------------------------------------------------
// Small byte helpers (no dependency needed)
// ----------------------------------------------------------------------------

const enc = new TextEncoder();
const utf8 = (s) => enc.encode(s);

function concat(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0) return null;
  if (!/^[0-9a-fA-F]*$/.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
  return s;
}

// constant-time-ish equality for two byte arrays
function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function cmpBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

// ----------------------------------------------------------------------------
// BIP-340 style tagged hash: SHA256( SHA256(tag) || SHA256(tag) || msg )
// ----------------------------------------------------------------------------

function taggedHash(tag, msg) {
  const t = sha256(utf8(tag));
  return sha256(concat(t, t, msg));
}

// ----------------------------------------------------------------------------
// Canonical challenge preimage. Byte-for-byte identical to the wallet's
// challengeBytes(): the signed message is the tagged hash of the compact JSON
// {"n":<nonce>,"o":<rp_origin>,"t":<ts>} with keys in exactly this order and no
// insignificant whitespace.
// ----------------------------------------------------------------------------

export function canonicalChallengeJSON(challenge) {
  // Build the object in fixed key order n, o, t. JSON.stringify then emits the
  // exact canonical string with no whitespace.
  return JSON.stringify({ n: challenge.nonce, o: challenge.rp_origin, t: challenge.ts });
}

export function challengeBytes(challenge) {
  return taggedHash(CONSTANTS.LOGIN_TAG, utf8(canonicalChallengeJSON(challenge)));
}

// ----------------------------------------------------------------------------
// Address derivation. Rebuild the P2MR (pay-to-Merkle-root) address from the
// login pubkey plus the recovery leaf hash (the Merkle sibling), then bech32m.
//
//   loginLeaf  = pushData(login_pubkey) || OP_CHECKSIG_MLDSA
//   h0         = taggedHash("P2MRLeaf", leafVersion || compactSize(script) || script)
//   root       = taggedHash("P2MRBranch", sort(h0, recovery_leaf_hash))
//   address    = bech32m("btx", witnessVersion=2, root)
// ----------------------------------------------------------------------------

function compactSize(n) {
  if (n < 253) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(253, n & 0xff, (n >> 8) & 0xff);
  throw new Error("compactSize too large");
}

function pushData(data) {
  const n = data.length;
  if (n < 76) return concat(Uint8Array.of(n), data);
  if (n <= 255) return concat(Uint8Array.of(76, n), data);
  if (n <= 0xffff) return concat(Uint8Array.of(77, n & 0xff, (n >> 8) & 0xff), data);
  throw new Error("pushData too large");
}

function leafHash(script) {
  return taggedHash(
    CONSTANTS.LEAF_TAG,
    concat(Uint8Array.of(CONSTANTS.LEAF_VERSION), compactSize(script.length), script)
  );
}

function branchHash(a, b) {
  const [lo, hi] = cmpBytes(a, b) <= 0 ? [a, b] : [b, a];
  return taggedHash(CONSTANTS.BRANCH_TAG, concat(lo, hi));
}

// Rebuild the 32-byte Merkle root from a login pubkey and the recovery sibling.
export function rebuildRoot(loginPubkey, recoveryLeafHash) {
  const loginLeaf = concat(pushData(loginPubkey), Uint8Array.of(CONSTANTS.OP_CHECKSIG_MLDSA));
  const h0 = leafHash(loginLeaf);
  return branchHash(h0, recoveryLeafHash);
}

// Derive the canonical btx address string from a login pubkey and recovery sibling.
export function deriveAddress(loginPubkey, recoveryLeafHash) {
  const root = rebuildRoot(loginPubkey, recoveryLeafHash);
  return bech32m.encode(CONSTANTS.HRP, [CONSTANTS.WITNESS_VERSION, ...bech32m.toWords(root)], 1023);
}

// Decode a btx address to its 32-byte witness program (the Merkle root).
// Returns null if the string is not a well-formed btx v2 witness address.
function addressToRoot(address) {
  let decoded;
  try {
    decoded = bech32m.decode(address, 1023);
  } catch {
    return null;
  }
  if (decoded.prefix !== CONSTANTS.HRP) return null;
  const words = decoded.words;
  if (words.length < 1 || words[0] !== CONSTANTS.WITNESS_VERSION) return null;
  let program;
  try {
    program = Uint8Array.from(bech32m.fromWords(words.slice(1)));
  } catch {
    return null;
  }
  if (program.length !== CONSTANTS.HASH_LEN) return null;
  return program;
}

// ----------------------------------------------------------------------------
// Core verify: pure cryptography, no wall-clock, no policy, never throws.
//
//   verifyOwnership(address, challenge, proof) -> boolean
//
// address    the btx1... address the RP expects the signer to own.
// challenge  the challenge object {nonce, rp_origin, ts} the RP issued. If null,
//            the challenge embedded in the proof is used instead.
// proof      the proof bundle {v, alg, address, login_pubkey,
//            recovery_leaf_hash, signature, challenge?}.
//
// Returns true iff:
//   1. the proof is a well-formed v1 ML-DSA-44 bundle,
//   2. login_pubkey + recovery_leaf_hash rebuild to exactly `address`,
//   3. the signature is a valid ML-DSA-44 signature by login_pubkey over
//      challengeBytes(challenge).
// ----------------------------------------------------------------------------

export function verifyOwnership(address, challenge, proof) {
  try {
    if (!proof || typeof proof !== "object") return false;
    if (proof.v !== CONSTANTS.VERSION) return false;
    if (proof.alg !== CONSTANTS.ALG) return false;

    const loginPubkey = hexToBytes(proof.login_pubkey);
    const recoveryLeafHash = hexToBytes(proof.recovery_leaf_hash);
    const signature = hexToBytes(proof.signature);
    if (!loginPubkey || loginPubkey.length !== CONSTANTS.MLDSA44_PUBKEY_LEN) return false;
    if (!recoveryLeafHash || recoveryLeafHash.length !== CONSTANTS.HASH_LEN) return false;
    if (!signature || signature.length !== CONSTANTS.MLDSA44_SIG_LEN) return false;

    // Which address are we matching against? The argument is authoritative.
    // If the caller passed none, fall back to the address inside the proof.
    const expectedAddress = address != null ? address : proof.address;
    if (typeof expectedAddress !== "string") return false;

    // 1) Rebuild the root and require it to equal the address' witness program.
    const claimedRoot = addressToRoot(expectedAddress);
    if (!claimedRoot) return false;
    const rebuiltRoot = rebuildRoot(loginPubkey, recoveryLeafHash);
    if (!equalBytes(rebuiltRoot, claimedRoot)) return false;

    // If the proof also carries an address, it must agree with what we matched.
    if (typeof proof.address === "string") {
      const proofRoot = addressToRoot(proof.address);
      if (!proofRoot || !equalBytes(proofRoot, claimedRoot)) return false;
    }

    // 2) Verify the signature over the canonical challenge digest.
    const ch = challenge != null ? challenge : proof.challenge;
    if (!ch || typeof ch.nonce !== "string" || typeof ch.rp_origin !== "string") return false;
    if (!Number.isInteger(ch.ts)) return false;

    const digest = challengeBytes(ch);
    return ml_dsa44.verify(signature, digest, loginPubkey) === true;
  } catch {
    // Any malformed input resolves to a clean false, never an exception.
    return false;
  }
}

// ----------------------------------------------------------------------------
// Replay protection: the RP tracks nonces it has issued and not yet consumed.
// Swap this for Redis / a DB table in production; the interface is what matters.
// ----------------------------------------------------------------------------

export class MemoryNonceStore {
  constructor() {
    this._used = new Set();
  }
  // Returns true if the nonce was fresh (and marks it used), false if replayed.
  consume(nonce) {
    if (this._used.has(nonce)) return false;
    this._used.add(nonce);
    return true;
  }
  isUsed(nonce) {
    return this._used.has(nonce);
  }
}

// ----------------------------------------------------------------------------
// Full sign-in check: cryptography + policy (origin binding, freshness, replay).
//
//   verifySignIn(proof, {
//     expectedOrigin,          required: your DApp's exact web origin
//     expectedAddress,         optional: the address you expect (else trust proof)
//     ttlMs, skewMs,           freshness window (see POLICY_DEFAULTS)
//     nonceStore,              optional: object with consume(nonce)->bool
//     now,                     optional: ms timestamp to check against (test hook)
//   }) -> { ok: boolean, reason: string, address: string|null }
//
// reason is one of:
//   ok | bad_proof_shape | origin_mismatch | address_mismatch |
//   expired | not_yet_valid | nonce_used | bad_signature
// ----------------------------------------------------------------------------

export function verifySignIn(proof, opts = {}) {
  const fail = (reason) => ({ ok: false, reason, address: null });

  if (!proof || typeof proof !== "object" || !proof.challenge) return fail("bad_proof_shape");
  const ch = proof.challenge;
  if (typeof ch.nonce !== "string" || typeof ch.rp_origin !== "string" || !Number.isInteger(ch.ts)) {
    return fail("bad_proof_shape");
  }

  // 1) Origin binding: a proof for another DApp must not be accepted here.
  if (opts.expectedOrigin != null && ch.rp_origin !== opts.expectedOrigin) {
    return fail("origin_mismatch");
  }

  // 2) Address: match against what the RP expects, if it named one.
  const address = opts.expectedAddress != null ? opts.expectedAddress : proof.address;
  if (typeof address !== "string") return fail("bad_proof_shape");
  if (opts.expectedAddress != null && typeof proof.address === "string" && proof.address !== opts.expectedAddress) {
    return fail("address_mismatch");
  }

  // 3) Freshness against the signed issuance time `ts`.
  const ttlMs = opts.ttlMs != null ? opts.ttlMs : POLICY_DEFAULTS.ttlMs;
  const skewMs = opts.skewMs != null ? opts.skewMs : POLICY_DEFAULTS.skewMs;
  const now = opts.now != null ? opts.now : Date.now();
  if (ch.ts - now > skewMs) return fail("not_yet_valid");
  if (now - ch.ts > ttlMs) return fail("expired");

  // 4) Cryptographic proof of ownership.
  if (!verifyOwnership(address, ch, proof)) return fail("bad_signature");

  // 5) Replay: consume the nonce last, only after everything else passed.
  if (opts.nonceStore && typeof opts.nonceStore.consume === "function") {
    if (!opts.nonceStore.consume(ch.nonce)) return fail("nonce_used");
  }

  return { ok: true, reason: "ok", address };
}

// ----------------------------------------------------------------------------
// RP-side challenge maker. Use crypto.getRandomValues for the nonce. The nonce
// and ts can be injected for deterministic tests.
// ----------------------------------------------------------------------------

export function makeChallenge(rpOrigin, { nonce, ts } = {}) {
  let nonceHex = nonce;
  if (nonceHex == null) {
    const b = new Uint8Array(32);
    crypto.getRandomValues(b);
    nonceHex = bytesToHex(b);
  }
  return {
    nonce: nonceHex,
    rp_origin: rpOrigin,
    ts: ts != null ? ts : Date.now(),
  };
}

export { bytesToHex, hexToBytes };
