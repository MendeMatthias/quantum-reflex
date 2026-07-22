#!/usr/bin/env bun
// btx-sign-ownership.mjs
//
// BTX Wallet Ownership Proof v1  (Sign-In With BTX)  --  reference signer / CLI
//
// Generates a proof that the holder of a BTX PQ wallet master key controls the
// wallet's address, by signing a challenge with the ML-DSA login key. Use it to
// produce test proofs today, before the in-wallet "Sign Message" button ships.
//
// This is self-contained: it ports the wallet's exact key derivation onto the
// same audited libraries the wallet core is built from, so the address and
// signature it produces are byte-identical to the BTX PQ wallet. It ships no
// wallet internals.
//
// Run with bun (recommended) or node >=20 after installing deps:
//   npm i @noble/post-quantum @noble/hashes @scure/base
//
// Usage:
//   bun btx-sign-ownership.mjs --random --origin https://dapp.example
//   bun btx-sign-ownership.mjs --master-file ./key.txt --origin https://dapp.example
//   bun btx-sign-ownership.mjs --random --origin https://x.example --nonce <64hex> --ts 1751835998000
//
// Flags:
//   --random                 use a throwaway random master key (default if none given)
//   --master-hex <64hex>     use this 64-char (32-byte) wallet master key  [SECRET]
//   --master-file <path>     read the 64-char master key from a file (first line)
//   --master-stdin           read the 64-char master key from stdin
//   --origin <url>           RP / DApp web origin to bind the proof to (required)
//   --nonce <64hex>          fixed challenge nonce (default: 32 random bytes)
//   --ts <ms>                fixed issuance time in ms since epoch (default: now)
//   --index <n>              login key index (default 0)
//   --out <path>             write the proof JSON to a file (default: stdout)
//   --pretty                 pretty-print the JSON
//
// SPDX-License-Identifier: MIT

import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { slh_dsa_shake_128s } from "@noble/post-quantum/slh-dsa.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { bech32m } from "@scure/base";

// ----------------------------------------------------------------------------
// Constants (must match the BTX wallet core + the verifier)
// ----------------------------------------------------------------------------
const HRP = "btx";
const WITNESS_VERSION = 2;
const LEAF_VERSION = 194;
const OP_CHECKSIG_MLDSA = 187;
const OP_CHECKSIG_SLHDSA = 188;
const LOGIN_TAG = "BTX-qID/login-v1";
const HARDENED = 0x80000000;
const PURPOSE = 87;
const PQ_SALT = "BTX-PQ-BIP87-HKDF-V1";
const PQ_INFO_TAG = "m/87h";
const ALGO_MLDSA = 0;
const ALGO_SLHDSA = 1;

// ----------------------------------------------------------------------------
// Byte helpers
// ----------------------------------------------------------------------------
const enc = new TextEncoder();
const utf8 = (s) => enc.encode(s);
const cat = (...a) => {
  let t = 0;
  for (const x of a) t += x.length;
  const o = new Uint8Array(t);
  let i = 0;
  for (const x of a) {
    o.set(x, i);
    i += x.length;
  }
  return o;
};
const be32 = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
};
const le32 = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
};
const toHex = (b) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
function fromHex(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function cmpBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

// ----------------------------------------------------------------------------
// Tagged hash, script, leaf/branch, address, challenge  (mirror of wallet core)
// ----------------------------------------------------------------------------
function taggedHash(tag, msg) {
  const t = sha256(utf8(tag));
  return sha256(cat(t, t, msg));
}
function compactSize(n) {
  if (n < 253) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(253, n & 0xff, (n >> 8) & 0xff);
  throw new Error("compactSize too large");
}
function pushData(data) {
  const n = data.length;
  if (n < 76) return cat(Uint8Array.of(n), data);
  if (n <= 255) return cat(Uint8Array.of(76, n), data);
  if (n <= 0xffff) return cat(Uint8Array.of(77, n & 0xff, (n >> 8) & 0xff), data);
  throw new Error("pushData too large");
}
function buildLeafScript(pubkey, opcode) {
  return cat(pushData(pubkey), Uint8Array.of(opcode));
}
function leafHash(script) {
  return taggedHash("P2MRLeaf", cat(Uint8Array.of(LEAF_VERSION), compactSize(script.length), script));
}
function branchHash(a, b) {
  const [lo, hi] = cmpBytes(a, b) <= 0 ? [a, b] : [b, a];
  return taggedHash("P2MRBranch", cat(lo, hi));
}
function p2mrAddress(loginPubkey, recoveryPubkey) {
  const h0 = leafHash(buildLeafScript(loginPubkey, OP_CHECKSIG_MLDSA));
  const h1 = leafHash(buildLeafScript(recoveryPubkey, OP_CHECKSIG_SLHDSA));
  const root = branchHash(h0, h1);
  const address = bech32m.encode(HRP, [WITNESS_VERSION, ...bech32m.toWords(root)], 1023);
  return { address, recoveryLeafHash: h1 };
}
function challengeBytes(c) {
  return taggedHash(LOGIN_TAG, utf8(JSON.stringify({ n: c.nonce, o: c.rp_origin, t: c.ts })));
}

// ----------------------------------------------------------------------------
// Key derivation (exact port of the wallet's BIP-87/HKDF PQ derivation).
// Verified byte-for-byte against ui/qid.bundle.js.
// ----------------------------------------------------------------------------
function derivePqSeedMaterial(masterSeed, { coin = 0, account = 0, change = 0, index = 0, algo }) {
  const info = cat(
    utf8(PQ_INFO_TAG),
    be32(HARDENED | PURPOSE),
    be32(HARDENED | coin),
    be32(HARDENED | account),
    be32(change),
    be32(index),
    Uint8Array.of(algo)
  );
  return hkdf(sha256, masterSeed, utf8(PQ_SALT), info, 32);
}
function stretchEntropy(sm) {
  const blocks = [];
  for (let c = 0; c < 4; c++) blocks.push(sha256(cat(sm, le32(c))));
  return cat(...blocks);
}
function deriveLoginKey(masterSeed, index = 0) {
  const sm = derivePqSeedMaterial(masterSeed, { index, algo: ALGO_MLDSA });
  const entropy = stretchEntropy(sm);
  return ml_dsa44.keygen(entropy.slice(0, 32));
}
function deriveRecoveryKey(masterSeed) {
  const sm = derivePqSeedMaterial(masterSeed, { index: 0, algo: ALGO_SLHDSA });
  const entropy = stretchEntropy(sm);
  return slh_dsa_shake_128s.keygen(entropy.slice(0, 48));
}

// ----------------------------------------------------------------------------
// Build a proof bundle from a master key + challenge
// ----------------------------------------------------------------------------
export function buildProof(masterSeed, challenge, { index = 0 } = {}) {
  const login = deriveLoginKey(masterSeed, index);
  const recovery = deriveRecoveryKey(masterSeed);
  const { address, recoveryLeafHash } = p2mrAddress(login.publicKey, recovery.publicKey);
  const signature = ml_dsa44.sign(challengeBytes(challenge), login.secretKey);
  return {
    v: 1,
    alg: "ML-DSA-44",
    address,
    challenge,
    login_pubkey: toHex(login.publicKey),
    recovery_leaf_hash: toHex(recoveryLeafHash),
    signature: toHex(signature),
  };
}

// ----------------------------------------------------------------------------
// CLI
// ----------------------------------------------------------------------------
function parseArgs(argv) {
  const a = { flags: new Set(), opts: {} };
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t === "--random" || t === "--master-stdin" || t === "--pretty") {
      a.flags.add(t.slice(2));
    } else if (t.startsWith("--")) {
      a.opts[t.slice(2)] = argv[++i];
    }
  }
  return a;
}

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

async function main() {
  const { flags, opts } = parseArgs(process.argv.slice(2));

  // Resolve the master key.
  let masterHex;
  let usedRealKey = false;
  if (opts["master-hex"]) {
    masterHex = opts["master-hex"].trim();
    usedRealKey = true;
  } else if (opts["master-file"]) {
    const fs = await import("node:fs");
    masterHex = fs.readFileSync(opts["master-file"], "utf8").split(/\r?\n/)[0].trim();
    usedRealKey = true;
  } else if (flags.has("master-stdin")) {
    masterHex = (await readStdin()).split(/\r?\n/)[0].trim();
    usedRealKey = true;
  } else {
    // default: throwaway random identity
    const b = new Uint8Array(32);
    crypto.getRandomValues(b);
    masterHex = toHex(b);
  }

  if (!/^[0-9a-fA-F]{64}$/.test(masterHex)) {
    console.error("error: master key must be 64 hex characters (32 bytes)");
    process.exit(2);
  }
  if (usedRealKey) {
    console.error("WARNING: you passed a real wallet master key. This is the wallet's root secret.");
    console.error("         Run this offline. The proof output does NOT contain the key, but be careful.");
  }
  const masterSeed = fromHex(masterHex);

  // Build the challenge.
  const origin = opts.origin || "https://dapp.example";
  if (!opts.origin) console.error("note: no --origin given, defaulting to https://dapp.example");
  let nonce = opts.nonce;
  if (nonce == null) {
    const nb = new Uint8Array(32);
    crypto.getRandomValues(nb);
    nonce = toHex(nb);
  }
  nonce = nonce.toLowerCase();
  if (!/^[0-9a-f]{32,}$/.test(nonce) || nonce.length % 2 !== 0) {
    console.error("error: --nonce must be even-length lowercase hex, at least 16 bytes");
    process.exit(2);
  }
  const ts = opts.ts != null ? Number(opts.ts) : Date.now();
  if (!Number.isInteger(ts)) {
    console.error("error: --ts must be an integer (ms since epoch)");
    process.exit(2);
  }
  const index = opts.index != null ? Number(opts.index) : 0;

  const challenge = { nonce, rp_origin: origin, ts };
  const proof = buildProof(masterSeed, challenge, { index });

  const json = flags.has("pretty") ? JSON.stringify(proof, null, 2) : JSON.stringify(proof);
  if (opts.out) {
    const fs = await import("node:fs");
    fs.writeFileSync(opts.out, json + "\n");
    console.error(`wrote proof to ${opts.out}`);
  } else {
    process.stdout.write(json + "\n");
  }
  console.error(`address: ${proof.address}`);
  console.error(`origin:  ${origin}`);
  console.error(`nonce:   ${nonce}`);
  console.error(`ts:      ${ts}  (${new Date(ts).toISOString()})`);
}

// Run as CLI only when invoked directly. Guarded so the module can also be
// imported in a browser bundle (where `process` does not exist) to reuse
// buildProof; the CLI tail simply never runs there.
const isNode = typeof process !== "undefined" && Array.isArray(process?.argv);
if (isNode && (import.meta.main || import.meta.url === `file://${process.argv[1]}`)) {
  main().catch((e) => {
    console.error("error:", e.message);
    process.exit(1);
  });
}
