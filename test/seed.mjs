// Seed a running Quantum Reflex server with a few real signed-in scores, so the
// leaderboard has life for a demo/screenshot. Uses the frozen reference signer
// (real post-quantum proofs), exactly like a wallet would.
//
//   bun test/seed.mjs [origin]        # default http://localhost:8899
//
// SPDX-License-Identifier: MIT
import { buildProof } from "./lib/btx-sign-ownership.mjs";

const ORIGIN = process.argv[2] || "http://localhost:8899";
const BASE = ORIGIN.replace("localhost", "127.0.0.1");

function randMasterHex() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}
function seed(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function play(name, ms) {
  const ch = await (await fetch(BASE + "/qid/challenge", { method: "POST", headers: { Origin: ORIGIN } })).json();
  const proof = buildProof(seed(randMasterHex()), ch.challenge);
  const vr = await fetch(BASE + "/qid/verify", {
    method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN },
    body: JSON.stringify({ proof }),
  });
  const setCookie = vr.headers.getSetCookie?.()[0] || vr.headers.get("set-cookie") || "";
  const cookie = (setCookie.match(/(qid_session=[^;]+)/) || [])[1];
  const sr = await fetch(BASE + "/score", {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: ORIGIN, Cookie: cookie },
    body: JSON.stringify(name ? { ms, name } : { ms }),
  });
  const body = await sr.json();
  console.log(`  ${name || "(anon)"} -> ${ms}ms  rank #${body.rank}/${body.total_players}`);
}

const PLAYERS = [
  ["Nova", 182], ["Zephyr", 201], ["q_rabbit", 214], ["Muon", 233],
  ["Photon", 258], [null, 291], ["Tanaka", 176], ["glitch", 247],
];

for (const [name, ms] of PLAYERS) {
  await play(name, ms);
  await new Promise((r) => setTimeout(r, 30)); // different addresses, so no per-addr limit
}
console.log("seeded.");
