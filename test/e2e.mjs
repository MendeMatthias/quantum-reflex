// End-to-end backend test for Quantum Reflex.
//
// Boots the real server and drives the full qID Connect flow with the frozen
// reference signer: challenge -> post-quantum proof -> /qid/verify (session
// cookie) -> guarded POST /score -> GET /leaderboard. No mocks; this exercises
// the vendored @qid/connect-server exactly as production does.
//
//   bun test/e2e.mjs
//
// SPDX-License-Identifier: MIT

import { buildProof } from "./lib/btx-sign-ownership.mjs";

const HERE = new URL(".", import.meta.url).pathname;
const ROOT = new URL("..", import.meta.url).pathname;

let passed = 0;
let failed = 0;
function ok(cond, label) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.log(`  ✗ ${label}`); }
}
function eq(a, b, label) { ok(a === b, `${label} (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`); }

function randMasterHex() {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}
function masterSeedFromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function waitForHealth(base, tries = 100) {
  for (let i = 0; i < tries; i++) {
    try { if ((await fetch(base + "/healthz")).ok) return true; } catch {}
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("server did not become healthy");
}

function startServer(env) {
  const proc = Bun.spawn(["bun", "server.mjs"], {
    cwd: ROOT,
    env: { ...process.env, ...env },
    stdout: "pipe",
    stderr: "pipe",
  });
  return proc;
}

// Full same-device sign-in: returns the session cookie string for `address`.
async function signIn(base, origin) {
  const master = randMasterHex();
  const chRes = await fetch(base + "/qid/challenge", { method: "POST", headers: { Origin: origin } });
  const { challenge } = await chRes.json();
  const proof = buildProof(masterSeedFromHex(master), challenge);
  const vRes = await fetch(base + "/qid/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: origin },
    body: JSON.stringify({ proof }),
  });
  const vBody = await vRes.json();
  if (!vBody.ok) throw new Error("verify failed: " + JSON.stringify(vBody));
  const setCookie = vRes.headers.getSetCookie?.()[0] || vRes.headers.get("set-cookie") || "";
  const m = setCookie.match(/(qid_session=[^;]+)/);
  if (!m) throw new Error("no session cookie set");
  return { cookie: m[1], address: vBody.address, origin };
}

async function postScore(base, session, ms, name) {
  const res = await fetch(base + "/score", {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: session.origin, Cookie: session.cookie },
    body: JSON.stringify(name === undefined ? { ms } : { ms, name }),
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

async function getBoard(base, session, limit) {
  const headers = {};
  if (session) { headers.Cookie = session.cookie; headers.Origin = session.origin; }
  const q = limit ? `?limit=${limit}` : "";
  const res = await fetch(base + "/leaderboard" + q, { headers });
  return { status: res.status, body: await res.json() };
}

// ---------------------------------------------------------------------------

const PORT_A = 8971;
const BASE_A = `http://127.0.0.1:${PORT_A}`;
const ORIGIN_A = `http://localhost:${PORT_A}`;
const DB_A = `${ROOT}data/e2e-a.sqlite`;

async function main() {
  await Bun.$`rm -rf ${ROOT}data/e2e-a.sqlite ${ROOT}data/e2e-a.sqlite-wal ${ROOT}data/e2e-a.sqlite-shm ${ROOT}data/e2e-b.sqlite ${ROOT}data/e2e-b.sqlite-wal ${ROOT}data/e2e-b.sqlite-shm`.quiet().nothrow();

  // ---- Boot A: functional pass, rate limiting OFF -------------------------
  const srvA = startServer({
    QID_ORIGIN: ORIGIN_A, QID_HOST: "127.0.0.1", QID_PORT: String(PORT_A),
    QID_SESSION_SECRET: "e2e-secret-32-chars-minimum-aaaaaaaaaa", QID_DB: DB_A,
    QR_RATE_MS: "0", QR_RELICS: "off", // hermetic: no external btxscan calls in the functional pass
  });
  try {
    await waitForHealth(BASE_A);

    console.log("\nsign-in + score");
    const alice = await signIn(BASE_A, ORIGIN_A);
    ok(/^btx1/.test(alice.address), `sign-in yields a btx address (${alice.address.slice(0, 12)}…)`);

    let r = await postScore(BASE_A, alice, 250);
    eq(r.status, 200, "first score accepted");
    eq(r.body.ok, true, "score ok:true");
    eq(r.body.best_ms, 250, "best_ms = 250");
    eq(r.body.rank, 1, "rank = 1 (only player)");
    eq(r.body.total_players, 1, "total_players = 1");

    console.log("\nbest-of preserved across replays");
    r = await postScore(BASE_A, alice, 400);
    eq(r.body.best_ms, 250, "slower score does not worsen best");
    r = await postScore(BASE_A, alice, 190);
    eq(r.body.best_ms, 190, "faster score improves best");

    console.log("\nscore clamp (80..2000)");
    eq((await postScore(BASE_A, alice, 10)).body.reason, "bad_score", "ms=10 rejected");
    eq((await postScore(BASE_A, alice, 79)).body.reason, "bad_score", "ms=79 rejected");
    eq((await postScore(BASE_A, alice, 5000)).body.reason, "bad_score", "ms=5000 rejected");
    eq((await postScore(BASE_A, alice, "fast")).body.reason, "bad_score", "non-number rejected");
    eq((await postScore(BASE_A, alice, 80)).status, 200, "ms=80 (floor) accepted");
    eq((await postScore(BASE_A, alice, 2000)).status, 200, "ms=2000 (ceil) accepted");

    console.log("\nunauthenticated + name handling");
    const noAuth = await fetch(BASE_A + "/score", {
      method: "POST", headers: { "Content-Type": "application/json", Origin: ORIGIN_A },
      body: JSON.stringify({ ms: 200 }),
    });
    eq(noAuth.status, 401, "no session -> 401");

    // Name: xss payload must survive only as inert text, capped at NAME_MAX (32).
    await postScore(BASE_A, alice, 150, '<img src=x onerror=alert(1)> ' + "z".repeat(50));
    let board = await getBoard(BASE_A, alice);
    const aliceRow = board.body.leaderboard.find((x) => x.mine);
    ok(aliceRow && aliceRow.name.length <= 32, `name capped to <=32 chars (got ${aliceRow?.name?.length})`);
    ok(aliceRow && !/[<>]/.test(aliceRow.name), "angle brackets stripped from name");

    console.log("\nrelic-name endpoint (guarded; hermetic with relics off)");
    const rnUnauth = await fetch(BASE_A + "/relic-name");
    eq(rnUnauth.status, 401, "relic-name without a session -> 401");
    const rn = await fetch(BASE_A + "/relic-name", { headers: { Cookie: alice.cookie, Origin: alice.origin } });
    const rnBody = await rn.json();
    eq(rn.status, 200, "relic-name signed in -> 200");
    eq(rnBody.ok, true, "relic-name ok:true");
    ok(Array.isArray(rnBody.names) && rnBody.names.length === 0, "relic-name returns [] when relics are off");

    console.log("\nleaderboard shape + ranking (fresh players, relative)");
    // Fresh identities so ranking assertions don't depend on earlier rows.
    const slow = await signIn(BASE_A, ORIGIN_A);
    const fast = await signIn(BASE_A, ORIGIN_A);
    const before = (await getBoard(BASE_A, null)).body.total_players;
    await postScore(BASE_A, slow, 480, "Slow");
    await postScore(BASE_A, fast, 320, "Fast");
    board = await getBoard(BASE_A, fast, 100);
    eq(board.body.total_players, before + 2, "two fresh players added");
    const fastRow = board.body.leaderboard.find((x) => x.name === "Fast");
    const slowRow = board.body.leaderboard.find((x) => x.name === "Slow");
    ok(fastRow && slowRow, "both named rows present");
    ok(fastRow.rank < slowRow.rank, `faster player outranks slower (Fast #${fastRow?.rank} < Slow #${slowRow?.rank})`);
    eq(fastRow.best_ms, 320, "Fast best_ms = 320");
    eq(slowRow.best_ms, 480, "Slow best_ms = 480");
    ok(fastRow.mine === true && slowRow.mine === false, "only the caller's row is flagged mine");
    ok(fastRow.address.includes("…"), "address shown in short form");
    ok(!fastRow.address.includes(fast.address.slice(10, 20)), "full address not leaked");
    eq(board.body.me.rank, fastRow.rank, "me.rank matches the caller's row");
    // Board is sorted ascending by best_ms.
    const times = board.body.leaderboard.map((x) => x.best_ms);
    ok(times.every((t, i) => i === 0 || times[i - 1] <= t), "board sorted fastest-first");

    console.log("\npublic board without a session");
    board = await getBoard(BASE_A, null);
    eq(board.status, 200, "public GET works signed-out");
    eq(board.body.me, null, "me is null when signed out");
    ok(board.body.leaderboard.every((x) => x.mine === false), "no row flagged mine when signed out");
  } finally {
    srvA.kill();
  }

  // ---- Boot B: rate limiting ON -------------------------------------------
  const PORT_B = 8972;
  const BASE_B = `http://127.0.0.1:${PORT_B}`;
  const ORIGIN_B = `http://localhost:${PORT_B}`;
  const srvB = startServer({
    QID_ORIGIN: ORIGIN_B, QID_HOST: "127.0.0.1", QID_PORT: String(PORT_B),
    QID_SESSION_SECRET: "e2e-secret-32-chars-minimum-bbbbbbbbbb", QID_DB: `${ROOT}data/e2e-b.sqlite`,
    QR_RATE_MS: "5000",
  });
  try {
    await waitForHealth(BASE_B);
    console.log("\nrate limit");
    const carol = await signIn(BASE_B, ORIGIN_B);
    eq((await postScore(BASE_B, carol, 200)).status, 200, "1st rapid score accepted");
    eq((await postScore(BASE_B, carol, 210)).status, 429, "2nd rapid score rate-limited (429)");
  } finally {
    srvB.kill();
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error("e2e crashed:", e); process.exit(1); });
