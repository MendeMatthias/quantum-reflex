// Quantum Reflex — one small server: the static game page + qID Connect
// (/qid/*) + the leaderboard API (/score, /leaderboard), all on ONE origin.
//
// Same-origin is the whole point: the qID session is a first-party HttpOnly
// cookie, so the page, the wallets, /qid/*, and /score must share an origin.
// That is why this is a single server (not a CDN page + separate backend) —
// see the build brief §3. Modeled on qid-connect examples/static-rewrite-demo.
//
// Runs on bun (bun:sqlite). Durable SQLite: qID nonces/accounts AND the
// leaderboard survive restarts.
//
//   QID_ORIGIN=https://play.qid.dev \
//   QID_SESSION_SECRET=$(openssl rand -hex 24) \
//   QID_DB=/var/lib/quantum-reflex/qid.sqlite  bun server.mjs
//
// SPDX-License-Identifier: MIT

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { mkdirSync } from "node:fs";
import { dirname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createQidConnect,
  SqliteNonceStore,
  SqliteAccounts,
} from "./vendor/qid-connect-server/src/index.js";
import { qidMiddleware, requireQidSession } from "./vendor/qid-connect-server/src/middleware.js";
import { fetchRelicNames } from "./lib/relic-name.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(HERE, "public");

const HOST = process.env.QID_HOST || "127.0.0.1";
const PORT = Number(process.env.QID_PORT || 8899);

// CRITICAL: the exact host users land on, AFTER any apex↔www / http→https
// redirect. Open the live site and read `location.origin` — that string goes
// here, or /qid/verify rejects every proof with bad_origin.
const ORIGIN = process.env.QID_ORIGIN || "";
const SECRET = process.env.QID_SESSION_SECRET || "";
const DB_PATH = process.env.QID_DB || "./data/qid.sqlite";

// Relic-name lookup: read the name a player forged into a BTX relic they hold,
// so they can claim their board spot under it. External, best-effort, cached.
const BTXSCAN_BASE = (process.env.QR_BTXSCAN || "https://btxscan.io").replace(/\/+$/, "");
const RELICS_ENABLED = !/^(0|off|false|no)$/i.test(process.env.QR_RELICS || "on");
const RELIC_TTL_MS = Number(process.env.QR_RELIC_TTL_MS) || 10 * 60 * 1000;

if (!/^https?:\/\/[^/]+$/.test(ORIGIN)) {
  console.error("QID_ORIGIN must be an exact origin like https://play.qid.dev (no path, no trailing slash).");
  process.exit(1);
}
if (SECRET.length < 32) {
  console.error("QID_SESSION_SECRET must be 32+ random chars. Refusing to start.");
  process.exit(1);
}

// Boot-time apex/www sanity check (non-fatal): warn if the configured origin
// itself redirects — the classic bad_origin trap. Fire-and-forget with a short
// timeout: when QID_ORIGIN points back at THIS app (custom domain), awaiting it
// would deadlock startup (the fetch waits on a server that hasn't listen()ed
// yet), so it must never block or hang.
(async () => {
  try {
    const head = await fetch(ORIGIN, { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(4000) });
    const loc = head.headers.get("location");
    if (head.status >= 300 && head.status < 400 && loc) {
      console.warn(
        `WARNING: QID_ORIGIN ${ORIGIN} redirects (${head.status}) to ${loc}. ` +
        `Set QID_ORIGIN to the FINAL host users land on, or /qid/verify rejects with bad_origin.`
      );
    }
  } catch { /* offline / self-referential / slow: skip */ }
})();

// bun:sqlite (this project targets bun). node:sqlite fallback keeps it running
// under Node 22+ too. Both give a handle with .exec/.prepare -> .run/.get/.all.
let db;
if (typeof Bun !== "undefined") {
  const { Database } = await import("bun:sqlite");
  mkdirSync(dirname(DB_PATH), { recursive: true });
  db = new Database(DB_PATH);
} else {
  const { DatabaseSync } = await import("node:sqlite");
  mkdirSync(dirname(DB_PATH), { recursive: true });
  db = new DatabaseSync(DB_PATH);
}
db.exec("PRAGMA journal_mode=WAL");

const qid = createQidConnect({
  origin: ORIGIN,
  sessionSecret: SECRET,
  nonceStore: new SqliteNonceStore(db),
  accounts: new SqliteAccounts(db),
});

// This service receives the FULL /qid/* path (raw node:http, no prefix strip).
const qidRoutes = qidMiddleware(qid, { basePath: "/qid" });
const guard = requireQidSession(qid);

// ---------------------------------------------------------------------------
// Leaderboard store — one extra table on the same SQLite db as qID.
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS scores (
    address    TEXT PRIMARY KEY,   -- the qID account (req.qidSession.address)
    best_ms    INTEGER NOT NULL,   -- lower is better; we keep the MIN avg seen
    name       TEXT,               -- optional display name (rendered as text)
    plays      INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
  )`);
db.exec("CREATE INDEX IF NOT EXISTS scores_best ON scores (best_ms ASC)");

// Positional (?) params throughout: bun:sqlite and node:sqlite handle anonymous
// params identically, while they disagree on named-param key prefixes.
//
// Upsert: keep the best (min) ms ever seen, bump plays, update name only when a
// non-empty one is supplied (COALESCE keeps the old name otherwise).
const upsertScore = db.prepare(`
  INSERT INTO scores (address, best_ms, name, plays, updated_at)
  VALUES (?, ?, ?, 1, ?)
  ON CONFLICT(address) DO UPDATE SET
    best_ms    = MIN(scores.best_ms, excluded.best_ms),
    name       = COALESCE(excluded.name, scores.name),
    plays      = scores.plays + 1,
    updated_at = excluded.updated_at`);
const getScore = db.prepare(`SELECT address, best_ms, name, plays FROM scores WHERE address = ?`);
const rankOf = db.prepare(`SELECT COUNT(*) AS better FROM scores WHERE best_ms < ?`);
const totalPlayers = db.prepare(`SELECT COUNT(*) AS n FROM scores`);
const topScores = db.prepare(`SELECT address, best_ms, name FROM scores ORDER BY best_ms ASC, updated_at ASC LIMIT ?`);

// Score bounds (brief §5): clamp superhuman/garbage. ~100ms is the human floor.
const MIN_MS = 80;
const MAX_MS = 2000;
const NAME_MAX = 32; // fits an on-chain forged name (<=31 bytes) exactly

// ---------------------------------------------------------------------------
// Small HTTP helpers
// ---------------------------------------------------------------------------
function sendJson(res, status, body) {
  const data = JSON.stringify(body);
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(data);
}

// Read a small JSON body. Score bodies are tiny; 8KB is plenty.
async function readJsonBody(req, maxBytes = 8 * 1024) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) throw new Error("body_too_large");
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text) return {};
  return JSON.parse(text);
}

function getCookie(req, name) {
  const header = req.headers?.cookie;
  if (typeof header !== "string") return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

// Same login-CSRF stance as the qID middleware: a present, mismatched Origin is
// a forgery; absent Origin is allowed (the session cookie is SameSite=Lax, so a
// cross-site POST would not carry it anyway).
function originAllowed(req) {
  const o = req.headers?.origin;
  if (o == null || o === "") return true;
  return o === qid.origin;
}

// btx1zwxyz...abcd  ->  btx1zwxy…abcd  (short form for the public board)
function shortAddr(a) {
  if (typeof a !== "string" || a.length <= 14) return a || "";
  return `${a.slice(0, 8)}…${a.slice(-4)}`;
}

// Trim to text, cap length, drop control chars. Rendered as textContent on the
// client too — this is defense in depth, never the only guard.
function cleanName(v) {
  if (typeof v !== "string") return null;
  // Strip C0 controls + DEL and angle brackets (defense in depth for the public
  // board; the client also renders names as textContent), collapse whitespace,
  // cap length.
  const s = v
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .replace(/[<>]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, NAME_MAX);
  return s.length ? s : null;
}

// Light per-address rate limit (brief §7). A real run takes >~10s, so one
// accepted score every 2s per address is generous and still blocks rapid spam.
// QR_RATE_MS tunes it; 0 disables (used by the e2e test's functional pass).
const RATE_MS = Number.isFinite(Number(process.env.QR_RATE_MS)) ? Number(process.env.QR_RATE_MS) : 2000;
const lastSubmit = new Map();
function rateLimited(address, now) {
  if (RATE_MS <= 0) return false;
  const prev = lastSubmit.get(address);
  if (prev != null && now - prev < RATE_MS) return true;
  lastSubmit.set(address, now);
  // Opportunistic prune so the map can't grow unbounded.
  if (lastSubmit.size > 5000) {
    for (const [k, t] of lastSubmit) if (now - t > 60_000) lastSubmit.delete(k);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Route: POST /score  (guarded — req.qidSession.address is the verified user)
// ---------------------------------------------------------------------------
function handleScore(req, res) {
  if (!originAllowed(req)) return sendJson(res, 403, { ok: false, reason: "bad_origin" });
  // requireQidSession sends its own 401 when there is no session; on success it
  // sets req.qidSession and calls our continuation.
  guard(req, res, async () => {
    try {
      const address = req.qidSession.address;
      const now = Date.now();
      if (rateLimited(address, now)) return sendJson(res, 429, { ok: false, reason: "rate_limited" });

      let body;
      try {
        body = await readJsonBody(req);
      } catch {
        return sendJson(res, 400, { ok: false, reason: "bad_request_body" });
      }

      const ms = Math.round(Number(body?.ms));
      if (!Number.isFinite(ms) || ms < MIN_MS || ms > MAX_MS) {
        return sendJson(res, 400, { ok: false, reason: "bad_score" });
      }
      const name = cleanName(body?.name);

      upsertScore.run(address, ms, name, now);

      const row = getScore.get(address);
      const best = row.best_ms;
      const rank = rankOf.get(best).better + 1;
      const total = totalPlayers.get().n;
      return sendJson(res, 200, { ok: true, best_ms: best, rank, total_players: total });
    } catch {
      return sendJson(res, 500, { ok: false, reason: "server_error" });
    }
  });
}

// ---------------------------------------------------------------------------
// Route: GET /leaderboard?limit=50  (public; adds { me } when signed in)
// ---------------------------------------------------------------------------
async function handleLeaderboard(req, res, query) {
  try {
    let limit = Number(query.get("limit"));
    if (!Number.isFinite(limit)) limit = 50;
    limit = Math.max(1, Math.min(100, Math.floor(limit)));

    // Who is asking? (Optional — the board is public.)
    let meAddr = null;
    const token = getCookie(req, qid.cookieName);
    if (token) {
      const s = await qid.session(token);
      if (s) meAddr = s.address;
    }

    const rows = topScores.all(limit).map((r, i) => ({
      rank: i + 1,
      address: shortAddr(r.address),
      name: r.name || null,
      best_ms: r.best_ms,
      mine: meAddr != null && r.address === meAddr,
    }));

    let me = null;
    if (meAddr) {
      const mine = getScore.get(meAddr);
      if (mine) {
        me = { rank: rankOf.get(mine.best_ms).better + 1, best_ms: mine.best_ms };
      }
    }

    res.setHeader("Cache-Control", "no-store");
    return sendJson(res, 200, { ok: true, total_players: totalPlayers.get().n, leaderboard: rows, me });
  } catch {
    return sendJson(res, 500, { ok: false, reason: "server_error" });
  }
}

// ---------------------------------------------------------------------------
// Route: GET /relic-name  (guarded) — the name the player forged into a BTX
// relic they currently hold, offered as their leaderboard name. Best-effort and
// cached; relics off / btxscan down / no relics all return an empty list, so
// this never blocks a sign-in.
// ---------------------------------------------------------------------------
const relicCache = new Map(); // address -> { at, names }
// Dev/demo only: on an http (non-prod) origin, QR_RELIC_DEBUG_ADDRESS makes the
// lookup resolve THIS address's relics instead of the caller's, so the relic
// chips can be exercised locally without holding a wallet. Inert over https.
const DEBUG_RELIC_ADDR =
  ORIGIN.startsWith("http://") && process.env.QR_RELIC_DEBUG_ADDRESS
    ? process.env.QR_RELIC_DEBUG_ADDRESS.trim()
    : "";
function handleRelicName(req, res) {
  guard(req, res, async () => {
    const address = DEBUG_RELIC_ADDR || req.qidSession.address;
    if (!RELICS_ENABLED) return sendJson(res, 200, { ok: true, names: [] });
    const now = Date.now();
    const hit = relicCache.get(address);
    if (hit && now - hit.at < RELIC_TTL_MS) return sendJson(res, 200, { ok: true, names: hit.names });
    let names = [];
    try {
      names = await fetchRelicNames(address, { base: BTXSCAN_BASE, timeoutMs: 6000 });
    } catch {
      names = [];
    }
    relicCache.set(address, { at: now, names });
    if (relicCache.size > 5000) {
      for (const [k, v] of relicCache) if (now - v.at > RELIC_TTL_MS) relicCache.delete(k);
    }
    return sendJson(res, 200, { ok: true, names });
  });
}

// ---------------------------------------------------------------------------
// Static files from ./public (index.html at /). Small allowlist by extension.
// ---------------------------------------------------------------------------
const CONTENT_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".webmanifest": "application/manifest+json",
  ".json": "application/json; charset=utf-8",
  ".woff2": "font/woff2",
};

async function serveStatic(req, res, path) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.statusCode = 405;
    return res.end("method not allowed\n");
  }
  let rel = decodeURIComponent(path);
  if (rel === "/" || rel === "") rel = "/index.html";
  // Resolve inside PUBLIC_DIR and reject traversal.
  const full = normalize(join(PUBLIC_DIR, rel));
  if (full !== PUBLIC_DIR && !full.startsWith(PUBLIC_DIR + "/")) {
    res.statusCode = 403;
    return res.end("forbidden\n");
  }
  const dot = full.lastIndexOf(".");
  const ext = dot === -1 ? "" : full.slice(dot).toLowerCase();
  const type = CONTENT_TYPES[ext];
  if (!type) {
    res.statusCode = 404;
    return res.end("not found\n");
  }
  try {
    const buf = await readFile(full);
    res.statusCode = 200;
    res.setHeader("Content-Type", type);
    // The page is tiny and must always reflect the latest deploy; don't cache
    // the HTML. Hashed assets could cache longer, but we have none yet.
    res.setHeader("Cache-Control", ext === ".html" ? "no-cache" : "public, max-age=3600");
    return res.end(req.method === "HEAD" ? undefined : buf);
  } catch {
    res.statusCode = 404;
    return res.end("not found\n");
  }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
const server = createServer((req, res) => {
  let path, query;
  try {
    const url = new URL(req.url, "http://internal");
    path = url.pathname;
    query = url.searchParams;
  } catch {
    path = "/";
    query = new URLSearchParams();
  }

  if (path === "/healthz") {
    res.setHeader("Content-Type", "text/plain");
    res.setHeader("Cache-Control", "no-store");
    return res.end("ok\n");
  }
  if (path === "/qid" || path.startsWith("/qid/")) return qidRoutes(req, res);
  if (path === "/score" && req.method === "POST") return handleScore(req, res);
  if (path === "/leaderboard" && req.method === "GET") return handleLeaderboard(req, res, query);
  if (path === "/relic-name" && req.method === "GET") return handleRelicName(req, res);

  return serveStatic(req, res, path);
});

server.listen(PORT, HOST, () => {
  console.log(`Quantum Reflex on http://${HOST}:${PORT}  origin=${ORIGIN}  db=${DB_PATH}`);
});
