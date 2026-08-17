// sqlite.js
//
// Durable stores on SQLite. This is the production adapter for single-host
// deployments: nonces, poll secrets, and accounts survive restarts and are
// shared across processes through the database file.
//
// Driver-agnostic: pass any synchronous SQLite handle with exec() and
// prepare() returning statements with run() / get(). All three mainstream
// drivers share that exact shape:
//
//   import { Database } from "bun:sqlite";            // bun
//   import { DatabaseSync } from "node:sqlite";       // node 22+
//   import Database from "better-sqlite3";            // node, any version
//
//   const db = new Database("qid.sqlite");            // or new DatabaseSync(...)
//   const qid = createQidConnect({
//     origin, sessionSecret,
//     nonceStore: new SqliteNonceStore(db),
//     accounts: new SqliteAccounts(db),
//   });
//
// TTL: SqliteNonceStore defaults to a 10-minute ttlMs, independent of the
// connect ttlMs. If you raise createQidConnect's ttlMs (e.g. for slow
// hardware-wallet signing), pass a matching or larger ttlMs here too —
// new SqliteNonceStore(db, { ttlMs: connectTtlMs + skewMs }) — or the store
// will sweep still-valid challenges and reject them as nonce_unknown.
//
// For multi-instance deployments use Redis or a SQL server implementing the
// same interfaces (documented in stores.js); this file doubles as the
// reference for how the operations must behave. The conformance tests in
// test/stores.test.js run against any adapter; point them at yours.
//
// SPDX-License-Identifier: MIT

// Re-claim window for a lost 'done' response. MUST match stores.js — the two
// implementations are held to one shared conformance suite, so a drift here shows up
// as a store-specific test failure rather than as a behaviour difference in production.
// Widened from 30s because it now also covers the human address-confirmation step
// (poll reports the address, the user accepts, poll mints). Re-claiming still needs
// the pollSecret, so this widens how long that one browser has, not who can claim.
const CLAIM_GRACE_MS = 120 * 1000;

export class SqliteNonceStore {
  constructor(db, { ttlMs = 10 * 60 * 1000, table = "qid_nonces" } = {}) {
    this.ttlMs = ttlMs;
    this.db = db;
    db.exec(
      `CREATE TABLE IF NOT EXISTS ${table} (
        nonce TEXT PRIMARY KEY,
        at INTEGER NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        secret TEXT,
        address TEXT,
        claimed_at INTEGER NOT NULL DEFAULT 0
      )`
    );
    // Migrate a table created by an earlier version that lacks claimed_at.
    try {
      db.exec(`ALTER TABLE ${table} ADD COLUMN claimed_at INTEGER NOT NULL DEFAULT 0`);
    } catch {
      /* column already exists */
    }
    this._insert = db.prepare(
      `INSERT OR REPLACE INTO ${table} (nonce, at, used, secret, address, claimed_at) VALUES (?, ?, 0, ?, NULL, 0)`
    );
    this._get = db.prepare(`SELECT at, used, secret, address, claimed_at FROM ${table} WHERE nonce = ?`);
    this._consume = db.prepare(
      `UPDATE ${table} SET used = 1 WHERE nonce = ? AND used = 0 AND at >= ?`
    );
    // Secret-bound burn for the rotating widget: match the secret in the WHERE so
    // only the issuing browser can retire the nonce (atomic, one row at most).
    this._retire = db.prepare(
      `UPDATE ${table} SET used = 1 WHERE nonce = ? AND used = 0 AND at >= ? AND secret IS NOT NULL AND secret = ?`
    );
    this._complete = db.prepare(`UPDATE ${table} SET address = ? WHERE nonce = ? AND at >= ?`);
    this._markClaimed = db.prepare(`UPDATE ${table} SET claimed_at = ? WHERE nonce = ? AND claimed_at = 0`);
    this._sweep = db.prepare(`DELETE FROM ${table} WHERE at < ?`);
  }
  issue(nonce, secret, now = Date.now()) {
    this._sweep.run(now - this.ttlMs);
    this._insert.run(nonce, now, secret || null);
  }
  has(nonce, now = Date.now()) {
    const rec = this._get.get(nonce);
    return !!rec && !rec.used && now - rec.at <= this.ttlMs;
  }
  consume(nonce, now = Date.now()) {
    // atomic: only one caller can flip used 0 -> 1
    const res = this._consume.run(nonce, now - this.ttlMs);
    return res.changes === 1;
  }
  retire(nonce, secret, now = Date.now()) {
    if (typeof secret !== "string" || !secret) return false;
    // The secret is compared inside the UPDATE. Constant-time comparison is not
    // available in SQL, but a retire only burns a nonce (a DoS-grade action, not
    // a login), so a timing side channel here reveals nothing that moves funds
    // or grants a session.
    return this._retire.run(nonce, now - this.ttlMs, secret).changes === 1;
  }
  complete(nonce, address, now = Date.now()) {
    return this._complete.run(address, nonce, now - this.ttlMs).changes === 1;
  }
  claim(nonce, secret, now = Date.now()) {
    const rec = this._get.get(nonce);
    if (
      !rec ||
      now - rec.at > this.ttlMs ||
      !rec.secret ||
      !timingSafeEqualStr(rec.secret, secret)
    ) {
      return { status: "expired" };
    }
    if (rec.address) {
      // Idempotent for the matching secret within a short grace, so a 'done'
      // response lost in transit can be re-claimed instead of losing the
      // sign-in. After the grace, expire. The record is swept at ttlMs.
      if (rec.claimed_at && now - rec.claimed_at > CLAIM_GRACE_MS) {
        return { status: "expired" };
      }
      if (!rec.claimed_at) this._markClaimed.run(now, nonce);
      return { status: "done", address: rec.address };
    }
    return { status: "pending" };
  }
}

export class SqliteAccounts {
  constructor(db, { table = "qid_accounts" } = {}) {
    this.db = db;
    db.exec(
      `CREATE TABLE IF NOT EXISTS ${table} (
        address TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL,
        profile TEXT NOT NULL DEFAULT '{}'
      )`
    );
    this._insert = db.prepare(
      `INSERT OR IGNORE INTO ${table} (address, created_at) VALUES (?, ?)`
    );
    this._get = db.prepare(`SELECT address, created_at, profile FROM ${table} WHERE address = ?`);
    this._patch = db.prepare(`UPDATE ${table} SET profile = ? WHERE address = ?`);
  }
  _row(rec) {
    if (!rec) return null;
    let profile = {};
    try {
      profile = JSON.parse(rec.profile);
    } catch {
      /* corrupt profile never blocks login */
    }
    // Spread profile FIRST so the real columns always win: a profile carrying a
    // key named "address" or "createdAt" (e.g. a dApp that patched user input)
    // must never shadow the verifier-derived address the rest of the app trusts.
    return { ...profile, address: rec.address, createdAt: rec.created_at };
  }
  async getOrCreate(address, now = Date.now()) {
    this._insert.run(address, now);
    return this._row(this._get.get(address));
  }
  async get(address) {
    return this._row(this._get.get(address));
  }
  // Optional profile fields (display name, avatar) as a JSON patch. Email is
  // not a profile field; do not put one here.
  async patch(address, fields) {
    const rec = this._get.get(address);
    if (!rec) return null;
    let profile = {};
    try {
      profile = JSON.parse(rec.profile);
    } catch {
      /* start clean */
    }
    Object.assign(profile, fields);
    // Reserved keys are real columns, never profile fields. Strip them so a dApp
    // that forwards user-controlled input to patch() can't store an "address"
    // that would later be read back as the account's identity.
    delete profile.address;
    delete profile.createdAt;
    for (const k of Object.keys(profile)) {
      if (profile[k] == null) delete profile[k];
    }
    this._patch.run(JSON.stringify(profile), address);
    return this._row(this._get.get(address));
  }
}

function timingSafeEqualStr(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
