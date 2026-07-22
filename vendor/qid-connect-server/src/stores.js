// stores.js
//
// Default in-memory stores plus the interfaces production deployments
// implement on Redis or a database. Both interfaces are tiny on purpose.
//
// SPDX-License-Identifier: MIT

// Nonce store. The server only accepts nonces it issued, once, within a TTL.
// It also carries the cross-device rendezvous state for QR sign-in: when a
// remote signer (phone wallet) submits the proof, the verified address is
// parked under the nonce until the browser that issued the challenge claims
// it with the poll secret only it knows.
//
// Production interface (implement on Redis or SQL, keyed by nonce):
//   issue(nonce, secret)      store as issued and unused, expire after ttlMs
//   has(nonce)                true if issued, unused, not expired
//   consume(nonce)            atomically mark used; true if issued and unused.
//                             This is the replay gate: it is called only after
//                             the post-quantum signature verified, so it needs
//                             no secret.
//   retire(nonce, secret)     mark used ONLY if the poll secret matches; true on
//                             success. Used by the rotating widget to burn the
//                             superseded nonce; the secret binding stops a
//                             bystander who can see the QR from griefing it.
//   complete(nonce, address)  park the verified address for pickup
//   claim(nonce, secret)      { status: "pending" | "done" | "expired", address? }
//                             "done" requires the secret to match. It is
//                             idempotent for the matching secret within a short
//                             grace window (CLAIM_GRACE_MS): a 'done' response
//                             lost on a flaky mobile hop can be re-claimed
//                             instead of losing the sign-in. A different secret
//                             never gets 'done'; the record is swept at ttlMs.
//
// Redis sketch: one hash per nonce (fields: used, secret, address, claimedAt)
// with PEXPIRE ttlMs; consume/retire = compare then HSET used; claim = compare
// secret, and on first done set claimedAt, then re-serve done until the grace
// elapses.
const CLAIM_GRACE_MS = 30 * 1000; // re-claim window for a lost 'done' response

export class IssuedNonceStore {
  constructor({ ttlMs = 10 * 60 * 1000 } = {}) {
    this.ttlMs = ttlMs;
    this._map = new Map(); // nonce -> { at, used, secret, address, claimedAt }
  }
  _sweep(now) {
    for (const [k, v] of this._map) {
      if (now - v.at > this.ttlMs) this._map.delete(k);
    }
  }
  _live(nonce, now) {
    const rec = this._map.get(nonce);
    if (!rec || now - rec.at > this.ttlMs) return null;
    return rec;
  }
  issue(nonce, secret, now = Date.now()) {
    this._sweep(now);
    this._map.set(nonce, { at: now, used: false, secret: secret || null, address: null, claimedAt: 0 });
  }
  has(nonce, now = Date.now()) {
    const rec = this._live(nonce, now);
    return !!rec && !rec.used;
  }
  consume(nonce, now = Date.now()) {
    const rec = this._live(nonce, now);
    if (!rec || rec.used) return false;
    rec.used = true;
    return true;
  }
  retire(nonce, secret, now = Date.now()) {
    const rec = this._live(nonce, now);
    if (!rec || rec.used) return false;
    if (!rec.secret || !timingSafeEqualStr(rec.secret, secret)) return false;
    rec.used = true;
    return true;
  }
  complete(nonce, address, now = Date.now()) {
    const rec = this._live(nonce, now);
    if (!rec) return false;
    rec.address = address;
    return true;
  }
  claim(nonce, secret, now = Date.now()) {
    const rec = this._live(nonce, now);
    if (!rec || !rec.secret || !timingSafeEqualStr(rec.secret, secret)) {
      return { status: "expired" };
    }
    if (rec.address) {
      // Idempotent for the matching secret within a short grace: a 'done'
      // response lost in transit (dropped on a flaky mobile hop) can be
      // re-claimed instead of stranding the sign-in. After the grace, expire.
      if (rec.claimedAt && now - rec.claimedAt > CLAIM_GRACE_MS) {
        return { status: "expired" };
      }
      if (!rec.claimedAt) rec.claimedAt = now;
      return { status: "done", address: rec.address };
    }
    return { status: "pending" };
  }
}

function timingSafeEqualStr(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Account store. The address is the primary key. That is the whole model.
//
// Production interface:
//   getOrCreate(address, now, context)  return the account, creating it on
//                         first sign-in. When the call comes from a verified
//                         proof, context is { proof, recoveryLeafHash } so an
//                         adapter can persist proof-derived identity fields
//                         (recoveryLeafHash is stable across login-key
//                         rotation). poll() resolves an account created
//                         moments earlier by the proof submission, so it may
//                         call without context; never null out a stored field
//                         on a context-free call. Ignore the argument if you
//                         only need the address (both built-ins do).
//   get(address)          return the account or null
//
// SQL sketch: one table, address TEXT PRIMARY KEY, created_at, plus whatever
// optional profile fields your app wants. No email column is needed.
export class MemoryAccounts {
  constructor() {
    this._map = new Map();
  }
  async getOrCreate(address, now = Date.now()) {
    let acct = this._map.get(address);
    if (!acct) {
      acct = { address, createdAt: now };
      this._map.set(address, acct);
    }
    return acct;
  }
  async get(address) {
    return this._map.get(address) || null;
  }
}
