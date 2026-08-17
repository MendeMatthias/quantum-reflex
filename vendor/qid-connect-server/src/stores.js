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
// Re-claim window for a lost 'done' response. Widened from 30s because it now also
// has to cover a HUMAN step: poll() reports the address first and only mints a session
// after the user confirms it (see the address confirmation gate in core.js), and both
// calls go through claim(). 30s was fine for retrying a dropped response and far too
// short for reading an address and deciding. Re-claiming still requires the pollSecret,
// which never leaves the browser that requested the challenge, so widening it does not
// widen who can claim — only how long that one browser has.
const CLAIM_GRACE_MS = 120 * 1000;

export class IssuedNonceStore {
  constructor({ ttlMs = 10 * 60 * 1000 } = {}) {
    this.ttlMs = ttlMs;
    this._map = new Map(); // nonce -> { at, used, secret, address, claimedAt }
  }
  // Entries are inserted in non-decreasing `at` order (issue() deletes before
  // re-inserting, so a re-issued nonce moves to the end) and a Map iterates in
  // insertion order — so the first LIVE entry means every later one is live too
  // and the walk can stop there. Walking the whole map instead was O(n) work on
  // every unauthenticated POST /challenge: measured 23.6us per issue at 10k live
  // nonces, 129us at 40k, 527us at 160k — i.e. a full core spent sweeping at a
  // few hundred req/s, reachable by anyone with no credentials. Stopping early
  // deletes exactly the same set ~300x cheaper.
  //
  // A caller that passes a DECREASING `now` (only tests do) can leave an expired
  // entry behind the break. That is safe by construction: _live() re-checks the
  // TTL on every read, so a survivor is still treated as expired — the sweep is
  // an eviction optimisation, never the correctness gate.
  _sweep(now) {
    for (const [k, v] of this._map) {
      if (now - v.at > this.ttlMs) this._map.delete(k);
      else break;
    }
  }
  _live(nonce, now) {
    const rec = this._map.get(nonce);
    if (!rec || now - rec.at > this.ttlMs) return null;
    return rec;
  }
  issue(nonce, secret, now = Date.now()) {
    this._sweep(now);
    // Delete before set so a re-issued nonce moves to the END of the insertion
    // order. Map.set on an existing key updates in place and keeps the old
    // position, which would put a NEW `at` behind older ones and break the
    // ordering invariant _sweep()'s early exit relies on.
    this._map.delete(nonce);
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
//                         adapter can persist proof-derived fields.
//                         recoveryLeafHash is stable across login-key rotation
//                         but is NOT an identity key: it is signer-chosen and
//                         public on chain, so never look up, merge, or
//                         rate-limit accounts by it (see core.js).
//                         poll() resolves an account created
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
