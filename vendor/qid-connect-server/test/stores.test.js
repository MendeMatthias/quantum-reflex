// Store adapter conformance suite. Every nonce store and account store
// implementation must pass these, including custom Redis/SQL adapters:
// import the two run* functions and point them at your adapter.

import { describe, test, expect } from "bun:test";
import { Database } from "bun:sqlite";
import { IssuedNonceStore, MemoryAccounts } from "../src/stores.js";
import { SqliteNonceStore, SqliteAccounts } from "../src/sqlite.js";

const TTL = 10 * 60 * 1000;
const T0 = 1_783_600_000_000;

export function runNonceStoreConformance(name, makeStore) {
  describe(`nonce store conformance: ${name}`, () => {
    test("issue, has, consume once", async () => {
      const s = makeStore();
      await s.issue("n1", "s1", T0);
      expect(await s.has("n1", T0)).toBe(true);
      expect(await s.has("unknown", T0)).toBe(false);
      expect(await s.consume("n1", T0)).toBe(true);
      expect(await s.consume("n1", T0)).toBe(false); // replay
      expect(await s.has("n1", T0)).toBe(false);
    });

    test("expiry fails closed", async () => {
      const s = makeStore();
      await s.issue("n2", "s2", T0);
      const late = T0 + TTL + 1;
      expect(await s.has("n2", late)).toBe(false);
      expect(await s.consume("n2", late)).toBe(false);
      expect((await s.claim("n2", "s2", late)).status).toBe("expired");
    });

    test("claim lifecycle: pending, wrong secret, done, idempotent within grace", async () => {
      const s = makeStore();
      await s.issue("n3", "sec", T0);
      expect((await s.claim("n3", "sec", T0)).status).toBe("pending");
      expect(await s.consume("n3", T0)).toBe(true);
      expect(await s.complete("n3", "btx1abc", T0)).toBe(true);
      expect((await s.claim("n3", "WRONG-SECRET", T0)).status).toBe("expired");
      const done = await s.claim("n3", "sec", T0);
      expect(done.status).toBe("done");
      expect(done.address).toBe("btx1abc");
      // Idempotent for the matching secret within the grace window, so a lost
      // 'done' response can be re-claimed instead of losing the sign-in.
      const reDone = await s.claim("n3", "sec", T0 + 5000);
      expect(reDone.status).toBe("done");
      expect(reDone.address).toBe("btx1abc");
      // A different secret never gets 'done', even inside the grace.
      expect((await s.claim("n3", "WRONG-SECRET", T0 + 5000)).status).toBe("expired");
      // The grace also has to cover the human address-confirmation step (poll reports
      // the address, the user accepts, poll mints), so it is 120s rather than 30s —
      // still inside it at +60s.
      expect((await s.claim("n3", "sec", T0 + 60000)).status).toBe("done");
      // After the grace window elapses, the claim expires (record still swept at TTL).
      expect((await s.claim("n3", "sec", T0 + 121000)).status).toBe("expired");
    });

    test("claim with no secret on record is never claimable", async () => {
      const s = makeStore();
      await s.issue("n4", null, T0);
      expect((await s.claim("n4", "", T0)).status).toBe("expired");
    });

    test("retire burns only with the matching secret", async () => {
      const s = makeStore();
      await s.issue("n5", "sec", T0);
      expect(await s.retire("n5", "WRONG", T0)).toBe(false); // bystander can't burn
      expect(await s.has("n5", T0)).toBe(true); // still live
      expect(await s.retire("n5", "sec", T0)).toBe(true); // issuing browser burns it
      expect(await s.has("n5", T0)).toBe(false);
      expect(await s.retire("n5", "sec", T0)).toBe(false); // already used
    });
  });
}

export function runAccountsConformance(name, makeAccounts) {
  describe(`accounts conformance: ${name}`, () => {
    test("getOrCreate is idempotent and keyed by address", async () => {
      const a = makeAccounts();
      const one = await a.getOrCreate("btx1abc", T0);
      const two = await a.getOrCreate("btx1abc", T0 + 5000);
      expect(one.address).toBe("btx1abc");
      expect(two.createdAt).toBe(one.createdAt);
      expect(await a.get("btx1missing")).toBeNull();
      expect((await a.get("btx1abc")).address).toBe("btx1abc");
    });
  });
}

runNonceStoreConformance("IssuedNonceStore (memory)", () => new IssuedNonceStore({ ttlMs: TTL }));
runNonceStoreConformance(
  "SqliteNonceStore (bun:sqlite)",
  () => new SqliteNonceStore(new Database(":memory:"), { ttlMs: TTL })
);
runAccountsConformance("MemoryAccounts", () => new MemoryAccounts());
runAccountsConformance("SqliteAccounts (bun:sqlite)", () => new SqliteAccounts(new Database(":memory:")));

describe("SqliteAccounts profile patch", () => {
  test("stores and clears optional profile fields", async () => {
    const a = new SqliteAccounts(new Database(":memory:"));
    await a.getOrCreate("btx1abc", T0);
    const withName = await a.patch("btx1abc", { displayName: "Satoshi PQ" });
    expect(withName.displayName).toBe("Satoshi PQ");
    const cleared = await a.patch("btx1abc", { displayName: null });
    expect(cleared.displayName).toBeUndefined();
    expect(cleared.createdAt).toBe(T0);
  });
});

describe("SqliteNonceStore persistence", () => {
  test("state survives a new store instance on the same database", async () => {
    const db = new Database(":memory:");
    const s1 = new SqliteNonceStore(db, { ttlMs: TTL });
    await s1.issue("n9", "sec", T0);
    await s1.consume("n9", T0);
    await s1.complete("n9", "btx1abc", T0);
    const s2 = new SqliteNonceStore(db, { ttlMs: TTL }); // "restart"
    const done = await s2.claim("n9", "sec", T0 + 1000);
    expect(done.status).toBe("done");
    expect(done.address).toBe("btx1abc");
  });
});
