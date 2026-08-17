import { test, expect } from "bun:test";
import { signSession, verifySessionToken } from "../src/session.js";

const secret = "test-secret-test-secret-test-secret-test";
const address = "btx1zy7veg685m5urvzf3p0num0vuy3pl5qwxapmrfut02ghghka22ftq36ccas";
const DAY = 24 * 60 * 60 * 1000;

test("round trip", () => {
  const now = 1_783_725_698_000;
  const token = signSession({ address, secret, maxAgeMs: 30 * DAY, now });
  const s = verifySessionToken(token, { secret, now: now + DAY });
  expect(s).not.toBeNull();
  expect(s.address).toBe(address);
});

test("expired token is rejected", () => {
  const now = 1_783_725_698_000;
  const token = signSession({ address, secret, maxAgeMs: DAY, now });
  expect(verifySessionToken(token, { secret, now: now + DAY + 1000 })).toBeNull();
});

test("wrong secret is rejected", () => {
  const token = signSession({ address, secret, maxAgeMs: DAY });
  expect(verifySessionToken(token, { secret: "another-secret-another-secret-xx" })).toBeNull();
});

test("tampered subject is rejected", () => {
  const now = 1_783_725_698_000;
  const token = signSession({ address, secret, maxAgeMs: DAY, now });
  const [h, p, s] = token.split(".");
  const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  payload.sub = "btx1attacker";
  const forged = [h, Buffer.from(JSON.stringify(payload)).toString("base64url"), s].join(".");
  expect(verifySessionToken(forged, { secret, now })).toBeNull();
});

test("garbage input never throws", () => {
  for (const junk of [null, undefined, "", "a.b", "a.b.c", "x".repeat(5000), 42]) {
    expect(verifySessionToken(junk, { secret })).toBeNull();
  }
});

test("alg is pinned to HS256", () => {
  const now = 1_783_725_698_000;
  const token = signSession({ address, secret, maxAgeMs: DAY, now });
  const [, p] = token.split(".");
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  expect(verifySessionToken(`${header}.${p}.`, { secret, now })).toBeNull();
});
