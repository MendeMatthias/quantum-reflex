// session.js
//
// Stateless session tokens for qID Connect. Standard JWT (HS256), implemented
// on node:crypto so the SDK carries zero extra dependencies. The subject is
// the verified BTX address. No user id, no email, the address is the account.
//
// SPDX-License-Identifier: MIT

import { createHmac, timingSafeEqual } from "node:crypto";

const b64url = (buf) => Buffer.from(buf).toString("base64url");

function fromB64url(s) {
  try {
    return Buffer.from(s, "base64url");
  } catch {
    return null;
  }
}

// Create a session token for a verified address.
export function signSession({ address, secret, maxAgeMs, now = Date.now() }) {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64url(
    JSON.stringify({
      sub: address,
      iss: "qid-connect",
      iat: Math.floor(now / 1000),
      exp: Math.floor((now + maxAgeMs) / 1000),
    })
  );
  const mac = createHmac("sha256", secret).update(`${header}.${payload}`).digest();
  return `${header}.${payload}.${b64url(mac)}`;
}

// Verify a session token. Returns { address, issuedAt, expiresAt } or null.
// Never throws on malformed input.
export function verifySessionToken(token, { secret, now = Date.now() }) {
  if (typeof token !== "string" || token.length > 4096) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;

  const expected = createHmac("sha256", secret).update(`${h}.${p}`).digest();
  const got = fromB64url(s);
  if (!got || got.length !== expected.length || !timingSafeEqual(got, expected)) return null;

  const headerBuf = fromB64url(h);
  const payloadBuf = fromB64url(p);
  if (!headerBuf || !payloadBuf) return null;
  let header, payload;
  try {
    header = JSON.parse(headerBuf.toString("utf8"));
    payload = JSON.parse(payloadBuf.toString("utf8"));
  } catch {
    return null;
  }

  if (!header || header.alg !== "HS256") return null;
  if (!payload || payload.iss !== "qid-connect") return null;
  if (typeof payload.sub !== "string" || !payload.sub.startsWith("btx1")) return null;
  if (!Number.isInteger(payload.exp) || payload.exp * 1000 <= now) return null;
  if (!Number.isInteger(payload.iat)) return null;

  return {
    address: payload.sub,
    issuedAt: payload.iat * 1000,
    expiresAt: payload.exp * 1000,
  };
}
