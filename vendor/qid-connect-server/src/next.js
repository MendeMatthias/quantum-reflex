// next.js
//
// Next.js App Router adapter for qID Connect. Built on the Web standard
// Request/Response, no Next import needed, so it also works in any runtime
// that speaks fetch handlers.
//
// Drop one catch-all route into your app:
//
//   // app/api/qid/[action]/route.js
//   import { createQidConnect } from "@qid/connect-server";
//   import { qidNextHandlers } from "@qid/connect-server/next";
//
//   const qid = createQidConnect({
//     origin: process.env.QID_ORIGIN,
//     sessionSecret: process.env.QID_SESSION_SECRET,
//     apiPath: "/api/qid",   // REQUIRED on Next, or QR/deep-link proof URLs 404
//   });
//   export const { GET, POST } = qidNextHandlers(qid);
//
// That serves POST /api/qid/challenge, POST /api/qid/verify,
// POST /api/qid/proof, GET /api/qid/poll, GET /api/qid/session,
// POST /api/qid/logout. Remember to pass apiPath: "/api/qid" to
// createQidConnect so QR sign-in points phones at the right proof URL.
//
// SPDX-License-Identifier: MIT

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

const MAX_BODY_BYTES = 64 * 1024; // a v1 proof bundle is about 9 KB

// Read and JSON-parse a request body with a hard size cap, mirroring the
// Express adapter. Vercel caps bodies at its platform limit, but this adapter
// also runs on self-hosted Node/Bun/Deno with no fronting proxy, where an
// uncapped request.json() would buffer an attacker's multi-hundred-MB body into
// memory before parsing (/proof is reachable cross-origin by design). Throws an
// Error with .tooLarge on overflow; returns {} for an empty body so an empty
// POST behaves the same as Express (verify({}) -> 401, not a parse 400).
async function readJsonCapped(request) {
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    const e = new Error("body_too_large");
    e.tooLarge = true;
    throw e;
  }
  const reader = request.body && typeof request.body.getReader === "function"
    ? request.body.getReader()
    : null;
  if (!reader) {
    // No readable stream (already-buffered/test env): fall back, still capped by
    // the declared-length check above.
    const text = await request.text();
    return text ? JSON.parse(text) : {};
  }
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_BODY_BYTES) {
      try { await reader.cancel(); } catch { /* ignore */ }
      const e = new Error("body_too_large");
      e.tooLarge = true;
      throw e;
    }
    chunks.push(value);
  }
  let size = 0;
  for (const c of chunks) size += c.length;
  const buf = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) { buf.set(c, off); off += c.length; }
  const text = new TextDecoder().decode(buf);
  return text ? JSON.parse(text) : {};
}

function getCookie(request, name) {
  const header = request.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

function sessionCookie(qid, token, maxAgeMs) {
  const parts = [
    `${qid.cookieName}=${token}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${Math.floor(maxAgeMs / 1000)}`,
  ];
  if (qid.secureCookies) parts.push("Secure");
  return parts.join("; ");
}

export function qidNextHandlers(qid) {
  async function dispatch(request) {
    const url = new URL(request.url);
    const action = url.pathname.replace(/\/+$/, "").split("/").pop();
    const route = `${request.method} ${action}`;

    try {
      if (route === "POST challenge") {
        // Optional { retire, retireSecret } lets the rotating widget burn the superseded
        // nonce so the acceptance window tracks the short display lifetime. A missing or
        // non-JSON body is the normal first fetch (challenge without retire).
        let retire, retireSecret;
        try {
          const body = await readJsonCapped(request);
          if (body && typeof body.retire === "string") retire = body.retire;
          if (body && typeof body.retireSecret === "string") retireSecret = body.retireSecret;
        } catch (e) {
          if (e && e.tooLarge) return json(400, { ok: false, reason: "body_too_large" });
          /* no body / not JSON: a plain challenge fetch */
        }
        const out = await qid.challenge(undefined, { retire, retireSecret });
        return json(200, out);
      }

      if (route === "POST verify") {
        // Login-CSRF guard, see middleware.js. Reject a present-and-mismatched
        // Origin; /proof stays exempt because it is cross-device.
        const origin = request.headers.get("origin");
        if (origin && origin !== qid.origin) {
          return json(403, { ok: false, reason: "bad_origin" });
        }
        let body;
        try {
          body = await readJsonCapped(request);
        } catch (e) {
          if (e && e.tooLarge) return json(400, { ok: false, reason: "body_too_large" });
          return json(400, { ok: false, reason: "bad_request_body" });
        }
        const proof = body?.proof && typeof body.proof === "object" ? body.proof : body;
        const result = await qid.verify(proof);
        if (!result.ok) return json(401, { ok: false, reason: result.reason });
        return json(
          200,
          { ok: true, address: result.address, account: result.account },
          { "Set-Cookie": sessionCookie(qid, result.token, qid.sessionMaxAgeMs) }
        );
      }

      if (route === "POST proof") {
        let body;
        try {
          body = await readJsonCapped(request);
        } catch (e) {
          if (e && e.tooLarge) return json(400, { ok: false, reason: "body_too_large" });
          return json(400, { ok: false, reason: "bad_request_body" });
        }
        const proof = body?.proof && typeof body.proof === "object" ? body.proof : body;
        const result = await qid.submitProof(proof);
        if (!result.ok) return json(401, { ok: false, reason: result.reason });
        return json(200, { ok: true, address: result.address });
      }

      if (route === "GET poll") {
        // Login-CSRF guard for the cookie-minting path. /poll hands out the same
        // session cookie as /verify, so it needs the same protection. The poll
        // secret does NOT stop login-CSRF: an attacker legitimately holds their
        // own (nonce, secret) and can drive a victim's browser to a cross-site
        // top-level GET of /poll to plant the attacker's session in the victim's
        // browser. The browser marks that request Sec-Fetch-Site: cross-site (or
        // same-site); the widget's own same-origin fetch is marked same-origin.
        // Reject present-and-not-same-origin, mirroring /verify's Origin posture;
        // absent header (non-browser client) is allowed, same as /verify. Reject
        // BEFORE poll() so a hostile poll never claims the nonce out from under
        // the real browser. /proof stays exempt: it is cross-device and mints no
        // cookie. See DESIGN.md and INTEGRATION.md "QR sign-in, what keeps it honest".
        const site = request.headers.get("sec-fetch-site");
        if (site && site !== "same-origin") {
          return json(403, { status: "bad_origin" });
        }
        // Origin fallback so the guard doesn't fail open when a proxy strips
        // Sec-Fetch-Site (mirrors /verify).
        const pollOrigin = request.headers.get("origin");
        if (pollOrigin && pollOrigin !== qid.origin) {
          return json(403, { status: "bad_origin" });
        }
        const result = await qid.poll(url.searchParams.get("nonce"), url.searchParams.get("secret"));
        if (result.status !== "done") return json(200, { status: result.status });
        return json(
          200,
          { status: "done", address: result.address, account: result.account },
          { "Set-Cookie": sessionCookie(qid, result.token, qid.sessionMaxAgeMs) }
        );
      }

      if (route === "GET session") {
        const auth = request.headers.get("authorization");
        const token =
          getCookie(request, qid.cookieName) ||
          (auth?.startsWith("Bearer ") ? auth.slice(7) : null);
        const s = token ? await qid.session(token) : null;
        if (!s) return json(401, { ok: false, reason: "no_session" });
        return json(200, { ok: true, ...s });
      }

      if (route === "POST logout") {
        // Same login-CSRF guard as /verify: block a cross-site forced logout.
        const origin = request.headers.get("origin");
        if (origin && origin !== qid.origin) {
          return json(403, { ok: false, reason: "bad_origin" });
        }
        const parts = [`${qid.cookieName}=`, "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"];
        if (qid.secureCookies) parts.push("Secure");
        return json(200, { ok: true }, { "Set-Cookie": parts.join("; ") });
      }
    } catch {
      return json(500, { ok: false, reason: "server_error" });
    }

    return json(404, { ok: false, reason: "not_found" });
  }

  return { GET: dispatch, POST: dispatch };
}

// getQidSession(qid, request) -> { address, account, expiresAt } | null
//
// For your own server components and route handlers.
export async function getQidSession(qid, request) {
  const auth = request.headers.get("authorization");
  const token =
    getCookie(request, qid.cookieName) || (auth?.startsWith("Bearer ") ? auth.slice(7) : null);
  return token ? qid.session(token) : null;
}
