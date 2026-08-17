// middleware.js
//
// Express / Connect / plain node:http adapter for qID Connect. Zero
// dependencies: it is a plain (req, res, next) middleware, so it works with
// any Express version, Connect, or a bare http.createServer.
//
//   import { createQidConnect } from "@qid/connect-server";
//   import { qidMiddleware } from "@qid/connect-server/express";
//
//   const qid = createQidConnect({ origin, sessionSecret });
//   app.use("/qid", qidMiddleware(qid));
//
// Routes (relative to the mount point):
//   POST /challenge   -> { request, challenge, pollSecret }
//   POST /verify      -> { ok, address, account } and sets the session cookie
//   POST /proof       -> remote signer (phone) submits a proof; no cookie
//   GET  /poll        -> ?nonce&secret; browser claims the session when the
//                        remote proof lands; sets the cookie on "done"
//   GET  /session     -> { address, account, expiresAt } or 401
//   POST /logout      -> clears the session cookie
//
// SPDX-License-Identifier: MIT

const MAX_BODY_BYTES = 64 * 1024; // a v1 proof bundle is about 9 KB

function sendJson(res, status, body) {
  const data = JSON.stringify(body);
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(data);
}

// Read and parse a JSON body. Uses req.body when a body parser already ran.
async function readJsonBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) throw new Error("body_too_large");
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text) return {};
  return JSON.parse(text);
}

// Origin allowlist for state-changing browser requests. Present-and-mismatched
// is rejected; absent is allowed (cannot judge, and the proof is still
// origin-bound and single-use).
function originAllowed(req, qid) {
  const o = req.headers?.origin;
  if (o == null || o === "") return true;
  return o === qid.origin;
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

function appendSetCookie(res, cookie) {
  const prev = res.getHeader("Set-Cookie");
  if (!prev) res.setHeader("Set-Cookie", cookie);
  else if (Array.isArray(prev)) res.setHeader("Set-Cookie", [...prev, cookie]);
  else res.setHeader("Set-Cookie", [prev, cookie]);
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

// qidMiddleware(qid, { basePath }) -> (req, res, next)
//
// basePath is only needed when you are NOT mounting under a prefix yourself
// (plain http server). With app.use("/qid", ...) Express strips the prefix.
export function qidMiddleware(qid, { basePath = "" } = {}) {
  return async function qidConnect(req, res, next) {
    let path, query;
    try {
      const url = new URL(req.url, "http://internal");
      path = url.pathname;
      query = url.searchParams;
    } catch {
      path = "/";
      query = new URLSearchParams();
    }
    if (basePath && path.startsWith(basePath)) {
      path = path.slice(basePath.length) || "/";
    }
    const route = `${req.method} ${path.replace(/\/+$/, "") || "/"}`;

    try {
      if (route === "POST /challenge") {
        // Optional { retire: <oldNonce> } lets the rotating widget burn the superseded
        // nonce so the acceptance window tracks the short display lifetime. A missing or
        // non-JSON body is the normal first fetch (challenge without retire).
        let retire, retireSecret;
        try {
          const body = await readJsonBody(req);
          if (body && typeof body.retire === "string") retire = body.retire;
          if (body && typeof body.retireSecret === "string") retireSecret = body.retireSecret;
        } catch {
          /* no body / not JSON: a plain challenge fetch */
        }
        const out = await qid.challenge(undefined, { retire, retireSecret });
        return sendJson(res, 200, out);
      }

      if (route === "POST /verify") {
        // Login-CSRF guard. /verify sets a session cookie for the browser
        // that calls it, so a cross-site page must not be able to POST an
        // attacker's proof into a victim's browser. The widget always calls
        // same-origin, so an Origin header that is present and does not match
        // is a forgery. Absent Origin is allowed (some clients strip it; the
        // proof is still origin-bound and single-use). /proof is exempt on
        // purpose: it is cross-device and legitimately cross-origin.
        if (!originAllowed(req, qid)) {
          return sendJson(res, 403, { ok: false, reason: "bad_origin" });
        }
        let body;
        try {
          body = await readJsonBody(req);
        } catch {
          return sendJson(res, 400, { ok: false, reason: "bad_request_body" });
        }
        const proof = body.proof && typeof body.proof === "object" ? body.proof : body;
        const result = await qid.verify(proof);
        if (!result.ok) return sendJson(res, 401, { ok: false, reason: result.reason });
        appendSetCookie(res, sessionCookie(qid, result.token, qid.sessionMaxAgeMs));
        return sendJson(res, 200, { ok: true, address: result.address, account: result.account });
      }

      if (route === "POST /proof") {
        let body;
        try {
          body = await readJsonBody(req);
        } catch {
          return sendJson(res, 400, { ok: false, reason: "bad_request_body" });
        }
        const proof = body.proof && typeof body.proof === "object" ? body.proof : body;
        const result = await qid.submitProof(proof);
        if (!result.ok) return sendJson(res, 401, { ok: false, reason: result.reason });
        return sendJson(res, 200, { ok: true, address: result.address });
      }

      if (route === "GET /poll") {
        // Login-CSRF guard for the cookie-minting path, same as /verify. /poll
        // hands out the session cookie, and the poll secret does not stop
        // login-CSRF (an attacker holds their own nonce+secret and can drive a
        // victim's browser to a cross-site GET of /poll). The widget's own poll
        // is a same-origin fetch (Sec-Fetch-Site: same-origin); a cross-site
        // navigation is marked cross-site/same-site. Reject present-and-not-same
        // -origin before poll() so a hostile poll never claims the nonce.
        const site = req.headers?.["sec-fetch-site"];
        if (site && site !== "same-origin") {
          return sendJson(res, 403, { status: "bad_origin" });
        }
        // Origin fallback (mirrors /verify) so the guard does not fail open on
        // a proxy that strips Sec-Fetch-Site: a present, mismatched Origin is a
        // forgery. Absent both signals is still allowed (some clients strip
        // them; the single-use nonce + secret remain).
        if (!originAllowed(req, qid)) {
          return sendJson(res, 403, { status: "bad_origin" });
        }
        // `confirm=1` is the user's acceptance of the address poll() reported on the
        // previous call. Without it the server reports the address and mints nothing —
        // see the address confirmation gate in core.js.
        const result = await qid.poll(query.get("nonce"), query.get("secret"), {
          confirm: query.get("confirm") === "1",
        });
        if (result.status === "confirm") {
          return sendJson(res, 200, { status: "confirm", address: result.address });
        }
        if (result.status !== "done") return sendJson(res, 200, { status: result.status });
        appendSetCookie(res, sessionCookie(qid, result.token, qid.sessionMaxAgeMs));
        return sendJson(res, 200, {
          status: "done",
          address: result.address,
          account: result.account,
        });
      }

      if (route === "GET /session") {
        const token =
          getCookie(req, qid.cookieName) ||
          (req.headers?.authorization?.startsWith("Bearer ")
            ? req.headers.authorization.slice(7)
            : null);
        const s = token ? await qid.session(token) : null;
        if (!s) return sendJson(res, 401, { ok: false, reason: "no_session" });
        return sendJson(res, 200, { ok: true, ...s });
      }

      if (route === "POST /logout") {
        // Same login-CSRF guard as /verify: a cross-site page must not be able
        // to force-log-out a visitor. Absent Origin is allowed (some clients
        // strip it); a present, mismatched Origin is a forgery.
        if (!originAllowed(req, qid)) {
          return sendJson(res, 403, { ok: false, reason: "bad_origin" });
        }
        const parts = [`${qid.cookieName}=`, "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"];
        if (qid.secureCookies) parts.push("Secure");
        appendSetCookie(res, parts.join("; "));
        return sendJson(res, 200, { ok: true });
      }
    } catch {
      return sendJson(res, 500, { ok: false, reason: "server_error" });
    }

    if (typeof next === "function") return next();
    return sendJson(res, 404, { ok: false, reason: "not_found" });
  };
}

// requireQidSession(qid) -> (req, res, next)
//
// Guard for your own routes. Attaches req.qidSession = { address, account }
// and returns 401 when there is no valid session.
export function requireQidSession(qid) {
  return async function qidGuard(req, res, next) {
    // Wrap the whole body: a throwing accounts adapter (a transient DB outage on
    // the app's own store) must become a clean 500, not an unhandled promise
    // rejection — Express 4 does not await middleware, so an unhandled rejection
    // would hang the request AND crash the process on Node >= 15. qidMiddleware
    // gets the same treatment; this guard must match it.
    try {
      const token =
        getCookie(req, qid.cookieName) ||
        (req.headers?.authorization?.startsWith("Bearer ")
          ? req.headers.authorization.slice(7)
          : null);
      const s = token ? await qid.session(token) : null;
      if (!s) return sendJson(res, 401, { ok: false, reason: "no_session" });
      req.qidSession = s;
      next();
    } catch {
      return sendJson(res, 500, { ok: false, reason: "server_error" });
    }
  };
}
