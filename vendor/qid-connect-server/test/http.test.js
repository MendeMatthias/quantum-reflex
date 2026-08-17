// Drives the real HTTP surface end to end, twice: once through the node
// middleware (Express compatible) on a live http server, once through the
// Next.js handlers with Web Request objects. The proof comes from the
// wallet-authentic signer.

import { test, expect } from "bun:test";
import { createServer } from "node:http";
import { once } from "node:events";

import { createQidConnect } from "../src/core.js";
import { qidMiddleware, requireQidSession } from "../src/middleware.js";
import { qidNextHandlers } from "../src/next.js";
import { buildProof } from "../../../tools/signer/btx-sign-ownership.mjs";

const secret = "test-secret-test-secret-test-secret-test";

function freshSeed() {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  return seed;
}

test("node middleware: full flow over a live http server", async () => {
  const qid = createQidConnect({ origin: "http://localhost", sessionSecret: secret });
  const server = createServer(qidMiddleware(qid, { basePath: "/qid" }));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const base = `http://127.0.0.1:${server.address().port}`;

  try {
    // 1. challenge
    const chRes = await fetch(`${base}/qid/challenge`, { method: "POST" });
    expect(chRes.status).toBe(200);
    const { challenge, request } = await chRes.json();
    expect(request.type).toBe("signin");

    // 2. wallet signs
    const proof = buildProof(freshSeed(), challenge);

    // 2b. login-CSRF guard: a proof POSTed with a foreign Origin is refused
    const csrf = await fetch(`${base}/qid/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://evil.example" },
      body: JSON.stringify({ proof }),
    });
    expect(csrf.status).toBe(403);
    expect((await csrf.json()).reason).toBe("bad_origin");

    // 3. verify, session cookie comes back (matching Origin is accepted)
    const vRes = await fetch(`${base}/qid/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "http://localhost" },
      body: JSON.stringify({ proof }),
    });
    expect(vRes.status).toBe(200);
    const verdict = await vRes.json();
    expect(verdict.ok).toBe(true);
    expect(verdict.address).toBe(proof.address);
    const setCookie = vRes.headers.get("set-cookie");
    expect(setCookie).toContain("qid_session=");
    expect(setCookie).toContain("HttpOnly");
    const cookie = setCookie.split(";")[0];

    // 4. session resolves with the cookie
    const sRes = await fetch(`${base}/qid/session`, { headers: { cookie } });
    expect(sRes.status).toBe(200);
    const session = await sRes.json();
    expect(session.address).toBe(proof.address);

    // 5. no cookie means no session
    const anon = await fetch(`${base}/qid/session`);
    expect(anon.status).toBe(401);

    // 6. replay is rejected
    const replay = await fetch(`${base}/qid/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ proof }),
    });
    expect(replay.status).toBe(401);

    // 7. logout: a cross-site forced logout is refused (login-CSRF guard),
    //    a same-origin (or Origin-less) logout clears the cookie.
    const csrfLogout = await fetch(`${base}/qid/logout`, {
      method: "POST",
      headers: { Origin: "https://evil.example" },
    });
    expect(csrfLogout.status).toBe(403);
    expect((await csrfLogout.json()).reason).toBe("bad_origin");
    const outRes = await fetch(`${base}/qid/logout`, { method: "POST" });
    expect(outRes.headers.get("set-cookie")).toContain("Max-Age=0");

    // 8. QR flow over HTTP: new challenge, phone posts to /proof, browser
    // polls /poll and receives the session cookie
    const ch2 = await (await fetch(`${base}/qid/challenge`, { method: "POST" })).json();
    const pending = await (
      await fetch(`${base}/qid/poll?nonce=${ch2.challenge.nonce}&secret=${ch2.pollSecret}`)
    ).json();
    expect(pending.status).toBe("pending");

    const phoneProof = buildProof(freshSeed(), ch2.challenge);
    const phoneRes = await fetch(`${base}/qid/proof`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ proof: phoneProof }),
    });
    expect(phoneRes.status).toBe(200);
    expect(phoneRes.headers.get("set-cookie")).toBeNull(); // phone gets no session

    // F1 regression: a CROSS-SITE poll (the login-CSRF vector) is refused BEFORE
    // it can claim the done nonce, and hands out no session cookie. The proof is
    // parked (status done) but the hostile poll must not pick it up.
    const csrfPoll = await fetch(
      `${base}/qid/poll?nonce=${ch2.challenge.nonce}&secret=${ch2.pollSecret}`,
      { headers: { "Sec-Fetch-Site": "cross-site" } }
    );
    expect(csrfPoll.status).toBe(403);
    expect((await csrfPoll.json()).status).toBe("bad_origin");
    expect(csrfPoll.headers.get("set-cookie")).toBeNull();

    // The real browser polls same-origin and is shown the address to accept — no
    // cookie yet. Nothing binds /proof to this browser (a bystander who reads the
    // nonce off the QR can park their own address), so the human confirms first.
    const confirmRes = await fetch(
      `${base}/qid/poll?nonce=${ch2.challenge.nonce}&secret=${ch2.pollSecret}`,
      { headers: { "Sec-Fetch-Site": "same-origin" } }
    );
    const toConfirm = await confirmRes.json();
    expect(toConfirm.status).toBe("confirm");
    expect(toConfirm.address).toBe(phoneProof.address);
    expect(confirmRes.headers.get("set-cookie")).toBeNull();

    // Only after confirm=1 is the session minted.
    const pollRes = await fetch(
      `${base}/qid/poll?nonce=${ch2.challenge.nonce}&secret=${ch2.pollSecret}&confirm=1`,
      { headers: { "Sec-Fetch-Site": "same-origin" } }
    );
    const claimed = await pollRes.json();
    expect(claimed.status).toBe("done");
    expect(claimed.address).toBe(phoneProof.address);
    expect(pollRes.headers.get("set-cookie")).toContain("qid_session=");
  } finally {
    server.close();
  }
});

test("next handlers: full flow with Web Requests", async () => {
  const qid = createQidConnect({ origin: "https://demo.qid.example", sessionSecret: secret });
  const { GET, POST } = qidNextHandlers(qid);
  const base = "https://demo.qid.example/api/qid";

  const chRes = await POST(new Request(`${base}/challenge`, { method: "POST" }));
  expect(chRes.status).toBe(200);
  const { challenge } = await chRes.json();

  const proof = buildProof(freshSeed(), challenge);
  const vRes = await POST(
    new Request(`${base}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ proof }),
    })
  );
  expect(vRes.status).toBe(200);
  const verdict = await vRes.json();
  expect(verdict.address).toBe(proof.address);
  const setCookie = vRes.headers.get("set-cookie");
  expect(setCookie).toContain("qid_session=");
  expect(setCookie).toContain("Secure");
  const cookie = setCookie.split(";")[0];

  const sRes = await GET(new Request(`${base}/session`, { headers: { cookie } }));
  expect(sRes.status).toBe(200);
  expect((await sRes.json()).address).toBe(proof.address);

  const bad = await GET(new Request(`${base}/nope`));
  expect(bad.status).toBe(404);
});

test("node middleware: POST /challenge with { retire } burns the superseded nonce (v2 Job A)", async () => {
  const qid = createQidConnect({ origin: "http://localhost", sessionSecret: secret });
  const server = createServer(qidMiddleware(qid, { basePath: "/qid" }));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const base = `http://127.0.0.1:${server.address().port}`;

  try {
    // First fetch has no body — the normal case must keep working.
    const first = await (await fetch(`${base}/qid/challenge`, { method: "POST" })).json();

    // Rotation: the widget passes the superseded nonce as { retire } plus its
    // poll secret (proof the caller was the browser that was issued the nonce).
    const second = await (
      await fetch(`${base}/qid/challenge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ retire: first.challenge.nonce, retireSecret: first.pollSecret }),
      })
    ).json();
    expect(second.challenge.nonce).not.toBe(first.challenge.nonce);

    // The retired request no longer verifies; the fresh one does.
    const stale = await fetch(`${base}/qid/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ proof: buildProof(freshSeed(), first.challenge) }),
    });
    expect(stale.status).toBe(401);
    expect((await stale.json()).reason).toBe("nonce_unknown");

    const fresh = await fetch(`${base}/qid/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ proof: buildProof(freshSeed(), second.challenge) }),
    });
    expect(fresh.status).toBe(200);
  } finally {
    server.close();
  }
});

test("next handlers: POST challenge with { retire } burns the superseded nonce (v2 Job A)", async () => {
  const qid = createQidConnect({ origin: "https://demo.qid.example", sessionSecret: secret });
  const { POST } = qidNextHandlers(qid);
  const base = "https://demo.qid.example/api/qid";

  const first = await (await POST(new Request(`${base}/challenge`, { method: "POST" }))).json();
  const second = await (
    await POST(
      new Request(`${base}/challenge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ retire: first.challenge.nonce, retireSecret: first.pollSecret }),
      })
    )
  ).json();
  expect(second.challenge.nonce).not.toBe(first.challenge.nonce);

  const stale = await POST(
    new Request(`${base}/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ proof: buildProof(freshSeed(), first.challenge) }),
    })
  );
  expect(stale.status).toBe(401);
  expect((await stale.json()).reason).toBe("nonce_unknown");
});

test("requireQidSession returns 500 (not an unhandled rejection) when the accounts adapter throws", async () => {
  // A transient DB outage in the app's own accounts store must become a clean
  // 500, never a hung request + process-crashing unhandled rejection on Express 4.
  const throwingAccounts = {
    async getOrCreate() { throw new Error("db down"); },
    async get() { throw new Error("db down"); },
  };
  const qid = createQidConnect({
    origin: "http://localhost",
    sessionSecret: secret,
    accounts: throwingAccounts,
  });
  // Mint a real, validly-signed session token so session() reaches accounts.get().
  const { challenge } = await qid.challenge();
  // getOrCreate throws during verify, so sign a token directly via the verify path
  // is not possible here; instead drive the guard with a hand-made valid cookie by
  // signing a session for a known address through the (non-throwing) token signer.
  // qid.session() calls accounts.get(), which throws — exactly the path under test.
  const proof = buildProof(freshSeed(), challenge);
  // submitProof -> verify -> accounts.getOrCreate throws, so build the token another
  // way: call the low-level session signer via a fresh qid with in-memory accounts,
  // reusing the same secret so the throwing-qid accepts the token.
  const signerQid = createQidConnect({ origin: "http://localhost", sessionSecret: secret });
  const okChallenge = (await signerQid.challenge()).challenge;
  const okVerify = await signerQid.verify(buildProof(freshSeed(), okChallenge));
  expect(okVerify.ok).toBe(true);
  const token = okVerify.token;

  const guard = requireQidSession(qid);
  const req = { headers: { cookie: `qid_session=${token}` } };
  let status = null;
  let body = null;
  const res = {
    statusCode: 200,
    setHeader() {},
    end(data) { status = this.statusCode; body = JSON.parse(data); },
  };
  let threw = false;
  try {
    await guard(req, res, () => { throw new Error("next should not be called on adapter throw"); });
  } catch {
    threw = true;
  }
  expect(threw).toBe(false); // the guard must not reject
  expect(status).toBe(500);
  expect(body.reason).toBe("server_error");
  void proof;
});

test("next handlers: an oversized proof body is rejected with 400 body_too_large", async () => {
  const qid = createQidConnect({ origin: "https://demo.qid.example", sessionSecret: secret });
  const { POST } = qidNextHandlers(qid);
  const base = "https://demo.qid.example/api/qid";
  const huge = "x".repeat(70 * 1024); // > 64 KB cap
  const res = await POST(
    new Request(`${base}/proof`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ blob: huge }),
    })
  );
  expect(res.status).toBe(400);
  expect((await res.json()).reason).toBe("body_too_large");
});
