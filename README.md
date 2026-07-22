# Quantum Reflex

A tiny reaction-time game that showcases **[qID Connect](https://qid.dev)**: play
in 10 seconds, sign in with your BTX wallet (bonuz or PQ), land on a global
leaderboard keyed by your address. No email, no password — **the address is the
account.**

> How fast are your reflexes? Can you out-react a quantum computer?

- **The game:** 5 reaction rounds, `performance.now()` timing, submit the average.
  Tap on mobile, click or spacebar on desktop. No framework, no build step, no assets.
- **The login:** the hosted qID Connect widget (auto-updates). Sign in by scanning
  a QR with the bonuz app or BTX PQ Wallet.
- **The board:** one row per address, best average kept, your row highlighted.
- **Forged relic names:** if you hold a BTX relic you engraved a name into
  (Attribute Archive name-on-chain, or a Last Relic engraving), the game offers
  that name to claim your spot under. qID already proved the address, so the name
  you forged is yours to pick. Best-effort, cached, and completely optional.

## Architecture — one origin, one server

qID's session is a **first-party HttpOnly cookie**, so the page, `/qid/*`, and the
leaderboard API must share an origin. A single `bun` server does all three:

```
GET  /                     public/index.html (the game + board + qID wiring)
POST /qid/challenge|verify|proof   qID Connect (vendored @qid/connect-server)
GET  /qid/poll|session   POST /qid/logout
POST /score                guarded by requireQidSession -> upsert best_ms
GET  /leaderboard          top N by best_ms, + { me } when signed in
GET  /relic-name           guarded -> names the caller forged into relics they hold
GET  /healthz
```

State is durable SQLite (`bun:sqlite`): qID nonces/accounts **and** the `scores`
table live in one db file and survive restarts.

## Run locally

```sh
bun install
bun run dev          # http://localhost:8899  (sets dev origin + a throwaway secret)
```

Then open http://localhost:8899, play a run. To sign in without a phone/wallet,
use the reference signer (below) or the seed script.

## Test

```sh
bun test             # test/e2e.mjs — boots the server and drives the FULL qID flow
                     # with real post-quantum proofs: challenge -> proof -> verify
                     # -> session cookie -> guarded /score -> ranked leaderboard.
```

Seed a running dev server with demo scores (real proofs, like wallets):

```sh
bun test/seed.mjs                 # 8 named/anon players against localhost:8899
```

## Anti-cheat (v1)

The client reports its own ms, so this is deliberately light (build brief §7):
the `80..2000` clamp, one row per address (best kept), a per-address rate limit,
and server-side name sanitizing (angle brackets + control chars stripped; the
client also renders names as `textContent`, never HTML). Upgrade path: gate the
board on a proof-of-personhood check — ties into the anti-Sybil work already in
flight. Not over-built for launch.

## Deploy

See [`deploy/DEPLOY.md`](deploy/DEPLOY.md) — VM + Caddy + systemd on
`play.qid.dev`, same pattern as btc2btx. TLS is automatic; the only rule is
`QID_ORIGIN` must be the exact host the browser lands on.

## Layout

```
server.mjs                 the one server (static + /qid + /score + /leaderboard + /relic-name)
public/index.html          the whole frontend (game, board, qID + relic wiring) — one file
lib/relic-name.mjs         address -> forged relic name (BZA1 name-on-chain + engraving)
vendor/qid-connect-server/ verbatim @qid/connect-server v1.5.2 (see VENDORED.md; do not edit)
test/e2e.mjs               full-flow backend test (real PQ proofs)
test/relic-live.mjs        relic-name decode tests (pure + live btxscan)
test/seed.mjs              demo-data seeder
test/lib/                  the reference signer (buildProof), for tests only
deploy/                    systemd unit, Caddy vhost, env template, DEPLOY.md
```

## Forged relic names (how it works)

qID hands us the verified BTX address, so we can read what the player already put
on chain. `GET /relic-name` (guarded) asks the public, CORS-open holder scan
`btxscan.io/api/relics/holder?address=…` for the relics that address holds, then
resolves each name two ways (both verified against live data):

- **Attribute Archive** (schema 2, "the human layer"): the 32 commitment bytes
  **are** the name — `[len][utf8]`. Decoded locally, no extra call.
- **Last Relic / Genesis** (schema 0): the forged name is the `engraving` in the
  off-chain record, fetched by commitment from `btxscan.io/api/artifact/…`.

It is entirely additive: `QR_RELICS=off`, btxscan down, or "no relics" all just
mean the game falls back to a typed name. Tune with `QR_BTXSCAN` / `QR_RELIC_TTL_MS`
(see `deploy/quantum-reflex.env.example`). Nothing about qID Connect is touched.

## What is NOT modified

The qID Sign-In protocol is **frozen v1**. This project consumes the hosted widget
and the server SDK **as-is** — the vendored server is a verbatim copy, never a
fork, and the verifier is never touched.

---
MIT. Built on qID Connect by [qid.dev](https://qid.dev).
