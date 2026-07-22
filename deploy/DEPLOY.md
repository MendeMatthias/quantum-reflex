# Deploying Quantum Reflex to play.qid.dev

The recommended shape (build brief §3): **one small server** on a VM that serves
the page **and** `/qid/*` **and** the leaderboard API, all on the single origin
`https://play.qid.dev`, with Caddy terminating TLS in front. Same origin is what
makes the first-party qID session cookie work.

```
browser ──https──▶ Caddy (play.qid.dev, TLS) ──http──▶ bun server 127.0.0.1:8899
                                                          ├─ /              index.html
                                                          ├─ /qid/*         qID Connect
                                                          └─ /score,/leaderboard
```

## What runs where
- **DNS (browser / dashboard):** point `play.qid.dev` at the VM. Claude can do
  this in the DNS provider's web console, but must **confirm before committing**
  the record (it is outward-facing and not trivially reversible).
- **VM shell (Mende runs this):** the agent's `ssh` / `az vm run-command` are
  classifier-blocked, so the box steps below are run by hand. Everything is
  copy-paste.

## 0. DNS
Create an `A` (and `AAAA` if you have IPv6) record:
`play.qid.dev` → the VM's public IP. Wait for it to resolve (`dig +short play.qid.dev`).

## 1. Put the code on the box
```sh
sudo mkdir -p /opt/quantum-reflex
sudo chown "$USER" /opt/quantum-reflex
# from your machine (rsync the project, excluding local state):
rsync -av --exclude node_modules --exclude data \
  /path/to/quantum-reflex/ user@vm:/opt/quantum-reflex/
```

## 2. Prereqs + install deps
```sh
# bun (if not present) and unzip (bun install needs it on a bare box)
sudo apt-get update && sudo apt-get install -y unzip
curl -fsSL https://bun.sh/install | bash    # or copy an existing bun binary
sudo ln -sf "$HOME/.bun/bin/bun" /usr/local/bin/bun

cd /opt/quantum-reflex
bun install --production
```
`node_modules` is only the 3 pinned crypto libs; the qID server is vendored in
`vendor/` and imported by path, so there is nothing to pull from the lab.

## 3. Service user + secrets
```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin quantum-reflex || true
sudo chown -R quantum-reflex:quantum-reflex /opt/quantum-reflex

sudo cp deploy/quantum-reflex.env.example /etc/quantum-reflex.env
sudo sed -i "s/CHANGE_ME/$(openssl rand -hex 24)/" /etc/quantum-reflex.env
sudo chmod 600 /etc/quantum-reflex.env
# confirm QID_ORIGIN=https://play.qid.dev in that file
```

## 4. systemd
```sh
sudo cp deploy/quantum-reflex.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now quantum-reflex
systemctl status quantum-reflex --no-pager
curl -fsS http://127.0.0.1:8899/healthz     # -> ok
```

## 5. Caddy (TLS + reverse proxy)
```sh
# install caddy if needed (https://caddyserver.com/docs/install), then:
sudo tee -a /etc/caddy/Caddyfile < deploy/Caddyfile
sudo systemctl reload caddy
```
Caddy fetches the cert automatically once DNS resolves.

## 6. Verify the public origin
```sh
curl -fsS https://play.qid.dev/healthz               # -> ok
curl -fsS https://play.qid.dev/leaderboard           # -> {"ok":true,...}
```
Open `https://play.qid.dev` in a browser, DevTools console:
`location.origin` must print exactly `https://play.qid.dev`. If the site
redirects apex/www or adds a trailing host, set `QID_ORIGIN` to the FINAL value
and `systemctl restart quantum-reflex`. The server also warns about this at boot
(`journalctl -u quantum-reflex`).

## Done when
Open `https://play.qid.dev` on a phone, play 5 rounds, tap **Sign in with qID**,
scan with the bonuz app, and your address lands on the leaderboard — still there
on reload.

---

## Alternative: fully browser-managed (Vercel + Turso)
If you want zero shell, the brief's plan B is Vercel functions + a hosted libSQL
(Turso) db, served same-origin. That is a different runtime shape (serverless
handlers instead of one long-lived `node:http` server, `@libsql/client` instead
of `bun:sqlite`) — a port, not a lift-and-shift. The VM path above is smaller and
is what this repo is wired for. Ask if you want the Vercel port instead.
