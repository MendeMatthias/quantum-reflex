# Ship Quantum Reflex to play.qid.dev on Azure (all in the browser)

The game is a small always-on `bun` server. It runs unchanged on a cheap Azure
VM, and every step here is doable from the **Azure Portal** in the browser
(portal.azure.com). No local terminal needed. Everything is automated by
[`azure-bootstrap.sh`](./azure-bootstrap.sh) — you paste it once.

Why this fixes the login: qID sign-in only completes on a **public** origin,
because the QR tells the wallet to POST the proof back to
`https://play.qid.dev/qid/proof`. On localhost that address is unreachable from a
phone, which is why the dialog just said "Waiting for your wallet." On the real
domain the round trip closes and the scan works.

## 0. Prereqs (one time)
- The repo is already on GitHub and wired into the bootstrap:
  `https://github.com/MendeMatthias/quantum-reflex` (public, no token needed).
- You control DNS for `qid.dev`.

## 1. Create the VM (Portal → Virtual machines → Create)
- Image: **Ubuntu Server 24.04 LTS**. Size: **B1s** or **B2s** (plenty; ~a few $/mo, covered by the grant).
- Authentication: SSH key (you won't need it, but the portal wants one).
- **Networking → open ports: 80, 443** (and 22). Or add them later in the VM's
  Network security group as inbound rules.
- **Advanced → Custom data**: paste the whole `azure-bootstrap.sh`. It runs on
  first boot and sets up everything. (If you skip this, do step 3 instead.)
- Create. Note the VM's **Public IP** on the overview page.

## 2. Point DNS
In your DNS provider for `qid.dev`, add an **A record**:
`play` → the VM's public IP. (Claude can do this in the browser for you; confirm
before committing.) Caddy issues the HTTPS cert automatically once it resolves.

## 3. Run the bootstrap (only if you did NOT use Custom data)
Portal → your VM → **Run command** → **RunShellScript** → paste
`azure-bootstrap.sh` → Run. Takes a couple of minutes. It ends with
`app healthy on :8899` and `== DONE ==`.

## 4. Verify (~1 min after DNS resolves)
- Open `https://play.qid.dev` — the game loads over HTTPS.
- Tap **Sign in with qID**, scan with the bonuz app or PQ Wallet. The scan now
  completes and your address lands on the board.
- If the cert isn't ready yet, wait a minute (Caddy retries) and reload.

## Updating later
Push to the repo, then Portal → Run command → `bash /opt/quantum-reflex/deploy/azure-bootstrap.sh`
(it `git pull`s and restarts). Or just `systemctl restart quantum-reflex` after a pull.

## Notes
- Secret + database live at `/etc/quantum-reflex.env` and
  `/var/lib/quantum-reflex/qr.sqlite` and survive restarts/redeploys.
- `QID_ORIGIN` is pinned to `https://play.qid.dev`. If you ever serve the site on
  a different host, update it in the env file and `systemctl restart quantum-reflex`,
  or qID rejects proofs with `bad_origin`.
- There is **nothing to register on the qID side** — no API key, no app setup.
  qID is keyless; the address is the account. The only requirement is same-origin
  serving, which this gives you.
