#!/usr/bin/env bash
# azure-bootstrap.sh — one-shot provisioner for Quantum Reflex on a fresh Ubuntu
# VM (Azure or any cloud). Installs bun, the app, a hardened systemd service, and
# Caddy with automatic HTTPS for the domain. Idempotent: safe to re-run.
#
# Run it either way (both browser-only via the Azure Portal):
#   * Paste into the VM's "Custom data" (cloud-init) when you create the VM, OR
#   * Portal -> your VM -> Run command -> RunShellScript -> paste -> Run.
#
# Edit the two values below, then it needs no other input. The session secret is
# generated once and kept across re-runs.
#
# SPDX-License-Identifier: MIT
set -euo pipefail

# ---- EDIT THESE TWO ---------------------------------------------------------
DOMAIN="play.qid.dev"
REPO_URL="https://github.com/OWNER/quantum-reflex.git"   # set after the repo exists
# -----------------------------------------------------------------------------

APP=/opt/quantum-reflex
STATE=/var/lib/quantum-reflex
ENV_FILE=/etc/quantum-reflex.env
BUN=/usr/local/bin/bun

echo ">> packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y unzip curl git ca-certificates debian-keyring debian-archive-keyring apt-transport-https

echo ">> bun (system-wide at $BUN)"
if [ ! -x "$BUN" ]; then
  export BUN_INSTALL=/usr/local
  curl -fsSL https://bun.sh/install | bash
fi
"$BUN" --version

echo ">> app user + code"
id quantum-reflex >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin quantum-reflex
if [ -d "$APP/.git" ]; then git -C "$APP" pull --ff-only || true; else rm -rf "$APP"; git clone --depth 1 "$REPO_URL" "$APP"; fi
cd "$APP"
"$BUN" install --production
mkdir -p "$STATE"
chown -R quantum-reflex:quantum-reflex "$APP" "$STATE"

echo ">> env (secret generated once, then preserved)"
if [ ! -f "$ENV_FILE" ]; then
  cat >"$ENV_FILE" <<EOF
QID_ORIGIN=https://$DOMAIN
QID_SESSION_SECRET=$(openssl rand -hex 24)
QID_DB=$STATE/qr.sqlite
QID_HOST=127.0.0.1
QID_PORT=8899
# QR_RELICS=on            # forged relic-name lookup (btxscan). off/0 disables.
EOF
  chmod 600 "$ENV_FILE"
fi

echo ">> systemd service"
cp "$APP/deploy/quantum-reflex.service" /etc/systemd/system/quantum-reflex.service
systemctl daemon-reload
systemctl enable --now quantum-reflex
sleep 1
curl -fsS http://127.0.0.1:8899/healthz && echo "  app healthy on :8899"

echo ">> caddy (automatic HTTPS)"
if ! command -v caddy >/dev/null 2>&1; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' >/etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y
  apt-get install -y caddy
fi
cat >/etc/caddy/Caddyfile <<EOF
$DOMAIN {
	encode zstd gzip
	reverse_proxy 127.0.0.1:8899 {
		header_up Host {host}
		header_up X-Forwarded-Proto {scheme}
	}
}
EOF
systemctl reload caddy || systemctl restart caddy

echo ""
echo "== DONE =="
echo "Point $DOMAIN at this VM's public IP (A record). Caddy issues the TLS cert"
echo "automatically once DNS resolves. Then open https://$DOMAIN"
echo "Logs:   journalctl -u quantum-reflex -f   |   journalctl -u caddy -f"
