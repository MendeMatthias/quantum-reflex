#!/usr/bin/env bash
# appservice-deploy.sh — deploy Quantum Reflex to Azure App Service as a bun
# container. Runs entirely in Azure Cloud Shell (no local Docker): ACR builds
# the image from the public GitHub repo, App Service runs it. App Service uses
# pooled capacity, so it works on grant subs where `az vm create` is blocked.
#
# Prereqs (already done once): resource group `quantum-reflex` + Linux plan
# `qr-plan` exist. Run:
#   curl -fsSL https://raw.githubusercontent.com/MendeMatthias/quantum-reflex/main/deploy/appservice-deploy.sh | bash
#
# SPDX-License-Identifier: MIT
set -euo pipefail

RG=quantum-reflex
PLAN=qr-plan
LOC=eastus
REPO=https://github.com/MendeMatthias/quantum-reflex.git
SUF=$(openssl rand -hex 3)
ACR=qracr$SUF
APP=quantum-reflex-$SUF

echo ">> [1/5] container registry: $ACR"
az acr create -g "$RG" -n "$ACR" --sku Basic --admin-enabled true -l "$LOC" -o none

echo ">> [2/5] building image from GitHub (server-side ACR build) ..."
az acr build -r "$ACR" -t quantum-reflex:1 "$REPO" -o none

LS=$(az acr show -n "$ACR" --query loginServer -o tsv)
PW=$(az acr credential show -n "$ACR" --query "passwords[0].value" -o tsv)

echo ">> [3/5] web app: $APP"
az webapp create -g "$RG" -p "$PLAN" -n "$APP" -i "$LS/quantum-reflex:1" -o none
az webapp config container set -g "$RG" -n "$APP" \
  --container-image-name "$LS/quantum-reflex:1" \
  --container-registry-url "https://$LS" \
  --container-registry-user "$ACR" \
  --container-registry-password "$PW" -o none

echo ">> [4/5] app settings"
az webapp config appsettings set -g "$RG" -n "$APP" --settings \
  WEBSITES_PORT=8899 \
  WEBSITES_ENABLE_APP_SERVICE_STORAGE=true \
  QID_ORIGIN=https://play.qid.dev \
  QID_SESSION_SECRET="$(openssl rand -hex 24)" \
  QID_HOST=0.0.0.0 QID_PORT=8899 QID_DB=/home/data/qr.sqlite -o none

echo ">> [5/5] restart"
az webapp restart -g "$RG" -n "$APP" -o none

echo ""
echo "== DEPLOYED =="
echo "APP_NAME=$APP"
echo "DEFAULT_URL=https://$APP.azurewebsites.net"
echo "ACR=$ACR"
echo "(QID_ORIGIN is pinned to https://play.qid.dev; the game works on the"
echo " default URL, but qID sign-in only completes on play.qid.dev.)"
