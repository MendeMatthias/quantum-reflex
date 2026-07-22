#!/usr/bin/env bash
# Redeploy the latest code to the EXISTING Quantum Reflex App Service app,
# keeping the app name and the play.qid.dev domain/SSL binding. Rebuilds the
# container image from GitHub (server-side ACR build) under a fresh tag so App
# Service is forced to pull it, repoints the app, and restarts.
#
# Run in Azure Cloud Shell:
#   curl -fsSL https://raw.githubusercontent.com/MendeMatthias/quantum-reflex/main/deploy/appservice-update.sh | bash
#
# SPDX-License-Identifier: MIT
set -euo pipefail

RG=quantum-reflex
APP=quantum-reflex-d03ed3
ACR=qracrd03ed3
REPO=https://github.com/MendeMatthias/quantum-reflex.git
TAG=$(date +%s)

echo ">> building $ACR/quantum-reflex:$TAG from GitHub ..."
az acr build -r "$ACR" -t "quantum-reflex:$TAG" "$REPO" -o none

LS=$(az acr show -n "$ACR" --query loginServer -o tsv)
PW=$(az acr credential show -n "$ACR" --query "passwords[0].value" -o tsv)

echo ">> pointing $APP at :$TAG and restarting ..."
az webapp config container set -g "$RG" -n "$APP" \
  --container-image-name "$LS/quantum-reflex:$TAG" \
  --container-registry-url "https://$LS" \
  --container-registry-user "$ACR" \
  --container-registry-password "$PW" -o none
az webapp restart -g "$RG" -n "$APP" -o none

echo "== UPDATED $APP to :$TAG =="
echo "Give it ~30-60s to pull + boot, then hard-refresh https://play.qid.dev"
