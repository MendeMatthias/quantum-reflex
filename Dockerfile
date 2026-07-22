# Quantum Reflex — container image (bun runtime). Works on Azure App Service,
# Azure Container Apps, or any container host. The leaderboard/qID SQLite db is
# written to QID_DB (set to a persistent mount by the host, e.g. App Service
# /home with WEBSITES_ENABLE_APP_SERVICE_STORAGE=true).
FROM oven/bun:1-alpine
WORKDIR /app

# deps first for layer caching (only the 3 pinned crypto libs)
COPY package.json bun.lock ./
RUN bun install --production

COPY . .

# Bind all interfaces so the host can reach it; host overrides QID_ORIGIN,
# QID_SESSION_SECRET, QID_DB, WEBSITES_PORT via app settings.
ENV QID_HOST=0.0.0.0 QID_PORT=8899
EXPOSE 8899

CMD ["bun", "server.mjs"]
