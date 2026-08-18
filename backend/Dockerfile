# V2.0-F (docs/V2_0_F_PRODUCTION_READINESS.md): a reference container image.
# This is a starting point for a real deployment, not a claim that
# containerizing this app makes it production-ready by itself -- see that
# doc for everything still missing (managed secrets, external object
# storage, a networked database, etc.) regardless of how it's packaged.
#
# IMPORTANT: build context must be the REPO ROOT (not backend/), since the
# server also serves the static frontend from ../../frontend/public
# relative to backend/src/server.js -- the image mirrors that same
# relative layout under /app so no code needs to change for containerized
# vs local-dev paths. Build from the repo root:
#   docker build -f backend/Dockerfile -t legacy-pulse .

FROM node:22-slim AS build
WORKDIR /app/backend
COPY backend/package*.json ./
# better-sqlite3 needs build tools to compile its native binding.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
  && npm ci --omit=dev \
  && apt-get purge -y python3 make g++ \
  && apt-get autoremove -y \
  && rm -rf /var/lib/apt/lists/*
COPY backend/src ./src

FROM node:22-slim
WORKDIR /app
# Runs as a non-root user -- the image never needs root privileges at
# runtime, only during the build step above.
RUN useradd --create-home --shell /bin/false appuser
COPY --from=build /app/backend/node_modules ./backend/node_modules
COPY --from=build /app/backend/src ./backend/src
COPY backend/package*.json ./backend/
COPY frontend/public ./frontend/public
RUN mkdir -p /app/backend/data /app/backend/uploads && chown -R appuser:appuser /app
USER appuser

WORKDIR /app/backend
ENV NODE_ENV=production
EXPOSE 4000

# The image intentionally does NOT bake in any secret. All of
# JWT_ACCESS_SECRET / JWT_REFRESH_SECRET / DATA_ENCRYPTION_KEY must be
# supplied at runtime (see .env.example) -- see
# docs/V2_0_F_PRODUCTION_READINESS.md for why baking secrets into an image
# or docker-compose.yml is exactly the anti-pattern a real deployment
# needs a secrets manager to avoid.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "require('http').get('http://localhost:4000/api/health', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "src/server.js"]
