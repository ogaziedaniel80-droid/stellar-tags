# syntax=docker/dockerfile:1

# Shared npm settings for every stage: no audit/fund noise, and generous
# retry/timeout values so the long install steps survive a flaky registry.
FROM node:20-alpine AS base
WORKDIR /app
ENV NPM_CONFIG_AUDIT=false \
	NPM_CONFIG_FUND=false \
	NPM_CONFIG_FETCH_RETRIES=5 \
	NPM_CONFIG_FETCH_RETRY_MINTIMEOUT=20000 \
	NPM_CONFIG_FETCH_RETRY_MAXTIMEOUT=120000 \
	NPM_CONFIG_FETCH_TIMEOUT=600000

# --- Backend dependency layer -------------------------------------------------
# Only the two manifests and the Prisma schema are copied into this stage, so
# the install layer is invalidated by dependency or schema changes alone —
# editing server code or adding a migration reuses the cached install.
#   * `npm ci` installs strictly from package-lock.json (deterministic, never
#     rewrites the lockfile) instead of resolving a fresh tree like `npm install`.
#   * `--omit=dev` keeps jest / supertest / tsx out of the runtime image.
#   * the BuildKit cache mount reuses npm's download cache across builds without
#     baking it into any layer.
FROM base AS backend-deps
COPY stellar-payment-platform/package.json stellar-payment-platform/package-lock.json ./
COPY stellar-payment-platform/prisma/schema.prisma ./prisma/schema.prisma
RUN --mount=type=cache,id=npm-cache,target=/root/.npm \
	npm ci --omit=dev --no-audit --no-fund \
	&& ./node_modules/.bin/prisma generate

# --- Backend runtime ----------------------------------------------------------
FROM base AS backend
ENV NODE_ENV=production

# Runtime write targets (LOG_DIR and the sqlite fallback DB) are created up
# front and owned by the unprivileged `node` user that ships with the image.
# /app/certs is the mount point for internal PKI material when mTLS is enabled
# (see docker-compose.yml); certificates arrive as a volume, never as a layer.
RUN mkdir -p /app/logs /app/data /app/certs \
	&& chown node:node /app/logs /app/data /app/certs

# Production-only dependency tree, Prisma client already generated above.
# `--chown` avoids a later `chown -R`, which would copy every node_modules file
# into a new layer and undo the size win.
COPY --from=backend-deps --chown=node:node /app/node_modules ./node_modules
# Application source. node_modules and tests are dropped by .dockerignore, so
# the build context only carries what the API reads at runtime.
COPY --chown=node:node stellar-payment-platform/ ./

USER node
ENV MTLS_CERT_DIR=/app/certs
EXPOSE 5000
CMD ["node", "server.js"]

# --- Frontend build -----------------------------------------------------------
FROM base AS frontend-build
COPY payment-dashboard/package*.json ./
RUN apk add --no-cache python3 make g++ linux-headers libusb-dev eudev-dev
RUN --mount=type=cache,id=npm-cache,target=/root/.npm \
	npm install --registry=https://registry.yarnpkg.com/ --no-audit --no-fund --fetch-retries=5 --fetch-retry-mintimeout=20000 --fetch-retry-maxtimeout=120000 --fetch-timeout=600000
COPY payment-dashboard/ ./
ARG VITE_API_BASE=http://localhost:5000
ENV VITE_API_BASE=$VITE_API_BASE
RUN npm run build

# --- Frontend serve -----------------------------------------------------------
FROM nginx:alpine AS frontend
COPY --from=frontend-build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80

# --- Frontend serve, proxying to the API over mTLS (#736) --------------------
# Same static build; the only difference is the proxy configuration, which
# presents the edge service certificate and verifies the API's. The placeholders
# are substituted from the environment when the container starts, so the
# defaults below are what run if nothing is overridden.
FROM nginx:alpine AS frontend-mtls
ENV MTLS_CA_BUNDLE=ca-bundle.crt \
	MTLS_EDGE_CERT=services/edge.crt \
	MTLS_EDGE_KEY=services/edge.key \
	MTLS_BACKEND_NAME=backend \
	MTLS_BACKEND_PORT=5000
# Only ${MTLS_*} placeholders are substituted; $host, $uri and friends stay.
ENV NGINX_ENVSUBST_FILTER=MTLS_
COPY --from=frontend-build /app/dist /usr/share/nginx/html
COPY nginx-mtls.conf /etc/nginx/templates/default.conf.template
EXPOSE 80
