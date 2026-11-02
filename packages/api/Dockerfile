# Build context is the repo root, so the workspace packages resolve.

# Grype comes from its own published image.
#
# Pinned by tag so the binary, and therefore the findings, are reproducible: results
# shift between Grype releases, and the database schema is tied to the binary version
# (0.115.0 supports schema 6). Upgrading is an edit here, not a drift.
#
# Copied from the official image rather than fetched by a script: the image digest is
# the integrity check, so there is no checksum list to keep current and no network call
# inside the build. The vulnerability DATABASE is deliberately not included - it is
# 1.9 GB expanded and Anchore rebuilds it daily, so a baked copy would be stale before
# anyone pulled the image. It lives on a volume and is fetched at runtime.
FROM anchore/grype:v0.115.0 AS grype

# Trivy, the second scanner, the same way: from its official image, pinned by tag.
FROM aquasec/trivy:0.76.1 AS trivy

# osv-scanner, the third. Its image keeps the binary at no stable path, so the release
# binary is fetched instead and checked against the SHA-256 the project publishes in
# osv-scanner_SHA256SUMS - a build that downloads something else stops here.
FROM alpine:3.20 AS osv
ARG TARGETARCH
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) sum=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b ;; \
      arm64) sum=4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7 ;; \
      *) echo "no pinned osv-scanner for ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    wget -qO /osv-scanner "https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_${TARGETARCH:-amd64}"; \
    echo "${sum}  /osv-scanner" | sha256sum -c -; \
    chmod 0755 /osv-scanner

FROM node:22-alpine AS base
WORKDIR /app
# argon2 is a native module and needs a toolchain to compile.
RUN apk add --no-cache python3 make g++

FROM base AS deps
COPY package.json package-lock.json ./
COPY packages/shared/package.json ./packages/shared/
COPY packages/api/package.json ./packages/api/
COPY packages/web/package.json ./packages/web/
RUN npm ci --workspace=@sbom/shared --workspace=@sbom/api --include-workspace-root

FROM deps AS build
COPY tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY packages/api ./packages/api
RUN npm run build --workspace=@sbom/shared \
 && npm run build --workspace=@sbom/api

FROM base AS runtime
ENV NODE_ENV=production
# Drop the build toolchain from the final image.
RUN apk del python3 make g++ || true

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/packages/shared/package.json ./packages/shared/package.json
COPY --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --from=build /app/packages/api/package.json ./packages/api/package.json
COPY --from=build /app/packages/api/dist ./packages/api/dist
# Migrations are shipped with the image so `db:migrate` runs the exact set the
# code was built against.
COPY --from=build /app/packages/api/drizzle ./packages/api/drizzle

# The scanners. On PATH, so binary resolution finds them without configuration. Their
# findings are merged; see packages/api/src/services/scanner/merge.ts.
COPY --from=grype /grype /usr/local/bin/grype
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=osv /osv-scanner /usr/local/bin/osv-scanner

# Raw SBOM blobs and the vulnerability database both live on mounted volumes, not in
# image layers. The database directory is created here so a first start with the volume
# mounted does not have to make it as an unprivileged user.
RUN mkdir -p /data/sboms /data/grype-db /data/trivy-db /data/osv-db && chown -R node:node /data
USER node
WORKDIR /app/packages/api

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Migrate then serve. Migrations are transactional and idempotent, so a restart
# or a second replica starting concurrently is safe.
CMD ["sh", "-c", "node dist/db/migrate.js && node dist/db/seed.js && node dist/server.js"]
