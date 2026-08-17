# Build context is the repo root, so the workspace packages resolve.
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/shared/package.json ./packages/shared/
COPY packages/api/package.json ./packages/api/
COPY packages/web/package.json ./packages/web/
# --ignore-scripts skips argon2's native build: the frontend image does not need
# it, and compiling it here would pull in a toolchain for nothing.
RUN npm ci --workspace=@sbom/shared --workspace=@sbom/web --include-workspace-root --ignore-scripts

FROM deps AS build
COPY tsconfig.base.json ./
COPY packages/shared ./packages/shared
COPY packages/web ./packages/web
RUN npm run build --workspace=@sbom/shared \
 && npm run build --workspace=@sbom/web

FROM nginx:1.27-alpine AS runtime
COPY --from=build /app/packages/web/dist /usr/share/nginx/html
COPY packages/web/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q --spider http://127.0.0.1/ || exit 1
