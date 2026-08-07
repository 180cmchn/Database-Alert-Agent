# syntax=docker/dockerfile:1.7

FROM node:22-alpine AS build

WORKDIR /app
COPY package.json package-lock.json* ./
# Persist npm's downloaded package tarballs between rebuilds. The lockfile still
# controls the installed dependency graph, while a cache miss no longer requires
# downloading every package after the dependency layer is invalidated.
RUN --mount=type=cache,target=/root/.npm \
    npm ci --prefer-offline --no-audit

COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
# This validates the static frontend process itself. `/health/live` remains
# proxied to the API for callers that need the backend liveness signal.
HEALTHCHECK --interval=30s --timeout=3s --start-period=2s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1/health/frontend || exit 1
