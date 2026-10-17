# SentinelASM frontend — multi-stage: compile the Vite SPA, serve dist/ via
# the UNPRIVILEGED nginx variant (runs as uid 101, binds 8080/8443 only).

# Base digest pinned via the Docker Hub registry v2 API (multi-arch manifest
# list digest for the tag): node:20-alpine.
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# nginxinc/nginx-unprivileged (tag 1.27-alpine, digest = manifest list from
# the registry API): no root, no privileged ports inside the container.
FROM nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0 AS runtime

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

# Explicit even though the base image already defaults to it.
USER nginx

EXPOSE 8080

# The runtime image has no HTTP CLI tools beyond busybox wget; port 8080 is
# the unprivileged listener (see nginx.conf).
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://localhost:8080/ || exit 1
