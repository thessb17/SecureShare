# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# SecureShare frontend image - build the Vite bundle, serve it from nginx.
#
# The bundle is static: it contains no secrets and no API credentials. Every
# request to /api is made with a relative path, so the edge proxy decides
# where the backend lives. Nothing here needs to know the API host.
# ---------------------------------------------------------------------------

FROM node:20-alpine AS builder

WORKDIR /build

# Copy manifests first so the dependency layer caches independently of source.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# tsc -b runs first (see package.json "build"), so a type error fails the image
# build rather than shipping a broken bundle.
RUN npm run build


# ---------------------------------------------------------------------------
FROM nginx:1.27-alpine AS runtime

# nginx:alpine ships an "nginx" user (uid 101). Run as it, not root.
# The stock image writes its pid to /var/run and caches to /var/cache/nginx,
# both of which must be writable by that account.
RUN rm -f /etc/nginx/conf.d/default.conf \
    && mkdir -p /var/cache/nginx /var/run \
    && chown -R nginx:nginx /var/cache/nginx /var/run /usr/share/nginx/html

COPY --chown=nginx:nginx nginx.conf /etc/nginx/conf.d/frontend.conf
COPY --from=builder --chown=nginx:nginx /build/dist /usr/share/nginx/html

USER nginx

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
    CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
