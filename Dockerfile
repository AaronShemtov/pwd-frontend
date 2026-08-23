# syntax=docker/dockerfile:1.7

# nginx-unprivileged runs as UID 101 — required to pass restricted PodSecurityStandard.
# Same image we use for the urlshortener-frontend, so OKE nodes already have it cached.
FROM nginxinc/nginx-unprivileged:1.27-alpine

# Replace the default site config with ours (healthcheck, MIME types,
# security headers and a strict Content-Security-Policy).
COPY --chown=nginx:nginx nginx.conf /etc/nginx/conf.d/default.conf

# Copy all static assets — single COPY of the whole public/ folder, so
# public/js/ and public/pwd.css come along without listing them here.
# To add new assets, drop them into public/ in the repo and rebuild.
COPY --chown=nginx:nginx public/ /usr/share/nginx/html/

EXPOSE 8080
