#!/bin/sh
set -eu

log() {
  printf "[caddy-entrypoint] %s\n" "$*"
}

mkdir -p /tmp/caddy-data /tmp/caddy-config

# Basic diagnostics to stdout for ACI logs
log "id: $(id)"
log "pwd: $(pwd)"
log "ls /etc/caddy:"
ls -la /etc/caddy || true
log "ls /tmp:"
ls -ld /tmp /tmp/caddy-data /tmp/caddy-config || true
log "CADDY_DOMAIN=${CADDY_DOMAIN:-}"
log "ACME_EMAIL=${ACME_EMAIL:-}"
log "CADDY_DEBUG_IDLE=${CADDY_DEBUG_IDLE:-}"

if grep -q "__ACME_GLOBAL__" /etc/caddy/Caddyfile; then
  if [ -n "${ACME_EMAIL:-}" ]; then
    log "Injecting ACME email into Caddyfile"
    awk -v email="$ACME_EMAIL" '
      $0=="__ACME_GLOBAL__" { print "{\n  email " email "\n}\n"; next }
      { print }
    ' /etc/caddy/Caddyfile > /tmp/Caddyfile && mv /tmp/Caddyfile /etc/caddy/Caddyfile
  else
    log "ACME_EMAIL empty; removing global ACME block"
    awk '
      $0=="__ACME_GLOBAL__" { next }
      { print }
    ' /etc/caddy/Caddyfile > /tmp/Caddyfile && mv /tmp/Caddyfile /etc/caddy/Caddyfile
  fi
fi

if grep -q "__CADDY_DOMAIN__" /etc/caddy/Caddyfile; then
  if [ -n "${CADDY_DOMAIN:-}" ]; then
    log "Substituting __CADDY_DOMAIN__ from env"
    sed -i "s|__CADDY_DOMAIN__|${CADDY_DOMAIN}|g" /etc/caddy/Caddyfile
  else
    log "CADDY_DOMAIN empty; placeholder left in Caddyfile"
  fi
fi

log "Caddyfile:"
cat /etc/caddy/Caddyfile || true

if [ "${CADDY_DEBUG_IDLE:-}" = "1" ]; then
  log "Debug idle enabled; sleeping for exec access."
  tail -f /dev/null
fi

log "Validating Caddyfile..."
if ! caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile; then
  log "Caddyfile validation failed; sleeping for exec access."
  tail -f /dev/null
fi

log "Starting Caddy..."
exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
