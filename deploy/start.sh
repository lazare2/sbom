#!/usr/bin/env sh
#
# Starts the SBOM Platform on an offline machine. Linux / macOS.
#
# Loads the bundled container images, generates per-deployment secrets on the
# first run, and brings the stack up. Safe to run repeatedly.
#
# Requires only Docker. No internet, no Node, no PostgreSQL install.
#
#   ./start.sh              # port 8080
#   SBOM_PORT=9000 ./start.sh
#
# POSIX sh on purpose: a minimal container host may not have bash.

set -eu

cd "$(dirname "$0")"

PORT="${SBOM_PORT:-8080}"

step() { printf '\033[36m==> %s\033[0m\n' "$1"; }
note() { printf '    \033[90m%s\033[0m\n' "$1"; }
fail() { printf '\033[31m%s\033[0m\n' "$1" >&2; }

# --- preflight -------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  fail "Docker is not installed, or docker is not on PATH."
  fail "Install Docker Engine or Docker Desktop and run this again."
  exit 1
fi

# Catches the common case of the CLI being present while the daemon is stopped,
# which would otherwise surface as a confusing error much later.
if ! docker info >/dev/null 2>&1; then
  fail "Docker is installed but the daemon is not running or is not reachable."
  fail "Try: sudo systemctl start docker   (or start Docker Desktop)"
  fail "If docker needs sudo on this machine, run: sudo ./start.sh"
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  fail "'docker compose' is unavailable. This needs Compose v2, not the old docker-compose."
  exit 1
fi

# --- 1. load the bundled images -------------------------------------------
if [ ! -f images.tar ]; then
  fail "images.tar is missing from this folder."
  fail "Copy the whole bundle directory across, not just the scripts."
  exit 1
fi

needs_load=0
if [ -f images.txt ]; then
  while IFS= read -r image; do
    [ -z "$image" ] && continue
    if ! docker image inspect "$image" >/dev/null 2>&1; then
      needs_load=1
      break
    fi
  done < images.txt
else
  needs_load=1
fi

if [ "$needs_load" -eq 1 ]; then
  step "Loading container images (this takes a minute on first run)"
  docker load --input images.tar
else
  step "Images already loaded"
fi

# --- 2. generate per-deployment secrets on first run ----------------------
# /dev/urandom rather than $RANDOM: these are a session-signing key and a CI
# credential, and $RANDOM is a seeded PRNG that must never be used for either.
#
# Both take a CHARACTER count, not a byte count. Stripping `+/=` out of base64
# removes an unpredictable number of characters, and `cut` truncates silently
# rather than failing — so sizing from the input would quietly produce secrets
# shorter than intended, including admin passwords under the API's 12-character
# minimum. Over-generating and cutting to an exact length avoids that.
rand_b64() {
  head -c $(( $1 * 2 + 16 )) /dev/urandom | base64 | tr -d '+/=\n' | cut -c"1-$1"
}
rand_hex() {
  od -An -tx1 -N $(( ($1 + 1) / 2 )) /dev/urandom | tr -d ' \n' | cut -c"1-$1"
}

if [ ! -f .env ]; then
  step "First run — generating secrets for this deployment"

  SESSION_SECRET="$(rand_b64 64)"
  INGEST_TOKEN="$(rand_hex 64)"
  # Comfortably over the 12-character minimum the API enforces.
  ADMIN_PASSWORD="$(rand_b64 20)"
  PG_PASSWORD="$(rand_b64 32)"

  # Generated here rather than shipped in the bundle, so copying the bundle to
  # two machines produces two independent deployments instead of two machines
  # sharing a session-signing key.
  cat > .env <<EOF
# Generated on first run by start.sh. Keep this file; losing SESSION_SECRET
# signs everyone out, and losing INGEST_TOKENS breaks every CI pipeline.
#
# This file is per-deployment. Do NOT copy it to another machine.

# Host port for the web UI.
SBOM_PORT=$PORT

# The address people will actually browse to. Change if this machine is
# reached by hostname or IP rather than localhost, e.g.
#   PUBLIC_URL=http://sbom.internal.example.com:8080
PUBLIC_URL=http://localhost:$PORT

SESSION_SECRET=$SESSION_SECRET

# Bearer token for CI/CD: POST /api/v1/scans
INGEST_TOKENS=ci:$INGEST_TOKEN

# The first admin account, created on first startup only.
BOOTSTRAP_ADMIN_EMAIL=admin@sbom.local
BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_PASSWORD

# Postgres password. Only reachable inside the compose network.
POSTGRES_PASSWORD=$PG_PASSWORD

# An application with no scan in this many days is flagged stale.
STALE_APP_THRESHOLD_DAYS=30
LOG_LEVEL=info
EOF

  cat > CREDENTIALS.txt <<EOF
SBOM Platform — generated $(date '+%Y-%m-%d %H:%M')

Web UI          http://localhost:$PORT
Sign in         admin@sbom.local
Password        $ADMIN_PASSWORD

CI ingest token $INGEST_TOKEN
                Send as: Authorization: Bearer <token>
                Endpoint: http://localhost:$PORT/api/v1/scans

Change the admin password after signing in (click your email, top right).
These values are also in .env. Delete this file once you have stored them.
EOF

  chmod 600 .env CREDENTIALS.txt 2>/dev/null || true
  note "Wrote .env and CREDENTIALS.txt"
else
  step "Using the existing .env"
fi

# --- 3. start --------------------------------------------------------------
# Image tags come from images.env, written by the bundle builder. Exported as
# environment variables rather than merged into .env: compose gives real
# environment variables precedence, so a bundle always starts the images it
# actually shipped even if an older .env on this machine names different tags.
if [ -f images.env ]; then
  while IFS='=' read -r key value; do
    case "$key" in
      SBOM_IMAGE_*) export "$key=$value" ;;
    esac
  done < images.env
fi

step "Starting the stack"
docker compose up -d

# --- 4. wait until it actually serves --------------------------------------
# "Containers created" is not "the application is usable": the API migrates and
# seeds the database on first boot, which takes a few seconds longer.
EFFECTIVE_PORT="$(grep '^SBOM_PORT=' .env | cut -d= -f2)"
[ -z "$EFFECTIVE_PORT" ] && EFFECTIVE_PORT="$PORT"

step "Waiting for the application to become ready"

# A minimal host may have neither curl nor wget, so fall back to asking Docker
# for the container's own health status rather than giving up on the check.
probe() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS -m 3 "http://localhost:$EFFECTIVE_PORT/health" >/dev/null 2>&1
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 3 -O /dev/null "http://localhost:$EFFECTIVE_PORT/health" 2>/dev/null
  else
    [ "$(docker compose ps --format '{{.Health}}' api 2>/dev/null)" = "healthy" ]
  fi
}

ready=0
i=0
while [ "$i" -lt 60 ]; do
  if probe; then
    ready=1
    break
  fi
  sleep 2
  i=$((i + 1))
done

echo ""
if [ "$ready" -eq 1 ]; then
  printf '\033[32mSBOM Platform is running.\033[0m\n\n'
  echo "  Open        http://localhost:$EFFECTIVE_PORT"
  [ -f CREDENTIALS.txt ] && echo "  Sign in     see CREDENTIALS.txt in this folder"
  echo ""
  note "Logs        docker compose logs -f"
  note "Stop        docker compose down          (data is kept)"
  note "Erase all   docker compose down -v       (deletes every scan)"
else
  printf '\033[33mThe stack started but did not answer on port %s within two minutes.\033[0m\n' "$EFFECTIVE_PORT"
  echo "Check the logs:  docker compose logs --tail=80"
  exit 1
fi
