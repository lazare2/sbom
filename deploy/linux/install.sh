#!/usr/bin/env sh
#
# Installs the SBOM Platform on a Linux server as a system service.
#
#   sudo ./linux/install.sh              # from the unpacked offline bundle
#   sudo ./linux/install.sh --port 9000
#
# What it does, with no internet connection at any point:
#   1. Uses the server's Docker if it has one; otherwise installs the Docker Engine shipped
#      in this bundle (static binaries, any 64-bit systemd Linux).
#   2. Copies the platform to /opt/sbom-platform. An existing .env there is kept as it is.
#   3. Loads the container images from this bundle, generates secrets on a first install,
#      and starts the platform (deploy/start.sh does this part, as on Windows).
#   4. Installs two systemd units: sbom-platform.service, which starts the platform at boot
#      with nobody signed in, and sbom-platform-backup.timer, a nightly backup.
#
# Safe to run again. It never deletes data.
#
# POSIX sh on purpose: a minimal server may not have bash.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
BUNDLE="$(cd "$HERE/.." && pwd)"
TARGET="${SBOM_HOME:-/opt/sbom-platform}"
PORT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --port=*) PORT="${1#--port=}"; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

. "$HERE/common.sh"

# --- preflight -------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "Run as root: sudo $0"
command -v systemctl >/dev/null 2>&1 || die "systemd is required (systemctl not found)."
[ "$(uname -m)" = "x86_64" ] || die "Only x86_64 is supported; this machine is $(uname -m)."
[ -f "$BUNDLE/images.tar" ] || die "images.tar is missing. Run this from the unpacked bundle folder."
[ -f "$BUNDLE/docker-compose.yml" ] || die "docker-compose.yml is missing from $BUNDLE."

# --- 1. docker -------------------------------------------------------------
ensure_docker

# --- 2. files --------------------------------------------------------------
step "Installing the platform files into $TARGET"
install_platform_files "$BUNDLE" "$TARGET"

# --- 3. images, secrets, start ---------------------------------------------
step "Starting the platform"
if [ -n "$PORT" ]; then export SBOM_PORT="$PORT"; fi
( cd "$TARGET" && SBOM_IMAGES_TAR="$BUNDLE/images.tar" sh ./start.sh )

# --- 4. systemd ------------------------------------------------------------
step "Installing the systemd units"
install_units "$TARGET"
systemctl enable sbom-platform.service >/dev/null
systemctl enable --now sbom-platform-backup.timer >/dev/null
# Mark the service started: the containers are already up from step 3, and `start` on a
# oneshot unit that is already running them is a no-op `docker compose up -d`.
systemctl start sbom-platform.service

echo ""
ok "SBOM Platform is installed as a service."
echo ""
echo "  Open          http://<this-server>:$(env_value "$TARGET/.env" SBOM_PORT)"
[ -f "$TARGET/CREDENTIALS.txt" ] && echo "  Sign in       see $TARGET/CREDENTIALS.txt (delete it once stored)"
echo "  Status        systemctl status sbom-platform"
echo "  Logs          cd $TARGET && docker compose logs -f"
echo "  Backups       $(backup_dir) (nightly; now: sudo $TARGET/backup.sh)"
echo "  Upgrade       sudo ./linux/upgrade.sh from the new bundle"
echo ""
note "Outbound connections it needs, and nothing else: see 'Network access' in $TARGET/README.md"
