#!/usr/bin/env sh
#
# Removes the SBOM Platform service. Keeps every piece of data.
#
#   sudo ./linux/uninstall.sh          # from the bundle the platform was installed from
#
# Stops and removes the containers and the systemd units. Leaves in place: the Docker
# volumes (database and stored SBOMs), /opt/sbom-platform with its .env, the backups, and
# Docker itself. What is left, and how to remove it by hand, is printed at the end.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="${SBOM_HOME:-/opt/sbom-platform}"
. "$HERE/common.sh"
[ "$(id -u)" -eq 0 ] || die "Run as root: sudo $0"

step "Stopping the service and its nightly backup"
systemctl disable --now sbom-platform-backup.timer sbom-platform.service 2>/dev/null || true
if [ -f "$TARGET/docker-compose.yml" ]; then
  ( cd "$TARGET" && docker compose down )   # containers only; the volumes stay
fi
rm -f /etc/systemd/system/sbom-platform.service /etc/systemd/system/sbom-platform-backup.service \
      /etc/systemd/system/sbom-platform-backup.timer
systemctl daemon-reload

ok "The service is removed. Nothing else was deleted."
echo ""
echo "  Still here, on purpose:"
echo "    $TARGET                      installation files and .env (secrets)"
echo "    $(backup_dir)    backups"
echo "    Docker volumes:"
docker volume ls --filter "label=com.docker.compose.project=sbom-platform" --format '      {{.Name}}' 2>/dev/null || true
echo ""
echo "  Reinstalling with linux/install.sh picks all of it up again."
