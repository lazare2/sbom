#!/usr/bin/env sh
#
# Upgrades an installed SBOM Platform to the version in this bundle.
#
#   sudo sh ./linux/upgrade.sh          # from the unpacked NEW bundle
#
#   1. Checks the installation and that this bundle is a different version.
#   2. Stops the web and API containers (the database keeps running) and makes a backup,
#      which must read back before anything changes.
#   3. Loads the new images, keeps the current files in .previous/, copies in the new ones.
#      .env is kept; keys new versions need are added to it, never replaced.
#   4. Starts the new version. The API applies its database migrations on start.
#   5. If it does not become healthy, goes back on its own: previous files, database and SBOM
#      files restored from the backup of step 2, previous version started.
#
# Never deletes data. The backup stays under /var/backups/sbom-platform.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
BUNDLE="$(cd "$HERE/.." && pwd)"
TARGET="${SBOM_HOME:-/opt/sbom-platform}"
. "$HERE/common.sh"

[ "$(id -u)" -eq 0 ] || die "Run as root: sudo sh $0"
[ -f "$TARGET/.env" ] || die "No installation in $TARGET. Use linux/install.sh for a first install."
[ -f "$BUNDLE/images.tar" ] || die "images.tar is missing. Run this from the unpacked NEW bundle."

old_version="$(env_value "$TARGET/.env" APP_VERSION)"
new_version="$(env_value "$BUNDLE/images.env" APP_VERSION)"
step "Upgrading ${old_version:-unknown} -> $new_version"
[ "$old_version" != "$new_version" ] || warn "The installed version is already $new_version; continuing re-installs it."

ensure_docker
cd "$TARGET"

# --- 2. backup -------------------------------------------------------------
step "Stopping the web and API containers"
docker compose stop web api
sh "$BUNDLE/linux/backup.sh" --dir "$TARGET" --keep 30
backup="$(ls -1d "$(backup_dir)"/[0-9]*-[0-9]* | sort | tail -n 1)"

# --- 3. files --------------------------------------------------------------
step "Loading the new images"
docker load --input "$BUNDLE/images.tar" >/dev/null
rm -rf "$TARGET/.previous"
install -d -m 0750 "$TARGET/.previous"
for f in docker-compose.yml start.sh images.env images.txt README.md backup.sh restore.sh common.sh .env; do
  [ -f "$TARGET/$f" ] && cp -p "$TARGET/$f" "$TARGET/.previous/$f"
done
install_platform_files "$BUNDLE" "$TARGET"

# --- 4. start --------------------------------------------------------------
step "Starting $new_version"
# start.sh waits two minutes for the API; migrations on a large database can take longer, so
# its verdict is not the one that decides a rollback - wait_healthy (up to ten minutes) is.
( SBOM_IMAGES_TAR="$BUNDLE/images.tar" sh ./start.sh ) || warn "start.sh did not see the platform answer yet; waiting longer"
if wait_healthy "$TARGET"; then
  install_units "$TARGET"
  systemctl enable sbom-platform.service sbom-platform-backup.timer >/dev/null 2>&1 || true
  echo ""
  ok "Upgraded to $new_version. Backup taken before the upgrade: $backup"
  note "Previous files are in $TARGET/.previous until the next upgrade."
  exit 0
fi

# --- 5. back to the previous version ------------------------------------------
warn "$new_version did not start. Going back to ${old_version:-the previous version}."
( docker compose logs --tail 120 api > "$backup/api-failed-upgrade.log" 2>&1 ) || true
docker compose down
for f in docker-compose.yml start.sh images.env images.txt README.md backup.sh restore.sh common.sh .env; do
  [ -f "$TARGET/.previous/$f" ] && cp -p "$TARGET/.previous/$f" "$TARGET/$f"
done
docker compose up -d db
i=0; until docker compose exec -T db pg_isready -U sbom -d sbom >/dev/null 2>&1; do i=$((i + 1)); [ "$i" -gt 60 ] && die "The database did not come back. Backup: $backup"; sleep 2; done
docker compose cp "$backup/sbom.dump" db:/tmp/restore.dump >/dev/null
docker compose exec -T db dropdb -U sbom --force sbom
docker compose exec -T db createdb -U sbom -O sbom sbom
docker compose exec -T db pg_restore -U sbom -d sbom /tmp/restore.dump
docker compose exec -T db rm -f /tmp/restore.dump
project="$(docker compose config --format json 2>/dev/null | sed -n 's/.*"name": *"\([^"]*\)".*/\1/p' | head -n 1)"
docker run --rm -v "${project:-sbom-platform}_sbom-blobs:/data" -v "$backup:/backup:ro" --entrypoint sh postgres:16-alpine \
  -c "find /data -mindepth 1 -delete && tar xzf /backup/sbom-blobs.tar.gz -C /data"
docker compose up -d
if wait_healthy "$TARGET"; then
  die "Rolled back: ${old_version:-the previous version} is running again with the data from before the upgrade. Log of the failed start: $backup/api-failed-upgrade.log"
fi
die "Rolled back, but the previous version did not become healthy either. Backup: $backup. Logs: cd $TARGET && docker compose logs api"
