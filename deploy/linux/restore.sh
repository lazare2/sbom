#!/usr/bin/env sh
#
# Restores a backup into the installed SBOM Platform: the database and the stored SBOM files.
#
#   sudo sh /opt/sbom-platform/restore.sh /var/backups/sbom-platform/20261117-023012
#
# The folder is one written by backup.sh (sbom.dump, sbom-blobs.tar.gz), or by the Windows
# installer when it moves an installation off Docker Desktop. The current database and files
# are REPLACED, so a backup of them is taken first, into the usual backup folder.
#
# .env is not touched: the backup's env.txt holds the secrets that belong with that data
# (session key, CI tokens, the key that encrypts the Xray token). Put it in place yourself
# if you are restoring onto a new installation - see "Moving to a new server" in README.md.

set -eu

HOME_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$HOME_DIR/common.sh"
FROM="${1:-}"
[ -n "$FROM" ] || die "Usage: sudo sh $0 <backup folder>"
[ "$(id -u)" -eq 0 ] || die "Run as root."
[ -f "$FROM/sbom.dump" ] || die "$FROM/sbom.dump not found."
[ -f "$FROM/sbom-blobs.tar.gz" ] || die "$FROM/sbom-blobs.tar.gz not found."
cd "$HOME_DIR"

step "Backing up the current data first"
sh "$HOME_DIR/backup.sh" --keep 30

step "Restoring $FROM"
docker compose stop web api >/dev/null 2>&1 || true
docker compose up -d db
i=0; until docker compose exec -T db pg_isready -U sbom -d sbom >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -gt 60 ] && die "The database did not become ready."; sleep 2
done
docker compose cp "$FROM/sbom.dump" db:/tmp/restore.dump >/dev/null
docker compose exec -T db dropdb -U sbom --force sbom
docker compose exec -T db createdb -U sbom -O sbom sbom
docker compose exec -T db pg_restore -U sbom -d sbom --no-owner --role=sbom /tmp/restore.dump
docker compose exec -T db rm -f /tmp/restore.dump

project="$(docker compose config --format json 2>/dev/null | sed -n 's/.*"name": *"\([^"]*\)".*/\1/p' | head -n 1)"
pg_image="$(docker compose config --images 2>/dev/null | grep '^postgres' | head -n 1)"
abs_from="$(cd "$FROM" && pwd)"
docker run --rm -v "${project:-sbom-platform}_sbom-blobs:/data" -v "$abs_from:/backup:ro" --entrypoint sh \
  "${pg_image:-postgres:16-alpine}" -c "find /data -mindepth 1 -delete && tar xzf /backup/sbom-blobs.tar.gz -C /data && chown -R 1000:1000 /data"

step "Starting the platform"
docker compose up -d
wait_healthy "$HOME_DIR" || die "The platform did not answer after the restore: docker compose logs api"
ok "Restored from $FROM"
