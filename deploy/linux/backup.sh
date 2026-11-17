#!/usr/bin/env sh
#
# Backs up the SBOM Platform: the database, the stored SBOM files and .env.
#
#   sudo /opt/sbom-platform/backup.sh            # run by sbom-platform-backup.timer nightly
#   sudo /opt/sbom-platform/backup.sh --keep 14  # how many backups to keep (default 7)
#
# Writes one folder per run under /var/backups/sbom-platform (SBOM_BACKUP_DIR to change it):
#   sbom.dump            pg_dump custom format, checked with pg_restore -l before it counts
#   sbom-blobs.tar.gz    every stored SBOM file
#   env.txt              the installation's .env (secrets - the folder is root-only)
#
# The platform keeps running. Only backups this script made are removed when over --keep.

set -eu

HOME_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$HOME_DIR/common.sh"
KEEP=7
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP="$2"; shift 2 ;;
    --dir) HOME_DIR="$2"; shift 2 ;;
    *) die "Unknown option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "Run as root."
[ -f "$HOME_DIR/.env" ] || die "$HOME_DIR/.env not found - is the platform installed there?"
cd "$HOME_DIR"

dest_root="$(backup_dir)"
stamp="$(date '+%Y%m%d-%H%M%S')"
dest="$dest_root/$stamp"
install -d -m 0700 "$dest_root" "$dest"

step "Backing up to $dest"
docker compose exec -T db pg_dump -U sbom -Fc sbom -f /tmp/sbom-backup.dump
docker compose cp db:/tmp/sbom-backup.dump "$dest/sbom.dump" >/dev/null
docker compose exec -T db rm -f /tmp/sbom-backup.dump
# Read it back: a dump that cannot be listed is not a backup.
docker compose cp "$dest/sbom.dump" db:/tmp/check.dump >/dev/null
entries="$(docker compose exec -T db pg_restore -l /tmp/check.dump | wc -l)"
docker compose exec -T db rm -f /tmp/check.dump
[ "$entries" -gt 10 ] || die "The database backup could not be read back ($entries entries)."

project="$(docker compose config --format json 2>/dev/null | sed -n 's/.*"name": *"\([^"]*\)".*/\1/p' | head -n 1)"
[ -n "$project" ] || project="sbom-platform"
pg_image="$(docker compose config --images 2>/dev/null | grep '^postgres' | head -n 1)"
docker run --rm -v "${project}_sbom-blobs:/data:ro" -v "$dest:/backup" --entrypoint tar \
  "${pg_image:-postgres:16-alpine}" czf /backup/sbom-blobs.tar.gz -C /data .

install -m 0600 .env "$dest/env.txt"
chmod 0600 "$dest"/*
note "database $(du -h "$dest/sbom.dump" | cut -f1) ($entries entries), SBOM files $(du -h "$dest/sbom-blobs.tar.gz" | cut -f1)"

# Retention: only folders named like this script names them.
ls -1d "$dest_root"/[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9] 2>/dev/null \
  | sort -r | tail -n +"$((KEEP + 1))" | while IFS= read -r old; do rm -rf "$old"; note "removed old backup $(basename "$old")"; done

ok "Backup complete: $dest"
