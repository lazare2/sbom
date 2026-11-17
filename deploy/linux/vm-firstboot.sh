#!/usr/bin/env sh
#
# First start of the SBOM Platform virtual machine on Windows Server. Run once by cloud-init
# from the installer's disc; never by hand. Log: /var/log/sbom-firstboot.log
#
#   sh vm-firstboot.sh <disc mount point>
#
# The disc carries:   bundle/        the offline bundle (images, compose file, linux scripts)
#                     sbom/settings.env   address, proxy (written by install-windows.ps1)
#                     migrate/       optional: a backup of an existing installation to bring in
#
# The machine has two disks. The system disk is Debian and can be replaced by a newer one later;
# everything that matters - Docker's images and volumes, the platform's folder, the backups -
# lives on the second disk (label sbomdata, mounted at /srv/sbom), so replacing the system
# disk never touches the data.

set -eu

CD="$1"
echo "== SBOM Platform first boot, $(date -u '+%Y-%m-%d %H:%M:%S') UTC"

# --- 1. the data disk -------------------------------------------------------------------
if [ ! -e /dev/disk/by-label/sbomdata ]; then
  root_disk="$(lsblk -no PKNAME "$(findmnt -no SOURCE /)")"
  disk=""
  for d in $(lsblk -dnpo NAME,TYPE | awk '$2 == "disk" { print $1 }'); do
    [ "$d" = "/dev/$root_disk" ] && continue
    # Empty means: no partitions and no filesystem. Anything else is not ours to format.
    [ "$(lsblk -no NAME "$d" | wc -l)" -eq 1 ] || continue
    [ -z "$(blkid -o value -s TYPE "$d" 2>/dev/null)" ] || continue
    disk="$d"; break
  done
  [ -n "$disk" ] || { echo "No empty data disk found."; exit 1; }
  echo "Formatting the data disk $disk"
  mkfs.ext4 -q -L sbomdata "$disk"
  udevadm settle
fi
mkdir -p /srv/sbom
grep -q '^LABEL=sbomdata ' /etc/fstab || echo 'LABEL=sbomdata /srv/sbom ext4 defaults,nofail 0 2' >> /etc/fstab
mountpoint -q /srv/sbom || mount /srv/sbom
mkdir -p /srv/sbom/docker /srv/sbom/platform /srv/sbom/backups
chmod 0700 /srv/sbom/backups

# The platform's usual paths, kept, so every Linux script and manual applies unchanged.
[ -e /opt/sbom-platform ] || ln -s /srv/sbom/platform /opt/sbom-platform
mkdir -p /var/backups
[ -e /var/backups/sbom-platform ] || ln -s /srv/sbom/backups /var/backups/sbom-platform

# Docker keeps its data on the data disk. The firewall backend is the installer's choice.
mkdir -p /etc/docker
if [ ! -f /etc/docker/daemon.json ]; then
  printf '{\n  "data-root": "/srv/sbom/docker"\n}\n' > /etc/docker/daemon.json
fi

# --- 2. settings from the installer ------------------------------------------------------
SBOM_PUBLIC_URL=""; SBOM_HTTP_PROXY=""; SBOM_NO_PROXY=""
# shellcheck disable=SC1091
[ -f "$CD/sbom/settings.env" ] && . "$CD/sbom/settings.env"

TARGET=/srv/sbom/platform
set_key() {   # KEY VALUE: replaces or appends KEY=VALUE in .env, keeping its mode
  if grep -q "^$1=" "$TARGET/.env"; then
    awk -v k="$1" -v v="$2" 'index($0, k "=") == 1 { print k "=" v; next } { print }' "$TARGET/.env" > "$TARGET/.env.tmp"
    cat "$TARGET/.env.tmp" > "$TARGET/.env"; rm -f "$TARGET/.env.tmp"
  else
    printf '%s=%s\n' "$1" "$2" >> "$TARGET/.env"
  fi
}

# Moving an existing installation: its .env goes in first, so the database is created with
# its password and the session key, CI tokens and the Xray encryption key carry over.
if [ -f "$CD/migrate/env.txt" ] && [ ! -f "$TARGET/.env" ]; then
  echo "Taking over the settings of the installation being moved"
  grep -v -E '^(SBOM_IMAGE_[A-Z_]*|APP_VERSION|SBOM_PORT|PUBLIC_URL)=' "$CD/migrate/env.txt" | tr -d '\r' > "$TARGET/.env"
  chmod 0600 "$TARGET/.env"
  set_key SBOM_PORT 8080
fi

# --- 3. install -------------------------------------------------------------------------
sh "$CD/bundle/linux/install.sh" --port 8080

# --- 4. address and proxy -------------------------------------------------------------
changed=0
if [ -n "$SBOM_PUBLIC_URL" ]; then set_key PUBLIC_URL "$SBOM_PUBLIC_URL"; changed=1; fi
if [ -n "$SBOM_HTTP_PROXY" ]; then
  set_key HTTP_PROXY "$SBOM_HTTP_PROXY"
  set_key HTTPS_PROXY "$SBOM_HTTP_PROXY"
  set_key NO_PROXY "${SBOM_NO_PROXY:-localhost,127.0.0.1,db,api,web}"
  changed=1
fi
if [ "$changed" -eq 1 ]; then
  ( cd "$TARGET" && docker compose up -d )
fi

# --- 5. the moved data ------------------------------------------------------------------
if [ -f "$CD/migrate/sbom.dump" ]; then
  echo "Restoring the data of the installation being moved"
  sh "$TARGET/restore.sh" "$CD/migrate"
fi

# The installer's disc holds a copy of this installation's secrets only when it moved one;
# CREDENTIALS.txt is written on a fresh install. Both stay inside this machine.
touch /srv/sbom/firstboot.done
echo "== done, $(date -u '+%Y-%m-%d %H:%M:%S') UTC"
