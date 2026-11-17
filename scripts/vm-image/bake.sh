#!/usr/bin/env bash
#
# Builds the Linux disk for the Windows Server installation: Debian's own cloud image, plus
# the few packages the platform needs that the image lacks, minus everything that would reach
# the internet on its own. Run by scripts/build-offline-bundle.ps1 inside a privileged
# container, on the build machine - which has internet; the server never does this.
#
#   bake.sh <debian.qcow2> <out.vhdx>
#
# Added:    nftables (Docker needs a firewall tool and the image has none), chrony reading
#           the Hyper-V host clock (no NTP servers), hyperv-daemons (the VM reports its
#           address and shuts down cleanly with the host).
# Removed:  unattended-upgrades and the apt timers (they contact deb.debian.org),
#           systemd-timesyncd (it contacts the Debian NTP pool),
#           every cloud-init data source except the disc the installer attaches.
#
# The result is a dynamic VHDX that Hyper-V boots as a generation 2 machine with Secure Boot.

set -euo pipefail

SRC="$1"
OUT="$2"
RAW="$(dirname "$OUT")/bake-work.raw"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends qemu-utils fdisk >/dev/null

qemu-img convert -O raw "$SRC" "$RAW"

# The root filesystem is partition 1 of the cloud image. Mounted by offset: a container does
# not see partition device nodes created after it started.
start="$(sfdisk -d "$RAW" | awk -F'[=,]' '/^[^ ]*1 :/ { gsub(/ /, "", $2); print $2 }')"
[ -n "$start" ] || { echo "could not find partition 1 in $RAW" >&2; exit 1; }
ROOT=/mnt/root
mkdir -p "$ROOT"
mount -o loop,offset=$((start * 512)) "$RAW" "$ROOT"
cleanup() {
  for m in dev/pts dev proc sys; do umount "$ROOT/$m" 2>/dev/null || true; done
  umount "$ROOT" 2>/dev/null || true
}
trap cleanup EXIT
mount --bind /dev "$ROOT/dev"; mount --bind /dev/pts "$ROOT/dev/pts"
mount -t proc proc "$ROOT/proc"; mount -t sysfs sys "$ROOT/sys"

# Name resolution for apt inside the chroot only; the image's own resolv.conf is restored.
resolv_backup=""
if [ -e "$ROOT/etc/resolv.conf" ] || [ -L "$ROOT/etc/resolv.conf" ]; then
  resolv_backup="$ROOT/etc/resolv.conf.bake"
  mv "$ROOT/etc/resolv.conf" "$resolv_backup"
fi
cp /etc/resolv.conf "$ROOT/etc/resolv.conf"

in_root() { chroot "$ROOT" /usr/bin/env DEBIAN_FRONTEND=noninteractive "$@"; }

in_root apt-get update -qq
in_root apt-get install -y -qq --no-install-recommends nftables chrony hyperv-daemons >/dev/null
in_root apt-get purge -y -qq unattended-upgrades systemd-timesyncd >/dev/null || true
in_root apt-get clean
rm -rf "$ROOT"/var/lib/apt/lists/*

# Nothing starts a network conversation on its own.
for unit in apt-daily.timer apt-daily-upgrade.timer apt-listchanges.timer; do
  in_root systemctl mask "$unit" >/dev/null 2>&1 || true
done

# The clock comes from the Hyper-V host through its PTP device, not from the internet.
cat > "$ROOT/etc/chrony/chrony.conf" <<'EOF'
# SBOM Platform: time from the Hyper-V host, no NTP servers.
refclock PHC /dev/ptp_hyperv poll 3 dpoll -2 offset 0 stratum 2
makestep 1.0 -1
driftfile /var/lib/chrony/chrony.drift
rtcsync
EOF

# cloud-init looks only at the installer's disc. The image default also probes cloud metadata
# addresses (169.254.169.254 and others), which on a server is just noise on the network.
cat > "$ROOT/etc/cloud/cloud.cfg.d/90-sbom-platform.cfg" <<'EOF'
datasource_list: [ NoCloud, None ]
EOF

# What went in, for the bundle's records.
in_root dpkg-query -W -f '${Package} ${Version}\n' nftables chrony hyperv-daemons > "$(dirname "$OUT")/vm-packages.txt"

rm -f "$ROOT/etc/resolv.conf"
[ -n "$resolv_backup" ] && mv "$resolv_backup" "$ROOT/etc/resolv.conf"

cleanup
trap - EXIT
qemu-img convert -O vhdx -o subformat=dynamic "$RAW" "$OUT"
rm -f "$RAW"
echo "baked $OUT"
