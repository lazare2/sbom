# Shared by install.sh, upgrade.sh and uninstall.sh. Sourced, not run.
# shellcheck shell=sh

step() { printf '\033[36m==> %s\033[0m\n' "$1"; }
note() { printf '    \033[90m%s\033[0m\n' "$1"; }
ok()   { printf '\033[32m%s\033[0m\n' "$1"; }
warn() { printf '\033[33m%s\033[0m\n' "$1" >&2; }
die()  { printf '\033[31m%s\033[0m\n' "$1" >&2; exit 1; }

# The value of KEY in an env file, without a trailing CR.
env_value() { grep "^$2=" "$1" 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d '\r'; }

backup_dir() { printf '%s' "${SBOM_BACKUP_DIR:-/var/backups/sbom-platform}"; }

# --- docker ----------------------------------------------------------------
# Uses an existing Docker Engine with Compose v2. Otherwise installs the static Docker
# Engine and Compose plugin that ship in linux/docker/, so no package repository is needed.
ensure_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    if ! docker info >/dev/null 2>&1; then
      systemctl start docker 2>/dev/null || true
      docker info >/dev/null 2>&1 || die "Docker is installed but not running: systemctl start docker"
    fi
    step "Using the Docker Engine already on this server ($(docker version --format '{{.Server.Version}}' 2>/dev/null))"
    systemctl enable docker >/dev/null 2>&1 || true
    return
  fi
  if command -v docker >/dev/null 2>&1; then
    die "Docker is installed without Compose v2 ('docker compose'). Install the compose plugin, or remove Docker and run this again to use the bundled one."
  fi

  local_dir="$HERE/docker"
  tgz="$(ls "$local_dir"/docker-*.tgz 2>/dev/null | head -n 1)"
  [ -n "$tgz" ] || die "Docker is not installed and the bundle carries no Docker Engine ($local_dir)."
  # Docker needs a firewall tool for container networking: iptables (Ubuntu, RHEL) or, with
  # the nftables backend, nft (Debian 12's default). Both are operating-system packages, on the
  # server's own installation media; the bundle cannot stand in for them.
  firewall=""
  if command -v iptables >/dev/null 2>&1; then
    firewall="iptables"
  elif command -v nft >/dev/null 2>&1; then
    firewall="nftables"
  else
    die "Neither iptables nor nft is installed, and Docker needs one of them for container networking.
Install the 'nftables' or 'iptables' package from this server's operating-system media, then run this again."
  fi

  step "Installing the bundled Docker Engine ($(basename "$tgz" .tgz), firewall: $firewall)"
  if [ "$firewall" = "nftables" ] && [ ! -f /etc/docker/daemon.json ]; then
    install -d -m 0755 /etc/docker
    printf '{\n  "firewall-backend": "nftables"\n}\n' > /etc/docker/daemon.json
  fi
  ( cd "$local_dir" && sha256sum -c SHA256SUMS >/dev/null ) || die "The bundled Docker files do not match SHA256SUMS: the bundle is damaged."
  tmp="$(mktemp -d)"
  tar xzf "$tgz" -C "$tmp"
  install -m 0755 "$tmp"/docker/* /usr/local/bin/
  rm -rf "$tmp"
  install -d -m 0755 /usr/local/lib/docker/cli-plugins
  install -m 0755 "$local_dir/docker-compose-linux-x86_64" /usr/local/lib/docker/cli-plugins/docker-compose
  install -m 0644 "$local_dir/containerd.service" "$local_dir/docker.service" "$local_dir/docker.socket" /etc/systemd/system/
  getent group docker >/dev/null 2>&1 || groupadd --system docker
  systemctl daemon-reload
  systemctl enable --now containerd.service docker.socket docker.service >/dev/null
  i=0
  until docker info >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -gt 30 ] && die "The Docker Engine did not start: journalctl -u docker"
    sleep 1
  done
  note "Docker $(docker version --format '{{.Server.Version}}') and Compose $(docker compose version --short) installed"
}

# --- files -----------------------------------------------------------------
# Copies the platform from a bundle into the target. Never touches .env, CREDENTIALS.txt or
# certificates someone put into ca/, and never copies images.tar (it is loaded from the bundle).
install_platform_files() {
  src="$1"; dst="$2"
  install -d -m 0750 "$dst" "$dst/ca"
  for f in docker-compose.yml start.sh images.env images.txt README.md; do
    [ -f "$src/$f" ] && install -m 0644 "$src/$f" "$dst/$f"
  done
  chmod 0755 "$dst/start.sh"
  [ -f "$src/ca/README.md" ] && install -m 0644 "$src/ca/README.md" "$dst/ca/README.md"
  install -m 0755 "$src/linux/backup.sh" "$dst/backup.sh"
  install -m 0755 "$src/linux/restore.sh" "$dst/restore.sh"
  install -m 0644 "$src/linux/common.sh" "$dst/common.sh"
  # An override written by an administrator (extra ports, a reverse proxy) is theirs: kept.
  return 0
}

install_units() {
  dst="$1"
  for u in sbom-platform.service sbom-platform-backup.service sbom-platform-backup.timer; do
    sed "s#@SBOM_HOME@#$dst#g" "$HERE/$u" > "/etc/systemd/system/$u"
    chmod 0644 "/etc/systemd/system/$u"
  done
  systemctl daemon-reload
}

# Waits until the platform answers on its health endpoint (or the API container is healthy).
wait_healthy() {
  dir="$1"; port="$(env_value "$dir/.env" SBOM_PORT)"; [ -n "$port" ] || port=8080
  i=0
  while [ "$i" -lt 200 ]; do   # up to ten minutes
    if command -v curl >/dev/null 2>&1; then
      curl -fsS -m 3 "http://127.0.0.1:$port/health" >/dev/null 2>&1 && return 0
    elif command -v wget >/dev/null 2>&1; then
      wget -q -T 3 -O /dev/null "http://127.0.0.1:$port/health" 2>/dev/null && return 0
    else
      [ "$(cd "$dir" && docker compose ps --format '{{.Health}}' api 2>/dev/null)" = "healthy" ] && return 0
    fi
    i=$((i + 1)); sleep 3
  done
  return 1
}
