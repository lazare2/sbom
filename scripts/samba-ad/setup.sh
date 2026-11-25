#!/bin/sh
# Provisions the test domain corp.example once, then runs Samba in the foreground.
set -eu
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
  rm -f /etc/samba/smb.conf
  samba-tool domain provision --realm=CORP.EXAMPLE --domain=CORP --server-role=dc \
    --dns-backend=SAMBA_INTERNAL --adminpass='Admin-pass-2026!' --use-rfc2307

  # Our own test CA and a certificate for "localhost", so certificate trust is tested for real.
  mkdir -p /tls && cd /tls
  openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 30 -subj "/CN=SBOM test CA" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost" 2>/dev/null
  # host.docker.internal: how a platform running in Docker on the same machine reaches it.
  printf 'subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1\n' > san.ext
  openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 30 -extfile san.ext 2>/dev/null
  chmod 600 server.key
  sed -i '/^\[global\]/a \	tls enabled = yes\n\ttls keyfile = /tls/server.key\n\ttls certfile = /tls/server.pem\n\ttls cafile = /tls/ca.pem' /etc/samba/smb.conf

  samba-tool user create svc-sbom 'Svc-pass-2026!' >/dev/null
  samba-tool user create alice 'User-pass-2026!' --mail-address=Alice@corp.example --given-name=Alice --surname=Anders >/dev/null
  samba-tool user create bob 'User-pass-2026!' --mail-address=bob@corp.example --given-name=Bob --surname=Berg >/dev/null
  samba-tool user create carol 'User-pass-2026!' --mail-address=carol@corp.example --given-name=Carol --surname=Cole >/dev/null
  samba-tool user disable carol >/dev/null
  samba-tool user create dave 'User-pass-2026!' --given-name=Dave --surname=Dunn >/dev/null
  for g in "Squad Payments" "Squad Ledger" "Squad (Legacy)" "Dev Teams" "Squad Big"; do samba-tool group add "$g" >/dev/null; done
  samba-tool group addmembers "Squad Payments" alice,carol >/dev/null
  samba-tool group addmembers "Squad Ledger" bob >/dev/null
  samba-tool group addmembers "Squad (Legacy)" dave >/dev/null
  samba-tool group addmembers "Dev Teams" "Squad Payments,Squad Ledger" >/dev/null
  python3 /opt/seed.py
  echo "provisioned"
fi
exec samba -i --debug-stdout
