# A throwaway Active Directory domain controller (Samba 4) for the directory connector's tests.
# Test data only: never point a platform at it except from scripts/test-directory-ad.ps1.
FROM debian:trixie
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision winbind python3-samba openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY setup.sh seed.py /opt/
EXPOSE 636
CMD ["sh", "/opt/setup.sh"]
