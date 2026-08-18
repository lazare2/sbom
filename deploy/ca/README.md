# Proxy / private CA certificates

Drop your corporate root CA here as a PEM file, then point `GRYPE_DB_CA_CERT` at it:

```
GRYPE_DB_CA_CERT=/certs/proxy-ca.crt
```

This directory is bind-mounted read-only at `/certs` inside the API container. It exists so
the mount always has a source: Compose cannot make a bind mount conditional, and a missing
source is a hard startup failure rather than a skipped option.

## Why this is needed

A TLS-inspecting proxy re-signs every connection with its own certificate authority. Grype
is a Go binary and trusts only the CAs it knows about, so the download fails with:

```
tls: failed to verify certificate: x509: certificate signed by unknown authority
```

That is not a proxy misconfiguration and no proxy variable fixes it. The client has to be
told to trust the CA doing the inspection.

## Getting the certificate

Ask whoever runs the proxy for the root CA in PEM format — that is the reliable route, and
they have it already.

Failing that, export it from a browser on the same network: open any HTTPS site, view the
certificate, walk to the **root** of the chain (it will carry your organisation's name, not
the site's), and export it as **Base-64 encoded X.509**. A PEM file starts with
`-----BEGIN CERTIFICATE-----`.

Chains are fine: if the proxy presents an intermediate as well, concatenate both PEM blocks
into the one file.

## Scope

This affects the vulnerability database download only. Nothing else in the platform makes
outbound connections, and scanning itself works with no network at all once the database is
installed — importing an archive by hand stays a fully supported path if the download is
never going to be permitted.
