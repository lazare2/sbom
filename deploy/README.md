# SBOM Platform — install

**Requirement: Docker.** Nothing else. No Node, no npm, no PostgreSQL install, no
compiler.

Two ways in, same compose file:

| | You need on the target | Use when |
|---|---|---|
| [**Pull from a registry**](#option-1--pull-from-a-registry) | `docker-compose.yml` + `.env` | The machine can reach your registry |
| [**Offline bundle**](#option-2--offline-bundle) | This whole folder, including `images.tar` | No internet, or no registry |

---

## Option 1 — pull from a registry

Copy just **two files** to the target — `docker-compose.yml` and a `.env` — then:

```bash
docker compose up -d
```

That pulls PostgreSQL, the API and the web image, creates the database, applies
migrations, and creates the admin account. Nothing else is needed on the machine.

Build `.env` from `.env.example`. Only three values are required:

```
SESSION_SECRET=<32+ random chars>
BOOTSTRAP_ADMIN_EMAIL=admin@sbom.local
BOOTSTRAP_ADMIN_PASSWORD=<a real password>
```

The compose file already points at the published images (`defaullltt/sbom-api:0.1.0` and
`defaullltt/sbom-web:0.1.0`), so no image variables are needed. Set `SBOM_IMAGE_API` and
`SBOM_IMAGE_WEB` only to run your own build or pin an older version.

Generate the secret rather than inventing one:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# or: openssl rand -hex 32
```

Then open <http://localhost:8080> and sign in with the bootstrap credentials.

**Generate a separate `SESSION_SECRET` per deployment.** Two machines sharing one can
forge each other's sessions.

**Pin the version, don't use `latest`.** `latest` is what a machine gets when nobody
chose, and having it move under a running deployment is an upgrade nobody triggered.

If the repositories are private, run `docker login` on the target once first.

To publish new images from a checkout of the source:

```powershell
.\scripts\publish-images.ps1 -User youruser
```

---

## Option 2 — offline bundle

Everything needed on a machine with no internet connection. PostgreSQL ships inside the
bundle as a container image.

### Install

1. Copy this **entire folder** to the offline machine. It must stay together —
   `images.tar` is the application.

2. Run the start script from inside the folder:

   **Windows (PowerShell)**
   ```powershell
   .\start.ps1
   ```

   **Linux / macOS**
   ```sh
   chmod +x start.sh
   ./start.sh
   ```

3. Open <http://localhost:8080> and sign in with the credentials in
   `CREDENTIALS.txt`, which the start script writes on the first run.

The first run takes a few minutes: it loads the container images, creates the
database, applies migrations, and creates the admin account. Later runs start in
seconds.

To use a different port: `.\start.ps1 -Port 9000` or `SBOM_PORT=9000 ./start.sh`.

---

## What the start script does

1. Checks Docker is installed **and running** — the most common failure is a
   stopped daemon, and the check turns that into a clear message.
2. `docker load` the bundled images, skipping it if they are already present.
3. On the first run only, generates a session secret, a CI ingest token, a
   database password, and an admin password, into `.env` and `CREDENTIALS.txt`.
4. `docker compose up -d`.
5. Waits until the application actually answers, not merely until the containers
   are created — the API migrates and seeds the database on first boot.

**Secrets are generated on the target, not shipped in this bundle.** Copying the
bundle to two machines gives two independent deployments rather than two
machines sharing a session-signing key.

> **If you test-run the bundle before copying it**, delete the `.env` and
> `CREDENTIALS.txt` it creates before copying the folder onward. Otherwise every
> machine you deploy to inherits the same session-signing key and the same admin
> password — exactly what generating them per machine is meant to avoid. A
> freshly built bundle never contains them.

---

## Running it

| Task | Command |
|---|---|
| Start / restart | `.\start.ps1` or `./start.sh` |
| Stop, keep data | `docker compose down` |
| Follow the logs | `docker compose logs -f` |
| Just the API's logs | `docker compose logs -f api` |
| Status | `docker compose ps` |
| **Erase everything** | `docker compose down -v` |

`docker compose down -v` deletes the volumes: every scan, every application, and
every stored SBOM. There is no undo.

---

## Sending SBOMs from CI

The ingest token is in `CREDENTIALS.txt`. A pipeline step looks like this:

```sh
syft "$IMAGE" -o cyclonedx-json > sbom.json

curl -f -X POST http://<this-machine>:8080/api/v1/scans \
  -H "Authorization: Bearer $SBOM_TOKEN" \
  -F "sbom=@sbom.json" \
  -F "app_name=$CI_PROJECT_NAME" \
  -F "commit_sha=$CI_COMMIT_SHA" \
  -F "build_number=$CI_PIPELINE_IID" \
  -F "branch=$CI_COMMIT_REF_NAME" \
  -F "image_ref=$IMAGE"
```

`curl -f` fails the build on any non-2xx, which is what the API's status codes
are designed around. Only `sbom` and `app_name` are required.

An `app_name` the platform has never seen is **not** an error: it creates the
application as *awaiting confirmation* and stores the scan. An admin resolves it
later under **Admin → Awaiting confirmation**. Losing a build's SBOM because
nobody pre-registered the repo would be the worse outcome.

---

## Vulnerability scanning

**Off by default.** With it off this is a dependency inventory and nothing below applies.

Grype itself is inside the bundle, so nothing needs installing. Its **database is not**:
1.9 GB expanded, rebuilt daily, so shipping it would multiply this folder's size and hand
you something already stale. Install it once, under **Admin → Vulnerability scanning**:

| Machine | How |
|---|---|
| Has internet (even via proxy) | **Update now**. Takes a few minutes for ~141 MB. |
| Internal Grype mirror | Set `GRYPE_DB_UPDATE_URL` in `.env`, restart, then **Update now** |
| No network at all | Download the archive on a connected machine and **upload** it in the panel |

For the last case, fetch the listing on a connected machine, download the archive it names,
and upload that file through the admin panel — no host paths or container shells involved:

```sh
curl -s https://grype.anchore.io/databases/v6/latest.json
# {"status":"active","schemaVersion":"v6.1.9","built":"...",
#  "path":"vulnerability-db_v6.1.9_2026-08-17T00-15-33Z_1786947573.tar.zst","checksum":"sha256:..."}
```

The field is **`path`**, and it is a filename rather than a link — prepend the base URL
yourself:

```sh
curl -LO "https://grype.anchore.io/databases/v6/$(curl -s https://grype.anchore.io/databases/v6/latest.json | jq -r .path)"
```

Upload the `.tar.zst` exactly as downloaded — do not decompress it, and do not worry if
the browser rewrites the colons in the filename, which Windows requires. The archive is
~145 MB; `GRYPE_DB_MAX_UPLOAD_BYTES` caps the upload at 1 GiB by default, which is
separate from the SBOM ingest limit so tightening one cannot break the other.

**If "Update now" reports no internet connection on a machine whose browser reaches
`grype.anchore.io` fine, the container has not been told about your proxy.** The browser and
the API are two different clients, and a container inherits nothing from the host's browser or
system proxy settings. Set `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` in `.env` — both compose
files pass them through — and add `GRYPE_DB_CA_CERT` if the proxy inspects TLS.

Setting those variables is necessary but was not sufficient before this release, and the
reason is worth knowing if you are debugging a similar tool: the update runs a reachability
check before downloading, and that check used Node's `fetch`, which ignores the proxy
variables entirely (built-in support arrived in Node 24 behind `NODE_USE_ENV_PROXY`; the
runtime image is Node 22). Grype is a Go binary and honoured the proxy perfectly well — but
the check refused first, so the downloader that would have worked never ran, and no amount
of correct proxy configuration changed the outcome. The check now runs `grype db check`
whenever a proxy is configured, so the probe and the download use the same client. Uploading the
archive by hand stays a fully supported path either way; it is what the offline install exists
for, not a workaround.

**If you put your own reverse proxy in front, raise its request body limit too.** The
bundled nginx allows 1 GiB to match the API. This is the failure worth knowing about
because of how it presents: a proxy that rejects the body closes the connection, and the
browser reports "failed to fetch" rather than a status, so the size-specific error the API
raises for exactly this case never reaches you. nginx's own default is 1 MB and this
config shipped with 128 MB — both below the archive, both silent. Whichever limit is
lowest is the one that decides, and it should not be the one that cannot explain itself.
Allow at least 30 minutes of read timeout as well: the import expands ~1.9 GB and
validates it before swapping, and a proxy timing out mid-import kills a *working* install.

Then tick **Enable vulnerability scanning**. Every package already in the platform is
matched in the background — historical builds included — and the dashboards gain the
findings. Expect a couple of minutes for a few thousand packages.

An offline machine with no database installed is **not** a failure state. Automatic checks
report `No internet connection to <url>`, return HTTP 200, leave the previous database
untouched, and affect nothing else: ingestion, search, the dashboards and the report all
continue exactly as normal.

The database lives on the `sbom-platform_grype-db` volume and is **not worth backing up**
— it is reproducible from upstream and stale within a day. Allow it ~4 GB of disk.

---

## Reaching it from other machines

By default the UI is bound to port 8080 on all interfaces, so
`http://<machine-ip>:8080` works from elsewhere on the network once the host
firewall allows it.

If people will reach it by hostname or IP rather than `localhost`, set that
address in `.env` and restart:

```
PUBLIC_URL=http://sbom.internal.example.com:8080
```

This only affects the session cookie's `Secure` flag and the allowed CORS
origin. The UI and API are same-origin behind nginx, so the app works either way
— but keeping it accurate matters if you later put HTTPS in front.

---

## Backups

Two Docker volumes hold everything:

| Volume | Contents | Back up |
|---|---|---|
| `sbom-platform_db-data` | Applications, scans, components, users, audit trail | **yes** |
| `sbom-platform_sbom-blobs` | The original CycloneDX files, gzipped | **yes** |
| `sbom-platform_grype-db` | Grype's vulnerability database | no — reproducible, and stale within a day |

Back up the first **two**. Scan rows reference blobs by key and cannot regenerate them, so
a database restored without its blobs loses every raw SBOM download.

```sh
# Database — a plain SQL dump
docker compose exec -T db pg_dump -U sbom sbom > sbom-backup.sql

# Raw SBOM blobs
docker run --rm -v sbom-platform_sbom-blobs:/data -v "$PWD":/backup alpine \
  tar czf /backup/sbom-blobs.tar.gz -C /data .
```

Also keep `.env`. Losing `SESSION_SECRET` signs everyone out; losing
`INGEST_TOKENS` breaks every pipeline until they are reissued.

---

## Upgrading

Build a new bundle on a connected machine, copy it across, and run its start
script **in the new folder**. Keep the old `.env`:

```powershell
copy old-bundle\.env new-bundle\.env
cd new-bundle
.\start.ps1
```

The compose project name is the same, so the new containers attach to the
existing volumes and your data carries over. Migrations run automatically on
startup and are transactional — a failed migration rolls back rather than
leaving a half-applied schema.

---

## Troubleshooting

**"Docker is installed but the daemon is not running"** — start Docker Desktop,
or `sudo systemctl start docker`. On Linux, if Docker needs root, run
`sudo ./start.sh`.

**Port 8080 is already in use** — `.\start.ps1 -Port 9000`.

**It started but the page will not load** — `docker compose logs api --tail=50`.
The API waits for PostgreSQL to report healthy, so a few seconds of connection
errors at startup are normal.

**"exec format error"** — the images were built for a different CPU
architecture. Rebuild the bundle with `--platform linux/amd64` (the builder does
this by default).

**Forgotten admin password** — there is no self-service reset; user emails are
login identifiers, not mailboxes. Another admin can reset it under
**Admin → Users**. If no admin is reachable at all, the account can be given a
fresh password directly:

```sh
docker compose exec db psql -U sbom -d sbom \
  -c "UPDATE \"user\" SET password_hash = NULL WHERE email = 'admin@sbom.local';"
```

That leaves the account unable to sign in, so follow it by deleting the row and
letting the seed recreate it from `BOOTSTRAP_ADMIN_PASSWORD` in `.env` on the
next restart. The platform refuses to let you demote or deactivate the last
active admin precisely so this situation is hard to reach by accident.
