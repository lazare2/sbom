# SBOM Platform - install

**Requirement: Docker.** Nothing else. No Node, no npm, no PostgreSQL install, no
compiler.

Two ways in, same compose file:

| | You need on the target | Use when |
|---|---|---|
| [**Pull from a registry**](#option-1--pull-from-a-registry) | `docker-compose.yml` + `.env` | The machine can reach your registry |
| [**Offline bundle**](#option-2--offline-bundle) | This whole folder, including `images.tar` | No internet, or no registry |

---

## Option 1 - pull from a registry

Copy just **two files** to the target - `docker-compose.yml` and a `.env` - then:

```bash
docker compose up -d
```

That pulls PostgreSQL, the API and the web image, creates the database, applies
migrations, and creates the admin account. Nothing else is needed on the machine.

Build `.env` from `.env.example`. These values are required:

```
SBOM_IMAGE_API=<registry>/sbom-api:<version>
SBOM_IMAGE_WEB=<registry>/sbom-web:<version>
POSTGRES_PASSWORD=<a generated password>
SESSION_SECRET=<32+ random chars>
BOOTSTRAP_ADMIN_EMAIL=admin@sbom.local
BOOTSTRAP_ADMIN_PASSWORD=<a real password>
```

The compose file has no default images and no default database password: name the images
you published and pin their version, and generate the password like the secret below.

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

## Option 2 - offline bundle

Everything needed on a machine with no internet connection. PostgreSQL ships inside the
bundle as a container image.

### Install

1. Copy this **entire folder** to the offline machine. It must stay together -
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

## Option 3 - Linux server, as a service

For a server that runs the platform permanently. From the unpacked bundle:

```sh
sudo sh ./linux/install.sh            # or: --port 9000
```

- Works on any 64-bit Linux with systemd: Ubuntu, Debian, RHEL and their relatives.
- Uses the server's Docker if it has one. Otherwise it installs the Docker Engine that ships
  in the bundle; nothing is downloaded. Docker needs `nftables` or `iptables`, which every
  normal server installation has.
- Installs to `/opt/sbom-platform`, starts at boot (`systemctl status sbom-platform`), and
  backs up every night at 02:30 to `/var/backups/sbom-platform` (the last 7 are kept).

| Task | Command |
|---|---|
| Upgrade (from the new bundle) | `sudo sh ./linux/upgrade.sh` - backs up first, rolls back by itself if the new version does not start |
| Back up now | `sudo /opt/sbom-platform/backup.sh` |
| Restore a backup | `sudo sh /opt/sbom-platform/restore.sh /var/backups/sbom-platform/<folder>` |
| Remove the service | `sudo sh ./linux/uninstall.sh` - keeps all data |

## Option 4 - Windows Server, in Hyper-V

The platform runs in a small Linux virtual machine that ships in the bundle (`windows/`),
so the server needs neither Docker Desktop nor a signed-in user. The machine starts with
the server. Requires the Hyper-V role; on a virtual server, the host must allow nested
virtualization.

### Before you start

Each of these stopped a real installation once; checking them first saves a second attempt.

1. **Hyper-V can start machines.** On a server that is itself a virtual machine, "Hyper-V
   installed" is not enough. Test, as Administrator:
   ```powershell
   New-VM -Name nested-test -Generation 2 -MemoryStartupBytes 512MB -NoVHD | Out-Null
   Start-VM nested-test; (Get-VM nested-test).State     # Running = fine
   Stop-VM nested-test -TurnOff -Force; Remove-VM nested-test -Force
   ```
   An error instead means the host must expose virtualization to this server (VMware: *Expose
   hardware assisted virtualization*; Hyper-V host: `Set-VMProcessor -ExposeVirtualizationExtensions $true`).
2. **Memory.** The machine needs its whole memory free when it starts: 8 GB by default
   (`-MemoryGB`; a real installation runs on 6). Docker Desktop holds several GB of its own. On a
   move it must run during the data copy, but can be quit as soon as the copy is done. If the
   start fails for lack of memory, nothing has to be redone: free memory, then
   `.\install-windows.cmd -Resume -MemoryGB 6`.
3. **Script signing.** If the scripts are refused as "not digitally signed" even from the
   `.cmd` files, Group Policy requires signed scripts. `Unblock-File` does not help against
   that. Either IT signs `windows\*.ps1`, or you paste the same scripts as commands, which the
   policy allows: open `windows\install-windows-paste.txt` (or `upgrade-` / `uninstall-`) in
   Notepad, set the values at the top (`$BundleFolder`, `$MigrateFrom` ...), and paste all of it
   into PowerShell opened as Administrator. They are generated from the scripts, not a variant
   of them. If PowerShell reports *ConstrainedLanguage*, application control blocks pasting too:
   only signing helps.
4. **Moving a Docker Desktop installation:** Docker Desktop must answer (`docker ps`). If
   `docker` reports *500 Internal Server Error ... check if the server supports the requested API
   version*, its engine is stuck: restart Docker Desktop, or the server. Then stop the old web
   front end and API so no upload is lost and its ports are free; the database stays up for the
   copy: `docker compose stop web api` in its folder.

### Install

In **PowerShell as Administrator**, from the unpacked bundle:

```powershell
.\install-windows.cmd                         # new installation
.\install-windows.cmd -MigrateFrom C:\sbom    # take over the Docker Desktop installation in C:\sbom
```

- Creates the machine `SBOM-Platform` (4 CPUs, 8 GB memory, 200 GB data disk; change with
  `-Cpu`, `-MemoryGB`, `-DataDiskGB`) in `C:\SBOM-Platform` (`-InstallRoot`).
- Gives it a private network and forwards port 8080 of the server to it (`-Port`). Other
  machines use `http://<server>:8080`. **On the server itself** use
  `http://192.168.250.10:8080`: Windows does not apply the forward to the server's own traffic,
  so `localhost:8080` does not reach the machine. A reverse proxy such as IIS on the same server
  must point at `http://192.168.250.10:8080` too.
- More ports forwarded to the same port in the machine: `-ExtraPorts 443`.
- Behind a proxy: `-Proxy http://proxy:3128`.
- `-MigrateFrom` copies the database, the stored SBOMs and `.env` (so CI tokens, sign-ins and
  the Xray connection keep working), and keeps the old `PUBLIC_URL`. It also brings what that
  installation added itself, so HTTPS keeps working:
  - its `docker-compose.override.yml`, with the host files it mounts (certificate, key, proxy
    configuration), also from outside its folder, such as `C:\sbom-tls`. In the machine they
    are in `/opt/sbom-platform/migrated`, and the override points there;
  - the ports it published, such as 443: forwarded and allowed in the firewall
    (rules `SBOM-Platform-TCP-<port>`). Ports bound to `127.0.0.1` only stay closed;
  - images it uses that are not in the bundle, such as a separate proxy, copied from Docker
    Desktop, because the machine may not be allowed to download them;
  - its own certificates in `ca\`.

  The Docker Desktop installation is only read: it keeps running until you stop it with
  `docker compose stop` in its folder. Keep its data until you have checked the new installation.

**Renewing an HTTPS certificate** carried over this way: replace the files in
`/opt/sbom-platform/migrated` inside the machine, then `sudo systemctl restart sbom-platform`.

**Upgrade:** from the new bundle, `.\upgrade-windows.cmd`, or `windows\upgrade-windows-paste.txt`
(see *Before you start*, step 3). It backs up first and rolls back by itself if the new
version does not start. Forwarded ports, the override and its files are kept.

**Inside the machine** it is the Linux service of Option 3: backups at 02:30 to
`/var/backups/sbom-platform`. A shell:
`ssh -i C:\SBOM-Platform\state\vm-ssh-key sbomadmin@192.168.250.10`.
Everything that matters is on the data disk (`sbom-data.vhdx`).

---

## What the start script does

1. Checks Docker is installed **and running** - the most common failure is a
   stopped daemon, and the check turns that into a clear message.
2. `docker load` the bundled images, skipping it if they are already present.
3. On the first run only, generates a session secret, a CI ingest token, a
   database password, and an admin password, into `.env` and `CREDENTIALS.txt`.
4. `docker compose up -d`.
5. Waits until the application actually answers, not merely until the containers
   are created - the API migrates and seeds the database on first boot.

**Secrets are generated on the target, not shipped in this bundle.** Copying the
bundle to two machines gives two independent deployments rather than two
machines sharing a session-signing key.

> **If you test-run the bundle before copying it**, delete the `.env` and
> `CREDENTIALS.txt` it creates before copying the folder onward. Otherwise every
> machine you deploy to inherits the same session-signing key and the same admin
> password - exactly what generating them per machine is meant to avoid. A
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
| Back up | see [Backups](#backups) |

Never add `-v` to `docker compose down`: it deletes the volumes, that is every scan,
every application and every stored SBOM, with no undo. Upgrades never need it.

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
you something already stale. Install it once, under **Admin → Scanners → Vulnerabilities**:

| Machine | How |
|---|---|
| Has internet (even via proxy) | **Update now**. Takes a few minutes for ~141 MB. |
| Internal Grype mirror | Set `GRYPE_DB_UPDATE_URL` in `.env`, restart, then **Update now** |
| No network at all | Download the archive on a connected machine and **upload** it in the panel |

For the last case, fetch the listing on a connected machine, download the archive it names,
and upload that file through the admin panel - no host paths or container shells involved:

```sh
curl -s https://grype.anchore.io/databases/v6/latest.json
# {"status":"active","schemaVersion":"v6.1.9","built":"...",
#  "path":"vulnerability-db_v6.1.9_2026-08-17T00-15-33Z_1786947573.tar.zst","checksum":"sha256:..."}
```

The field is **`path`**, and it is a filename rather than a link - prepend the base URL
yourself:

```sh
curl -LO "https://grype.anchore.io/databases/v6/$(curl -s https://grype.anchore.io/databases/v6/latest.json | jq -r .path)"
```

Upload the `.tar.zst` exactly as downloaded - do not decompress it, and do not worry if
the browser rewrites the colons in the filename, which Windows requires. The archive is
~145 MB; `GRYPE_DB_MAX_UPLOAD_BYTES` caps the upload at 1 GiB by default, which is
separate from the SBOM ingest limit so tightening one cannot break the other.

**If "Update now" reports no internet connection on a machine whose browser reaches
`grype.anchore.io` fine, the container has not been told about your proxy.** The browser and
the API are two different clients, and a container inherits nothing from the host's browser or
system proxy settings. Set `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` in `.env` - both compose
files pass them through - and add `GRYPE_DB_CA_CERT` if the proxy inspects TLS.

Setting those variables is necessary but was not sufficient before this release, and the
reason is worth knowing if you are debugging a similar tool: the update runs a reachability
check before downloading, and that check used Node's `fetch`, which ignores the proxy
variables entirely (built-in support arrived in Node 24 behind `NODE_USE_ENV_PROXY`; the
runtime image is Node 22). Grype is a Go binary and honoured the proxy perfectly well - but
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
config shipped with 128 MB - both below the archive, both silent. Whichever limit is
lowest is the one that decides, and it should not be the one that cannot explain itself.
Allow at least 30 minutes of read timeout as well: the import expands ~1.9 GB and
validates it before swapping, and a proxy timing out mid-import kills a *working* install.

Then tick **Enable vulnerability scanning**. Every package already in the platform is
matched in the background - historical builds included - and the dashboards gain the
findings. Expect a couple of minutes for a few thousand packages.

An offline machine with no database installed is **not** a failure state. Automatic checks
report `No internet connection to <url>`, return HTTP 200, leave the previous database
untouched, and affect nothing else: ingestion, search, the dashboards and the report all
continue exactly as normal.

The database lives on the `sbom-platform_grype-db` volume and is **not worth backing up**
- it is reproducible from upstream and stale within a day. Allow it ~4 GB of disk.

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
- but keeping it accurate matters if you later put HTTPS in front.

---

## Network access

The bundle carries everything the installation needs: the container images, and on Linux
the Docker Engine too. Installing, starting, upgrading and restoring download nothing.

Once running, the platform needs outbound HTTPS (port 443) to these addresses **only**,
and only for the features you switch on. Allow them on the firewall or proxy and block
everything else:

| Address | What for | Needed when |
|---|---|---|
| `grype.anchore.io` | Grype vulnerability database | vulnerability scanning is on |
| `mirror.gcr.io` | Trivy vulnerability database | the Trivy scanner is on (`TRIVY_DB_REPOSITORY` can name an internal mirror instead) |
| `osv-vulnerabilities.storage.googleapis.com` | OSV vulnerability database | the OSV scanner is on |
| `github.com`, `codeload.github.com` | malicious-package list (OpenSSF) | malicious-package checks are on |

Your own systems, if you connect them: single sign-on (for Microsoft Entra ID,
`login.microsoftonline.com` and `graph.microsoft.com`), the mail relay, JFrog Xray, and your
Active Directory domain controllers (**LDAPS, TCP 636**, Administration → Directory). LDAPS is
not web traffic: it does not go through `HTTPS_PROXY`, so the firewall must let the platform
reach the domain controllers directly. On Windows Server that is the platform's virtual machine.

Nothing else. No package registries, no Docker Hub, no telemetry. With none of these
addresses open the platform still works fully; the databases are then installed by
uploading them in **Administration** (see [Vulnerability scanning](#vulnerability-scanning)).

Inbound, people need only the web port (`SBOM_PORT`, 8080 by default) and CI servers the
same port for `POST /api/v1/scans`.

Behind a proxy, set `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` in `.env` and restart. Every
outbound call then goes through the proxy, except the hosts in `NO_PROXY`: keep
`localhost,127.0.0.1,db,api,web` there and add internal systems reached directly, such as an
internal JFrog Xray or mail relay.

---

## Connecting Active Directory

Squads can take their members from Active Directory groups, so access follows people's real
teams: someone added to a team's AD group gets that squad's projects, someone who moves gets
the new team's, and someone who leaves or is disabled loses them. People still sign in with
single sign-on; AD only decides which squads they are in. The platform only reads AD, and
changes nothing there.

It is the **Directory** module, off until you switch it on (Administration → Directory).

### What to ask IT for

- The **domain controllers' host names**, as written on their certificates.
- **LDAPS (TCP 636)** open from the platform to those domain controllers. On Windows Server that
  is the platform's virtual machine (it leaves through the server's address). LDAPS does not go
  through `HTTPS_PROXY`. Plain LDAP (389) is not used.
- The **base DN**, for example `DC=corp,DC=example`, or the OU that holds people and groups.
- A **read-only service account** (`svc-sbom@corp.example`) and its password, ideally one that
  does not expire: when it does, the sync stops until the new one is entered.
- The organisation's **root CA certificate**, put in the installation's `ca` folder (on Windows
  Server: inside the machine, `/opt/sbom-platform/ca`), or pasted on the Directory page.
- **Which AD groups are the development teams.**
- Whether **single sign-on gives the same address as AD's `mail`**. If SSO uses the sign-in name
  instead, choose `userPrincipalName` on the Directory page.

### Setting it up

1. **Administration → Directory**: fill in the connection, **Save connection**, then **Test
   connection**. A failure names the step: server unreachable, certificate not trusted, wrong
   password, wrong base DN.
2. Switch **Directory module on**.
3. Under **Squads**, **Link to a group…** for each team. A linked squad's members can then no
   longer be changed by hand (the **Team lead** tick still can). **Unlink** keeps the members
   and makes them hand-managed again.
4. **Sync now**. The first sync always waits: check its plan (who joins and leaves which squad,
   which accounts are deactivated, who is not in the platform yet) and **Approve and apply**.

### How it behaves

- **Matching**: by email the first time, then by the person's permanent AD id. A changed address
  in AD is followed; an address that now belongs to a different AD person is refused and shown.
- **Sign-in**: every single sign-on reads the person's AD groups at once. A first sign-in creates
  the account (when *Create an account the first time somebody signs in* is on, under
  Authentication) and puts it straight into its squads. If AD does not answer within five
  seconds, the person signs in with their squads as they were.
- **Nightly sync** at 03:00 **server time**, adjustable. The Windows Server machine and the
  containers run on UTC; the Directory page shows the next run in your own time.
- **Disabled in AD**: removed from linked squads; an account that came from single sign-on is
  deactivated and signed out. Local accounts and administrators never are.
- **Safety**: a sync waits for approval when it is the first one, would remove more than 10
  people or more than 25 % of a squad, or would leave a squad empty (limits adjustable). A sync
  that cannot read AD completely changes nothing. A group deleted in AD leaves its squad as it is.
- People in a linked group with no account here are listed; they get one at their first sign-in.
- Every change is in the audit log.

### First check on a new installation

With one colleague who agrees to help:

1. Link their team's squad and **Sync now**: they appear in it.
2. They sign in with single sign-on in a private window and see their team's projects.
3. IT moves them to another team's AD group (one that is linked too); they sign in again and
   now see the new team's projects.
4. IT moves them back.

---

## Backups

Two Docker volumes hold everything:

| Volume | Contents | Back up |
|---|---|---|
| `sbom-platform_db-data` | Applications, scans, components, users, audit trail | **yes** |
| `sbom-platform_sbom-blobs` | The original CycloneDX files, gzipped | **yes** |
| `sbom-platform_grype-db` | Grype's vulnerability database | no - reproducible, and stale within a day |
| `sbom-platform_trivy-db` | Trivy's vulnerability database | no - re-downloaded from `mirror.gcr.io` |
| `sbom-platform_osv-db` | OSV.dev's per-ecosystem databases | no - re-downloaded from `osv-vulnerabilities.storage.googleapis.com` |

Back up the first **two**. Scan rows reference blobs by key and cannot regenerate them, so
a database restored without its blobs loses every raw SBOM download.

```sh
# Database - a plain SQL dump
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
startup and are transactional - a failed migration rolls back rather than
leaving a half-applied schema.

---

## Troubleshooting

**"Docker is installed but the daemon is not running"** - start Docker Desktop,
or `sudo systemctl start docker`. On Linux, if Docker needs root, run
`sudo ./start.sh`.

**Port 8080 is already in use** - `.\start.ps1 -Port 9000`.

**Directory: somebody is not put in their squad** - the sync's plan lists why: *not in the
platform yet* (they get an account at first sign-in), *no email in AD* (IT fills in `mail`), or
a conflict (their address belongs to a different AD person than before - an address reused for
a new colleague). If many people are "not in the platform" although they have accounts, single
sign-on and AD give different addresses: switch the Directory page to `userPrincipalName`.

**Directory: the sync failed or says "certificate not trusted"** - nothing was changed. Run
**Test connection** on the Directory page; it names the step and what to do.

**It started but the page will not load** - `docker compose logs api --tail=50`.
The API waits for PostgreSQL to report healthy, so a few seconds of connection
errors at startup are normal.

**"exec format error"** - the images were built for a different CPU
architecture. Rebuild the bundle with `--platform linux/amd64` (the builder does
this by default).

**Forgotten admin password** - there is no self-service reset; user emails are
login identifiers, not mailboxes. Another admin can reset it under
**Admin → Access → Users**. If no admin is reachable at all, the account can be given a
fresh password directly:

```sh
docker compose exec db psql -U sbom -d sbom \
  -c "UPDATE \"user\" SET password_hash = NULL WHERE email = 'admin@sbom.local';"
```

That leaves the account unable to sign in, so follow it by deleting the row and
letting the seed recreate it from `BOOTSTRAP_ADMIN_PASSWORD` in `.env` on the
next restart. The platform refuses to let you demote or deactivate the last
active admin precisely so this situation is hard to reach by accident.
