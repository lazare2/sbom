# Internal SBOM / Dependency Management Platform

An SBOM inventory, search, and analytics platform. CI/CD runs Syft against a built
image, posts the CycloneDX JSON here, and the platform keeps a permanent,
searchable history of every application's dependencies.

Vulnerability scanning is built in, backed by **Grype**, and **off by default**. With
it switched off the platform is exactly the dependency inventory described above. With
it on, every package is matched against Grype's vulnerability database and the findings
appear on the dashboards, in the report, and in a "who is affected by CVE-X" search.

---

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Data model + migrations | ✅ done |
| 2 | Auth (local password, RBAC) | ✅ done |
| 3 | Ingestion API + CycloneDX parsing | ✅ done |
| 4 | Application list + detail pages | ✅ done |
| 5 | Global component search | ✅ done |
| 6 | Admin panel | ✅ done |
| 7 | History / diff view | ✅ done |
| 8 | Stale detection, dashboard | ✅ done |
| 9 | Vulnerability scanning (Grype) | ✅ done |

All nine phases are implemented. Out of scope by design: any per-application or
per-squad access restriction — every authenticated user can read every application,
and the two roles are `admin` (writes) and `user` (reads).

---

## Stack

- **Postgres 16** with `pg_trgm` for partial package-name search
- **Fastify 5** + TypeScript — streaming multipart handles multi-MB SBOM uploads
- **Drizzle ORM** + drizzle-kit for typed queries and reviewable SQL migrations
- **argon2id** password hashing, Postgres-backed session cookies
- **React 19** + Vite + react-router + TanStack Query, Tailwind v4
- npm workspaces monorepo; Zod schemas in `packages/shared` are the single
  source of truth for the API contract on both sides of the wire

---

## Layout

```
packages/
  shared/                 Zod schemas + DTO types shared by API and web
  api/
    drizzle/              Generated SQL migrations (reviewed, checked in)
    src/
      config.ts           Env validation — the only place process.env is read
      context.ts          Dependency graph for the whole app
      db/schema.ts        Complete relational schema
      lib/                Errors, crypto, validation helpers
      modules/
        auth/             AuthProvider interface + local provider, sessions
        ingestion/        CycloneDX parser, purl handling, ingest service + route
        applications/     Application read API (list, detail, components)
        scans/            Scan history, scan detail, raw SBOM download
        components/       Global cross-application package search
        attributes/       Attribute definitions (read side)
        diff/             Build-to-build comparison + "no longer used" history
        dashboard/        Estate-wide aggregates
        admin/            Every write: users, applications, attributes, audit
        vulnerabilities/  Grype sweep, findings, advisory search, suppressions,
                          estate posture (vuln-report.service.ts) and the
                          app/base-image split (scope.ts)
        settings/         Admin-editable runtime settings (the scanning flag)
        health/
      plugins/            Fastify plugins: context, auth guards, error handler
      services/
        blob-store/       Raw SBOM storage (fs | s3)
        scanner/          Grype adapter: binary resolution, matching, DB updates
    test/unit/            343 tests, no database required
  web/
    src/
      lib/                API client, query hooks, URL-state, sorting, formatting
      auth/               Session context and the route guard
      components/         Layout, UI primitives, severity and findings blocks,
                          the shared vulnerability filter (VulnFilter.tsx)
      pages/              Dashboard, applications, detail, scan, diff, search
      pages/admin/        Admin panel: applications, pending, users, attributes,
                          CI tokens, vulnerability scanning, audit log
    nginx.conf            Serves the SPA and proxies /api in production
ci-templates/
  jenkins/vars/sbomScan.groovy         Shared-library step
  gitlab/sbom-scan.gitlab-ci.yml       Includable CI template
deploy/                   Copied verbatim into the offline bundle
  docker-compose.yml      Image-only compose, no build contexts
  start.ps1 / start.sh    Target-side installer: load, generate secrets, start
  README.md               Offline install, backup and upgrade guide
scripts/
  setup-local-db.ps1      One-time local Postgres role + database
  install-grype.mjs       Fetches the pinned Grype build, checksum-verified
  build-offline-bundle.ps1  Builds + saves images into a copyable folder
  smoke-test.ps1          187 end-to-end API assertions
  ui-drive.mjs            Drives the real UI in Chromium and screenshots it
                          (shots land in var/ui-shots unless a path is given)
```

---

## Running it locally

Needs Node 22+ and a PostgreSQL 14+ server. Either a native install or the bundled
`docker compose` will do — pick one.

### Option A — native PostgreSQL (Windows)

The Windows installer does not add `psql` to `PATH` and creates only the
`postgres` superuser, so one setup step is needed to create the app's role and
database:

```powershell
npm install
npm run setup:db          # prompts for your postgres superuser password
npm run db:migrate        # apply migrations
npm run db:seed           # attribute definitions + bootstrap admin
npm run dev               # API on http://127.0.0.1:3000
```

`setup:db` creates a `sbom` role and a `sbom` database owned by it, grants the
`public` schema (PostgreSQL 15+ no longer makes it world-writable), and installs
`pg_trgm` and `pgcrypto`. It is idempotent, and it never stores the superuser
password — the prompt is read into a `SecureString` and passed only to the child
`psql` process.

The `sbom` role is intentionally **not** a superuser. Migrations still work
because `pg_trgm` and `pgcrypto` are marked `trusted = true` in PostgreSQL 13+,
which lets a database owner install them. On a locked-down production server where
that is not true, have a DBA create both extensions once and the migration's
`CREATE EXTENSION IF NOT EXISTS` becomes a no-op.

### Option B — Docker, the whole stack

Runs everything in containers. Needs a `.env` at the repo root: copy
`.env.example` and set at minimum `SESSION_SECRET`, `BOOTSTRAP_ADMIN_EMAIL` and
`BOOTSTRAP_ADMIN_PASSWORD`.

```bash
docker compose up -d --build
```

That builds the API and web images, starts PostgreSQL, applies migrations, seeds
the attribute definitions and the first admin, and serves the app on
<http://localhost:8080>. nginx serves the built SPA and proxies `/api` to the
API, so the browser sees one origin and the session cookie needs no CORS
handling. Only port 8080 is published — PostgreSQL and the API are reachable
only inside the compose network.

The API container migrates and seeds on every start. Migrations are
transactional and idempotent, so restarts and a second replica starting
concurrently are both safe.

### Option C — Postgres in Docker, app on the host

Useful when you want watch-reload on the app but do not want to install
PostgreSQL:

```bash
docker compose up -d db
npm install
npm run db:migrate
npm run db:seed
npm run dev
```

### Configuration

`.env` at the repo root is loaded by every script via Node's
`--env-file-if-exists`, so there is no `dotenv` dependency and a deployment that
injects real environment variables needs no `.env` at all. Copy `.env.example`
if you need to regenerate it:

```bash
node -e "console.log(require('node:crypto').randomBytes(48).toString('base64'))"  # SESSION_SECRET
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"     # an ingest token
```

Set `BOOTSTRAP_ADMIN_EMAIL` before seeding to get a usable admin account. With
`BOOTSTRAP_ADMIN_PASSWORD` set, that password is used as-is. Leave it blank and
`npm run db:seed` generates one, prints it once, and requires it to be changed at
first sign-in.

There is no mail configuration, and none is needed. See
[Accounts and passwords](#accounts-and-passwords).

### Runtime platform

Every SBOM already says what the image is built on, and the platform reads it out:
the OS distribution from the `operating-system` component's `syft:distro:*`
properties, and language runtimes from Syft's binary classifier. It surfaces as
`Alpine 3.20.3 · Node.js 22.11.0` in four places:

| Where | What |
|---|---|
| **Overview → Operating systems / Language runtimes** | Application counts per OS and per runtime; every row links to the filtered list |
| **Applications list → "Runs on"** | Per-application chips, plus **Operating system** and **Runtime** filters |
| **Application detail → Runs on** | The current build's platform; chips link to "what else runs this" |
| **Scan detail → Build provenance** | That build's platform, so a base-image bump is visible between two scans |

The filters are the point: `?runtime=node&runtimeVersion=18.20.5` answers "which
applications are still on Node 18".

Two things this deliberately does not claim:

- **It is not the base image name.** An SBOM describes a flattened filesystem,
  not layer ancestry, so nothing here can report that the Dockerfile said
  `FROM node:22-alpine` — only that Alpine and Node 22 files are present. Two
  images from different bases with identical contents produce identical SBOMs.
- **Only a closed list of runtimes counts.** A container has dozens of binaries;
  reporting `busybox` and `bash` as "the runtime" would bury the one fact worth
  surfacing. A library merely *named* `node` is not the interpreter either — only
  binary-cataloged components are considered.

`component.kind` records whether a row is a `library`, the `os`, or a `runtime`.
All three stay searchable — "which images carry nginx" is a real question — but
the OS and runtimes are excluded from the dependency aggregates, because ranking
`alpine` alongside `log4j-core` would make the blast-radius list useless.

Scans ingested before this existed show no platform. Because the raw SBOMs are
retained, they can be filled in rather than lost:

```bash
npm run db:backfill:platform
```

That re-parses every stored blob, is idempotent, and is resumable if interrupted.

### Exact or substring name matching

Both searches take an **Exact name match** checkbox, and they default the opposite way on
purpose.

The single search defaults to **substring**, because you usually do not know the whole
name — searching `log4j` should find `log4j-core`. The cost is that a search for `react`
returns `reactive-element` and `reactor`, and if `react` itself is not deployed it returns
nothing that looks like an answer. Ticking the box switches to a case-insensitive
whole-name comparison; the two run genuinely different queries against different indexes
(`component_name_lower_idx` for exact, the pg_trgm GIN index for substring), so this is a
mode rather than a filter applied afterwards.

The list search defaults to **exact**, because a pasted list is an audit: 200 names in,
200 verdicts out. Substring matching there is available but changes what a row means — one
line can match many packages, so the row reports the count and expands to name them, and
each line is capped at 50 packages with the row saying when it hit the cap. The cap counts
packages rather than (name, version) rows; `libc6` alone ships five versions here, so a
row-based cap would let one deb package exhaust an entry's whole budget and then report
"1 package matched (partial)".

Exact is also the default the other way round for a practical reason: every list anyone has
already saved and shared was run under exact matching, and re-opening one must not silently
return a different answer.

### Sorting any table

Every table column that has a meaningful order is sortable by clicking its header. The
caret cycles `↕` → the column's **natural** direction → the reverse, and alternates from
there. There is no third click back to unsorted, because a table is always in some order;
the neutral caret means "not sorting by this column".

Natural direction comes from the column's type, declared once per table in
`packages/shared/src/schemas/sort.ts` and consumed by both ends: text opens A→Z, counts and
dates open at the largest and newest. That is the click that answers the question the column
is usually opened for.

Two things are deliberately not sortable. The `critical → low` severity breakdowns already
carry their meaning in their order, and reordering one destroys the thing it is showing.
Free-text and composite cells — an audit entry's jsonb detail, a list of versions, a
`name + version` tool cell — have no single value to order by.

The **Vulnerable Applications** and **Vulnerable Packages** rankings sort, but they are a
case worth stating plainly, because the obvious implementation is wrong. The server sends
only its worst N rows, so sorting reorders those N and nothing else: ascending shows the
least vulnerable **of the worst N**, which reads as "our safest applications" and is the
opposite of the truth. Both titles therefore carry the row count — `Vulnerable Applications
· top 10` — and both subtitles say outright that the sort does not rank the estate. The cap
is part of the answer rather than decoration; without it on screen, one click turns a
ranking into a claim it cannot support. Sorting the merged `38 / 28` findings column orders
on the ranked half alone, for the same reason the column is merged: a sort on the sum would
rank base-image age.

Underneath, the split matters more than the arrows. A **paginated** table must sort
server-side: reordering the 50 rows on screen while the other 4,000 stay put is a control
that looks like it works and answers a different question. So sort state lives in the URL
alongside the filters, and every ORDER BY ends in a **unique** column. Without that last
part, sorting on a column with duplicate values leaves tied rows in whatever order the plan
chooses, and offset pagination then genuinely loses data — the same row appearing on two
pages while another appears on none. It needs ties *and* a page boundary inside them to
reproduce, and it reads as a data bug rather than a sorting one. `scripts/smoke-test.ps1`
pages through several sorted lists with a page size of 3 and asserts the collected rows are
exactly the total, with no duplicates.

Sort columns are never interpolated from the request: each service maps its validated
`sortBy` through a `switch` over literals. The one exception is sorting the applications
list by a custom attribute, where the target is administrator-defined and cannot be a fixed
enum — safe because a jsonb key is a *value* (`attributes->>$1`) and binds as an ordinary
parameter.

### Searching a list of packages

**Package search → A list** takes a pasted list and checks all of it against the
estate at once. A different question from the single search, and the difference
shapes the output: "who ships log4j" wants applications, but "of these 40 packages
from an advisory, which are we exposed to" wants a verdict on all 40 —
**including the misses**, because if three are present the answer is mostly about
the other thirty-seven.

One package per line, with or without a version. The parser accepts the forms
people actually have on their clipboard:

| Input | Read as |
|---|---|
| `express` | every version of express |
| `express@4.19.2` | that exact version |
| `@wb-track/shared-front@2.1.0` | scoped npm name, split on the **last** `@` |
| `django==4.2.1` | pip pin |
| `django >= 4.2` | range — **specifier dropped**, name matched across all versions |
| `express 4.19.2` | whitespace, tab or comma separated |
| `pkg:npm/keyv@6.0.0` | purl; the ecosystem constrains the match |
| `com.fasterxml…:jackson-databind:2.17.2` | maven coordinate, matched on the artifact id |
| `# note` | ignored |

Parsing is **server-side** so the rules are one testable contract, `curl
--data-binary @list.txt` works, and the response can echo back how every line was
read. That echo is the point: silently misreading one line of a 200-line audit is
the failure nobody notices. Lines that parse as nothing are reported as *not
searched* rather than dropped.

Four verdicts per package, not two:

| Verdict | Meaning |
|---|---|
| **in use** | in at least one application's current build |
| **removed** | shipped once, no current build has it |
| **other version** | the package is deployed, but not at the version you asked for — the versions that *are* present are listed |
| not found | never seen in any scan |

"Other version" has to be its own answer. `express@4.0.0` being absent while
express runs at 4.19.2 in four applications is a different and far more useful
result than a bare "not found", and collapsing them would answer a security
question wrongly.

Three properties worth knowing:

- **Every list gets a shareable URL.** The list travels in a POST body — several
  hundred packages will not fit in a request line — so it is persisted and the
  results live at `/search/list/:id`. Content-addressed, so resubmitting the same
  list (reordered, re-cased, differently commented) returns the same link instead
  of accumulating rows. Only the *question* is stored: results are recomputed on
  every open, because a cached answer behind a permanent link would be stale data
  wearing a current URL.
- **Excel, not CSV.** `GET /components/bulk-search/:id/export.xlsx` returns a real
  `.xlsx` — which earns its place by carrying four sheets in one file: provenance
  and totals, the per-package verdict, the flat package × application matrix, and
  the lines that could not be parsed. Headers are frozen and filtered, because the
  first thing anyone does with a 200-row audit is filter it to the misses.
- **Scope narrows the applications, not the verdict.** Whether a package exists at
  all is always answered against full retained history, so "not found" means never
  seen — not merely absent today.

The list is capped at 1000 entries, and going over says so rather than silently
reporting on a prefix. The query passes the parsed list to Postgres as arrays and
`unnest`s them, which keeps it to four bind parameters regardless of length (a
generated `IN (…)` list would hit the 65535-parameter ceiling) and gives every
input line a row that a `LEFT JOIN` preserves even when nothing matches.

Submitting persists a row as a signed-in user, which makes this the one read-scope
route that writes. Rows are a few KB, bounded by the global rate limit, and
`package_query.last_accessed_at` is indexed so a retention sweep can be added
without a migration.

### Analytics and the PDF report

**Analytics** in the main nav, and the same content as a PDF from **Download PDF**
or `GET /api/v1/analytics/report.pdf?periodDays=30`.

Both are rendered from one `analytics.report()` call. That is deliberate: a
printed report and a screen that disagree about the same figure is the failure
that destroys trust in a reporting tool, and the only reliable prevention is for
them to be two renderings of one payload rather than two query paths that happen
to be written similarly.

| Section | What it measures |
|---|---|
| **Scan coverage** | Share of active applications with a build inside the staleness threshold. Printed above the totals, not in an appendix — it is the confidence interval on everything else |
| **Top 10 most widely deployed packages** | Blast radius: the number that decides whether a problem package is one team's afternoon or an estate-wide exercise |
| **Top 10 applications by package count** | Size, *not* risk. A big image costs more to review and patch; it is not automatically in worse shape |
| **Dependency churn** | Each application's current build against its last build from before the window |
| **Version fragmentation** | Packages the estate runs several versions of at once — standardisation targets, and the one section that names work which can be finished |
| **New to the estate** | First seen inside the window and still deployed: the supply-chain review queue |
| **Coverage gaps** | Longest-silent applications, never-scanned ones first |
| **Platform inventory** | OS and runtime counts, per [Runtime platform](#runtime-platform) |
| **Ecosystem mix** | Distinct packages by package manager |

The window (7 / 30 / 90 / 365 days) is URL state, and the PDF link carries it, so
what you print is what you were looking at. Every count that can be filtered for
links into the filtered list — a metric you cannot drill into is trivia.

**Vulnerability sections appear only when scanning is enabled.** When it is off they
are replaced by an explicit "not assessed" notice rather than by zeros, on the page and
in the PDF alike — an unscanned estate rendered as a clean one is the worst thing a
report like this could do. When it is on, the report gains estate totals, Top 10
vulnerable applications, Top 10 vulnerable packages and base-image exposure, all from the
same payload the page renders.

#### Filtering the vulnerability figures

The overview and the analytics page share one filter: **scope** (application dependencies
/ base image / both) and **severity** (Critical, High, Medium, Low, Other). It is URL
state (`?scope=app&severity=critical,high`) and the PDF link carries it, so a filtered
dashboard can be pasted into a ticket and a filtered report cannot be mistaken for a full
one — the filter is named on the PDF cover and beside the figures, and the unfiltered
totals are printed alongside as the reference point.

Four properties are load-bearing, each pinned by a test:

- **It narrows the vulnerability section only.** Severity means nothing for coverage,
  churn, fragmentation or platform mix, so those always describe the whole estate. The
  control sits inside the section rather than in the page toolbar for that reason.
- **It recounts rather than filtering rows.** Under `severity=critical`, an application's
  findings count *is* its critical count, and the rankings reorder accordingly — so "worst
  on criticals" is answerable, not just "which applications have a critical".
- **An excluded scope reads as excluded, never as zero.** `app` and `baseImage` come back
  `null`, the base-image exposure section is dropped rather than shown empty, and the page
  says "nothing here was counted, so this is not a statement that there are none". Same
  rule as the feature flag, one level down.
- **Rankings never use the combined total.** Application dependencies unless the filter
  asks for base image alone. See [Application dependencies vs base image](#application-dependencies-vs-base-image).

`Other` folds negligible together with advisories no upstream feed has rated, so the five
visible buckets always sum to the total. Unrated is a real answer rather than missing
data — promoting it to Low would invent an assessment nobody made.

Selecting every severity bucket is normalised back to selecting none, so "everything" has
one representation. Without that the page would advertise a filter that excludes nothing,
and the service would take the slow exact path to compute an answer the pre-aggregated
snapshot already had.

Three details worth knowing, because each is a number that would otherwise be
quietly wrong:

- **Churn is counted by package name, not by exact version.** A patch bump is one
  upgrade, not one addition plus one removal. Counting identities would render a
  routine dependency-update round as thousands added and thousands removed —
  true, and useless.
- **Applications with no build before the window are excluded from churn** and
  reported separately, because every package in a first build would otherwise
  register as an addition and swamp the real churn. A third count covers
  applications that did not build inside the window at all, so the three buckets
  account for every scanned application.
- **The activity chart reconciles with the scans-in-window figure.** Buckets are
  day- or week-aligned, so the first one starts earlier than the window; its lower
  bound is clamped, or the bars would total more than the number printed beside
  them.

The PDF is generated server-side with `pdfkit` — vector text in a ~12 KB file, no
headless browser in the API image, and a curl-able URL a scheduled job can archive
monthly. `Cache-Control: no-store`, because the response embeds its own generation
time and a cached copy would misreport its freshness.

### Seeing the drift tracking work

`npm run db:seed:drift` creates a single application, `drift-demo-service`, with
five hand-written builds covering every category of change exactly once, and
prints the expected result so the UI can be checked against it:

| Package | What happens across the five builds |
|---|---|
| `lodash 4.17.21` | present in all five — must **never** appear as removed |
| `express` | upgraded once, so `4.18.2` is gone |
| `log4j-core` | upgraded twice, leaving **two** dead versions behind |
| `request 2.88.2` | dropped in build 103 and never came back |
| `moment` | dropped in 103, **returned** in 104 at `2.30.1` |
| `openssl` | rolling OS patches, two dead versions |
| `axios` | added in 103, upgraded in 105 |
| `commons-io 2.11.0` | shipped in build 104 only, then dropped |

Open **drift-demo-service → No longer used**. It lists 9 rows. Tick *Hide
version upgrades* and it drops to 2: `request` and `commons-io` — the only two
packages with no remaining version.

`moment 2.29.4` is the row worth understanding. It appears in the default view
because that exact version really is gone, and disappears under the filter
because `moment 2.30.1` is back. Which of those two answers is the useful one
depends on whether you are chasing a specific bad release or asking whether a
dependency was dropped at all, which is why both views exist.

The expected table is computed in the seed script independently of the SQL that
serves the page, so the two agreeing is a real check rather than a tautology.

### Deploying from a git clone

The target needs **Docker and git**, nothing else — no Node, no npm, no
PostgreSQL, no compiler. Everything is built inside the images.

```bash
git clone <repo-url> sbom
cd sbom
cp .env.docker.example .env     # then set SESSION_SECRET and BOOTSTRAP_ADMIN_PASSWORD
docker compose up -d --build
```

The first build takes several minutes: it installs dependencies, compiles both
workspaces, and downloads the Grype binary. Then open `http://localhost:8080`.

Use `.env.docker.example`, **not** `.env.example`. The latter configures a
native development run — `DATABASE_URL` on `localhost` and `PUBLIC_URL` on the
Vite port — and a compose deployment that inherits `PUBLIC_URL=…:5173` rejects
the browser's requests as a cross-origin.

Data lives in three named Docker volumes rather than in the clone, so
`docker compose down`, a reboot, a `git pull`, or a rebuild all leave it intact.
Only `docker compose down -v` destroys it. See
[Backups](deploy/README.md#backups).

Pulling the published images instead of building is the lighter path when the
machine can reach a registry — two files and no build. See
[deploy/README.md](deploy/README.md).

### Deploying to a machine with no internet

`npm run bundle:offline` produces a folder that runs the whole platform —
PostgreSQL included — on a machine that has only Docker. No Node, no npm
registry, no PostgreSQL install, no compiler for the argon2 native module.

```powershell
npm run bundle:offline            # ~330 MB in dist-offline/
```

Copy the folder across, then on the target:

```powershell
.\start.ps1          # Windows
./start.sh           # Linux / macOS
```

It loads the bundled images, generates a session secret, a CI ingest token, a
database password and an admin password **on that machine**, brings the stack
up, and waits until it actually serves before reporting success. Open
`http://localhost:8080` and sign in with the `CREDENTIALS.txt` it writes.

Secrets are generated on the target rather than baked into the bundle, so
copying it to two machines produces two independent deployments instead of two
machines sharing a signing key. Build it on a connected machine; the build pulls
base images and npm packages.

Full details, backups, and upgrades: [deploy/README.md](deploy/README.md).

### Commands

| Command | Needs Postgres | Needs `npm run dev` | What it does |
|---|---|---|---|
| `npm test` | no | no | Unit tests (343) — pure logic plus PDF and Excel output, no I/O |
| `npm run typecheck` | no | no | Typecheck all workspaces |
| `npm run build` | no | no | Compile all workspaces |
| `npm run setup:db` | yes | no | One-time: create the local `sbom` role and database |
| `npm run db:migrate` | yes | no | Apply pending migrations |
| `npm run db:seed` | yes | no | Attribute definitions + bootstrap admin |
| `npm run db:generate` | no | no | Generate a migration after editing `db/schema.ts` |
| `npm run db:studio` | yes | **no** | Browse the database in a web UI |
| `npm run db:seed:demo` | yes | no | Generate demo applications and scan history |
| `npm run db:seed:drift` | yes | no | One application with a hand-designed drift history (see below) |
| `npm run db:backfill:platform` | yes | no | Fill in OS/runtime for scans ingested before that existed |
| `npm run dev` | yes | — | Start the API with watch-reload |
| `npm run dev:web` | yes | yes | Start the frontend on :5173 |
| `npm run smoke` | yes | **yes** | 174 end-to-end API assertions (cleans up after itself) |
| `npm run grype:install` | no | no | Fetch the pinned Grype build into `var/bin/` (checksum-verified) |
| `npm run ui:drive` | yes | **yes** + `dev:web` | Drive the UI in Chromium, screenshot each view |
| `npm run bundle:offline` | no | no | Build the offline Docker bundle (needs Docker + internet) |

`npm run smoke` is an HTTP client, so the API has to already be running in another
terminal — it checks this first and tells you if it isn't. `npm run db:studio`
talks to Postgres directly and does not care whether the API is up; note that it
serves its UI from the hosted `local.drizzle.studio` frontend over a local
websocket, so the page needs internet access even though your data stays local.

Schema changes always go through `db:generate` and are reviewed as SQL. Never push
a schema directly.

### Trying the ingest endpoint by hand

```bash
# Generate a real SBOM if you have syft, or use any CycloneDX JSON file.
syft alpine:latest -o cyclonedx-json=sbom.json

curl -f -H "Authorization: Bearer <token from INGEST_TOKENS in .env>" \
  -F sbom=@sbom.json \
  -F app_name=my-test-app \
  -F build_number=1 \
  http://127.0.0.1:3000/api/v1/scans
```

`my-test-app` does not need to exist — it is auto-created with status
`pending_confirmation`.

---

## The UI

Two dev servers: `npm run dev` (API, :3000) and `npm run dev:web` (frontend, :5173).
Open <http://localhost:5173>.

The Vite dev server proxies `/api` to the API rather than relying on CORS. That is
deliberate — it makes the app same-origin in development exactly as it is behind
nginx in production, so the session cookie behaviour being tested locally is the
real one. A CORS-relaxed dev setup can hide a cookie problem until deploy.

**Applications** lists the inventory with filters for name, squad, owner, severity,
status, and staleness, plus sortable columns. Unconfirmed applications are shown to
everyone with a badge; inactive ones are hidden until asked for.

**Overview** is the landing page: application counts by status, stale and
never-scanned counts, scan volume, the ecosystem mix, and the packages deployed in
the most applications — the blast-radius list, which is the figure that decides
whether a bad package is one team's afternoon or an organisation-wide exercise.
Every counter that can be filtered for links into the filtered list.

**Package search** has two modes behind one toggle. *One package* answers who
ships X, now or at any point in history. *A list* checks a whole pasted list at
once and reports a verdict per package — see
[Searching a list of packages](#searching-a-list-of-packages).

**Analytics** is the reporting view: coverage, the two top-10 rankings, dependency
churn over a selectable window with a scan-volume trend, version fragmentation,
packages new to the estate, coverage gaps, and the platform and ecosystem
breakdowns — downloadable as a PDF. See
[Analytics and the PDF report](#analytics-and-the-pdf-report).

**Application detail** has four tabs:

| Tab | What it shows |
|---|---|
| Current components | The latest build's dependencies |
| Latest build changes | Removed / version-changed / added against the previous build |
| No longer used | Everything ever shipped that the current build does not contain, each with the build it was last seen in |
| Scan history | Every build that submitted an SBOM, plus **Upload SBOM** |

Any historical build opens its own page with that build's component list and
provenance — commit, branch, image, Syft version, and the SBOM SHA-256, so a
downloaded SBOM can be verified against what was uploaded. "Compare with previous"
opens a diff of any two builds, with the pair in the URL.

**Upload SBOM** on the Scan history tab takes a CycloneDX file and processes it
exactly as a pipeline's — it becomes the application's current build. The dialog
says so before you submit, because that is the consequence someone needs to know
about rather than discover. Rows uploaded this way carry a `manual` badge whose
tooltip names the uploader, and the build page shows *Uploaded by* where a CI scan
shows its ingest token, along with the reason given. CI scans are not badged: the
overwhelming default labelled on every row is noise, but a hand-uploaded build
that looked identical to a pipeline's would misrepresent where the data came from.
Full contract in
[`POST /api/v1/applications/:id/scans`](#post-apiv1applicationsidscans).

*Latest build changes* folds a version bump into a single `changed` row rather
than reporting it as one removal plus one addition. On a typical build almost
every difference is an upgrade, and without that folding the genuine adds and
drops are buried. Where the pairing is ambiguous — two versions added, one removed
— the rows stay unpaired rather than being matched arbitrarily.

**Package search** answers the cross-application question. The usage selector is
the point of the page:

| Scope | Question it answers |
|---|---|
| Currently used | Which applications ship this package today? |
| Previously used, not now | Which applications *dropped* it — and in which build was it last seen? |
| Both | Everything, labelled |

The second scope is why full scan history is retained. Results link to the exact
build a package was last seen in.

All filter and pagination state lives in the URL, so a filtered view can be pasted
into a ticket and opens the same way for the next person.

### Admin panel

Visible only to admins, at `/admin`.

- **Applications** — register one before its first scan so CI lands on a confirmed
  record with its attributes already set, edit name / status / attributes, or
  delete. Deleting destroys the scan history; *inactive* exists so "we don't build
  this any more" does not require that.
- **Awaiting confirmation** — the triage queue for applications the ingest endpoint
  auto-created because `app_name` matched nothing. Four resolutions: confirm,
  merge once, merge and record a permanent alias, or delete. *Merge always* is the
  one that fixes the cause rather than the occurrence: the alias redirects every
  future build posting that name.
- **Users** — create accounts, change roles, deactivate, delete, and reset
  passwords. The last active admin cannot be demoted, deactivated or deleted, and
  an admin cannot do any of those to their own account.
- **Attributes** — add, edit, hide, or delete the attribute definitions. Deleting
  one that applications still carry values for is refused with the count, and
  offers to purge those values as a separate, deliberate step.
- **CI tokens** — mint and revoke ingest tokens. Environment-configured tokens are
  listed too, marked as such, because listing only database rows would report "no
  tokens" on a deployment where CI is authenticating perfectly well.
- **Audit log** — every administrative write, kept indefinitely. This exists mainly
  for merges: a merge moves scan history between applications and then deletes the
  source, so without it "why does this app have someone else's builds" is
  unanswerable.

### Accounts and passwords

User "emails" are **login identifiers, not mailboxes**. The platform never sends
mail — no invites, no notifications, no reset links — so nothing needs an SMTP
server and `admin@localhost` is a perfectly valid account.

That makes password recovery entirely admin-driven:

1. An admin creates the account, or resets an existing one, in the admin panel.
2. The password is generated (or typed) and shown **once**. Only its argon2 hash
   is stored; it cannot be retrieved again. If it is lost, reset again.
3. The account is flagged `must_change_password`. The user can sign in and read
   their own identity, but every other route returns
   `403 password_change_required` until they choose their own password.

Step 3 is enforced server-side, not just by the client redirect: an admin-issued
password has by construction been seen by someone other than its owner, often via
a chat message. Re-entering the issued password as the "new" one is rejected for
the same reason. Resetting a password also revokes every live session for that
account immediately — which is why sessions are Postgres-backed rather than JWTs.

---

## Vulnerability scanning

Built in, backed by [Grype](https://github.com/anchore/grype), and **off by default**.
Enable it under **Admin → Vulnerability scanning**.

Grype ships inside the container image (`COPY --from=anchore/grype:v0.115.0`), pinned so
findings are reproducible — results shift between releases, and the database schema is
tied to the binary version. On a native install, `npm run grype:install` fetches the same
pinned build into `var/bin/` after verifying its SHA-256 against a checksum committed in
the script. Binaries already on `PATH` are used as-is.

The **vulnerability database is not in the image.** It is ~141 MB compressed, expands to
~1.9 GB, and Anchore rebuilds it about daily, so a baked copy would arrive stale and
triple the image size. It lives on a volume and is fetched at runtime when an
administrator asks for it. A fresh `docker compose up` downloads nothing.

### How findings are stored, and why it matters

Findings are keyed on the **component**, not the scan — `component_vulnerability` joins a
package version to an advisory. Three things follow:

- **Re-evaluating the whole estate after a database update is one pass over distinct
  packages.** Measured: 50,000 components in ~1m41s, against ~9s *per application* if each
  build were scanned separately. That is what makes "rescan everything when the database
  changes" cheap enough to do on every update.
- **Every retained build is re-evaluated for free.** Opening a release from six months ago
  shows what is known *today*, so a CVE published this morning immediately lists the
  applications that have been shipping the affected version for months.
- **Unconfirmed applications are covered with no special handling.** An SBOM whose
  `app_name` matched nothing still auto-creates a `pending_confirmation` application, its
  components are matched like any others, and its vulnerabilities are visible immediately.

There is no job queue. The work list is derived from two columns:

```sql
WHERE vuln_scanned_at IS NULL
   OR vuln_db_built_at IS NULL
   OR vuln_db_built_at < <installed database build>
```

Installing a database moves the build timestamp, which makes every package pending again.
The same expression covers a newly ingested package, the first time scanning is enabled, a
new database, and a sweep killed halfway — so a restart needs no recovery logic, because
there was never a queue to lose.

### Application dependencies vs base image

Every count is reported in two groups. Measured on a realistic container SBOM: **2,845
findings, 2,817 of them (99%) from base-image OS packages.**

The dashboards show a combined total *and* the split, with the split given the visual
weight — the combined figure is the one that gets quoted in a meeting, and on a typical
estate it is mostly a statement about base-image age. **No ranking is ever computed on the
combined figure**: **Vulnerable Applications** ranks on application dependencies (or on
base image alone, if the filter excludes dependencies), because ranking on the sum would
order applications by base-image age and bury the handful of findings a team actually chose
and can act on. Each row shows both halves in one column — `38 / 28` — so the pair reads as
a pair rather than as two numbers to add up.

### One row per advisory

The estate advisory table on the vulnerabilities tab answers the other direction: not "how
bad is this application" but "how far does this CVE reach". One row per advisory, with the
packages it affects, the applications running them now, and the applications that dropped it.

The package cell is a **count that expands to the packages behind it**, and the reason it is
a count at all is that one advisory affects many packages — there is no single name to put in
the cell. The list travels on the row rather than being fetched when opened, which is a
correctness constraint rather than an optimisation: the app/base-image split is a shared SQL
predicate rather than a column, so a list fetched from the per-advisory endpoint could not be
narrowed to the same scope, and a scoped count of 3 above an unscoped list of 8 is a
contradiction the reader cannot resolve. One query, one WHERE clause, no disagreement
possible. Entries are keyed on name **and** version to match what the count counts — eight
vulnerable versions of `openssl` is one name and eight rows, and the difference is the whole
finding.

A **top ten by blast radius** sits on the overview and analytics tabs. It defaults to
applications-reached descending, where the full table defaults to severity: a glance surface
answers "where are we most exposed", while a triage list must not bury a critical in one
application under a low-severity advisory in eight.

Both halves report the same figures, including fix availability and known-exploited counts.
That symmetry is why `scan_vuln_summary` carries `os_fixable` and `os_known_exploited`: "is
a rebuild going to fix this" is the first question a reader has when they select base image
as a scope, and it cannot be answered from a severity breakdown.

The split is by **ecosystem**, not by `component.kind`, and that distinction is subtle
enough to be worth stating: only the distro *marker* (`alpine 3.20`) is stored as
`kind = 'os'`. The ~1,500 individual `pkg:deb/debian/...` entries in a real Syft SBOM are
ordinary CycloneDX `library` components. Splitting on `kind` looks right on synthetic data
and silently files the entire base image under "application dependencies" on real data.
One definition lives in `modules/vulnerabilities/scope.ts` and every query uses it.

### Ingest stays fast

`POST /api/v1/scans` returns **201 as soon as the SBOM is stored**, exactly as before.
Matching happens in a background worker and findings appear seconds later. Synchronous
matching would put Grype's runtime on every build (~9s for a 3,000-package image) and would
force an impossible choice when Grype fails: fail a build whose SBOM stored perfectly, or
return 201 while silently recording no vulnerabilities.

Two settings are forced on every Grype invocation. `GRYPE_DB_AUTO_UPDATE=false` because
Grype otherwise downloads a database mid-scan — measured at **96s versus 1.8s** for the
same match — which on the ingest path would stall a CI request and on an air-gapped host
would fail it. `GRYPE_DB_VALIDATE_AGE=false` because Grype refuses to match against a
database older than five days, and a stale database still produces useful findings; the
age is reported prominently instead.

### Database updates

Automatic on a schedule (**default 3 hours**, editable in the panel, bounded 30 minutes to
7 days) and on demand with **Update now**. Both check the listing URL first, so an offline
deployment gets a precise answer:

```
No internet connection to https://grype.anchore.io/databases/v6/latest.json
```

That is reported as a **state, not a failure**: HTTP 200 with `outcome: "unreachable"`, the
previously installed database untouched, and nothing else in the platform affected.
Ingestion, search, the dashboards and the report all continue exactly as normal. A
permanently offline server does not log an error every three hours — the staleness warning
in the panel is the signal.

An update and a sweep are **mutually exclusive**, and the exclusion runs in both
directions. Installing a database means deleting the old file, and a sweep holds that file
open through the grype process it spawns. On Windows the unlink then fails — and it fails
*after* grype has removed `import.json`, so a working installation is left
present-but-invalid by an update that never landed. POSIX unlink-while-open hides the
symptom, but a sweep matching against a file being swapped underneath it would attribute
its findings to the wrong database build, so both orderings are refused everywhere:
`outcome: "busy"`, nothing written to the history table, and the scheduler retries on its
next tick. See `packages/api/test/unit/vuln-db-exclusion.test.ts`.

Installing by hand, for a host with no route to the listing at all: fetch
`latest.json`, take its **`path`** field — a filename, not a link — prepend the base URL,
and upload the `.tar.zst` under **Admin → Vulnerability scanning**. The upload ceiling is
`GRYPE_DB_MAX_UPLOAD_BYTES` (1 GiB), deliberately separate from `INGEST_MAX_SBOM_BYTES`:
they differ by more than an order of magnitude, and sharing one limit meant tightening the
ingest limit silently broke the only install path an air-gapped deployment has.

Anchore rebuilds roughly daily, so a 3-hour check is a small listing request that usually
transfers nothing, not eight 141 MB downloads a day.

For an air-gapped machine, **Import from file** takes the `.tar.zst` archive through
`grype db import`, with no network involved.

### What the admin panel shows

Scanner and database are reported **separately**, because they fail independently and need
different fixes. When the binary is missing, every resolution rule that was tried is listed
with the reason it failed — "not found" alone tells nobody where to put it.

There is deliberately **no field for the binary path.** A web form that sets an executable
the server then runs is a remote-code-execution primitive, and this project is meant to be
published; a default-on field like that becomes every deployer's vulnerability. The path is
`GRYPE_PATH` in the environment, where changing it needs deployment access.

### Accepted risks

An admin can accept a finding as a risk, with a required reason, scoped to one package
version, one application, or the whole estate. Accepted findings are **excluded from every
count and ranking but never deleted** — a dashboard that only grows is one people stop
reading, and a silently dropped finding is one nobody can audit later. They stay listed
under Accepted risks with who accepted them and why.

### Disabled means "not assessed", never "zero"

The one invariant worth stating on its own. With scanning off:

- Read endpoints answer **409 `vuln_scanning_disabled`**, not an empty list.
- `analytics/report` and `dashboard/vulnerabilities` return `vulnerabilities: null`, not a
  zero-filled object.
- The nav item, the application tab and the dashboard cards are **absent**.
- The PDF prints "Not assessed … the absence of findings below is not a clean result —
  nothing was checked", and its methodology note tracks the flag.

An empty findings list means the packages were checked and are clean. Rendering an
unassessed estate the same way would be the most damaging thing this feature could do, so
the two are distinguished at the status-code level and the client has to handle it
explicitly rather than being able to fall into a plausible-looking zero.

The same rule applies to the dashboard filter, one level down. A scope the filter excluded
comes back as `null` rather than as zeros, the base-image exposure section is dropped rather
than rendered empty, and the panel says *"nothing here was counted, so this is not a
statement that there are none"*. Nullable types are what enforce it: a consumer cannot read
`app.counts.critical` without first deciding what to do when `app` is absent.

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `GRYPE_PATH` | unset | Explicit binary path. Highest-priority resolution rule. |
| `GRYPE_DB_CACHE_DIR` | `./var/grype-db` | Where the ~1.9 GB database lives. **Must be a volume in a container.** |
| `GRYPE_DB_UPDATE_URL` | `https://grype.anchore.io/databases` | Point at an internal mirror to keep traffic inside the network. |
| `GRYPE_DB_CA_CERT` | unset | CA for a mirror behind a TLS-inspecting proxy. |
| `GRYPE_BATCH_SIZE` | `5000` | Packages per Grype invocation. Bounds memory and gives the sweep resume points. |
| `GRYPE_SCAN_TIMEOUT_MS` | `600000` | Per-batch match timeout. |
| `GRYPE_DB_UPDATE_TIMEOUT_MS` | `1800000` | Download timeout — 141 MB on a slow link. |
| `GRYPE_REACHABILITY_TIMEOUT_MS` | `8000` | Listing probe. Short: it only answers "is there a route". |

Whether scanning is **on**, and the check interval, are not here — they are admin-editable
rows in `setting`, because they are runtime decisions rather than deployment ones.

Plan **~4 GB** for the database volume: 1.9 GB installed, plus the archive and its
expansion during a replacement.

---

## Ingestion API

### `POST /api/v1/scans`

`multipart/form-data`, authenticated with `Authorization: Bearer <ingest-token>`.

| Field | Required | Notes |
|---|---|---|
| `sbom` | yes | CycloneDX JSON file from `syft -o cyclonedx-json` |
| `app_name` | yes | Matched case-insensitively against application names, then aliases |
| `commit_sha` | no | |
| `build_number` | no | |
| `pipeline_id` | no | |
| `image_ref` | no | Falls back to the SBOM's `metadata.component` name |
| `branch` | no | |

```bash
curl -f -H "Authorization: Bearer $SBOM_TOKEN" \
  -F sbom=@sbom.json \
  -F app_name=payments-api \
  -F commit_sha=$GIT_COMMIT \
  -F build_number=$BUILD_NUMBER \
  -F image_ref=registry.example.com/payments/api:1.42.0 \
  -F branch=main \
  https://sbom.internal.example.com/api/v1/scans
```

Status codes are the contract, because pipelines call this with `curl -f`:

| Code | Meaning |
|---|---|
| 201 | Scan committed and queryable |
| 400 | Malformed request (missing/empty `sbom`, invalid `app_name`) — retrying won't help |
| 401 | Bad or revoked ingest token |
| 413 | SBOM exceeds `INGEST_MAX_SBOM_BYTES` |
| 415 | Not `multipart/form-data` |
| 422 | File is not a CycloneDX SBOM |
| 5xx | Transient — safe to retry |

**An unknown `app_name` is not an error.** It auto-creates an application with
status `pending_confirmation` and ingests the scan against it. Losing a build's
SBOM because nobody pre-registered the repo would be worse than giving an admin a
queue to resolve.

### `POST /api/v1/applications/:id/scans`

The same ingestion, reached by a signed-in person instead of a pipeline. Used by
the **Upload SBOM** button on an application's Scan history tab, for the case
where a pipeline is not wired up yet — or not wired up at all — and someone has a
CycloneDX file in hand.

`multipart/form-data`, authenticated with the **session cookie**. An ingest token
does *not* work here, and that is deliberate: the two auth mechanisms live in
separate plugin scopes so they cannot cross over, and a CI token able to post
against an arbitrary application id would bypass `app_name` resolution, aliasing
and pending auto-creation entirely.

| Field | Required | Notes |
|---|---|---|
| `sbom` | yes | CycloneDX JSON, same parser and same `INGEST_MAX_SBOM_BYTES` limit |
| `commit_sha` | no | |
| `build_number` | no | |
| `image_ref` | no | Falls back to the SBOM's `metadata.component` name |
| `branch` | no | |
| `note` | no | Why this was uploaded by hand; shown on the scan detail page |
| `allow_duplicate` | no | `true` to store an SBOM this application already holds |

**The resulting scan is a normal scan.** It becomes the application's current
build, its packages are searchable across the estate, and it appears in diffs, the
dashboard and the analytics report. This is enforced structurally rather than by
convention: the route calls `IngestionService.ingestManual()`, which shares one
private `store()` with the CI path, so the two cannot drift.

Four differences from the CI endpoint, each because a human is on the other end
rather than a `curl -f`:

1. **The application comes from the URL.** Nothing is auto-created; an unknown id
   is a 404. Someone uploading from a page they navigated to has already chosen
   the target, and letting the SBOM's contents redirect it elsewhere would be a
   surprise, not a convenience.
2. **A byte-identical re-upload is a 409**, whose `error.details` names the
   existing scan so the UI can link to it. A double-clicked button is far more
   likely than a genuine need for the duplicate. Serialised by a per-application
   advisory lock, so the check is a guarantee rather than a race. The CI endpoint
   keeps the old behaviour — a pipeline re-scanning an unchanged artifact produces
   identical bytes legitimately, and failing that would break builds over a
   non-problem.
3. **The uploader is recorded** on the scan (`source`, `uploaded_by_user_id`,
   `uploaded_by_email`) and on the admin audit log as `scan.manual_upload`.
4. **20 requests/minute**, against the CI endpoint's 600. Nobody uploads SBOMs by
   hand at pipeline speed.

```bash
curl -f -b cookies.txt \
  -F sbom=@sbom.json \
  -F build_number=402 \
  -F branch=main \
  -F 'note=pipeline not wired up yet' \
  https://sbom.internal.example.com/api/v1/applications/$APP_ID/scans
```

**Any authenticated user may upload, not only admins.** This matches the trust
level of the path it mirrors: CI ingest is authenticated by a token shared across
pipelines, auto-creates applications with no human approval, and is usable by any
pipeline author. Restricting the *named, audited* equivalent to admins while
leaving the anonymous-by-design one open would be backwards, and it would block
the case the feature exists for. The write is also append-only — history is never
overwritten, and a wrong upload is corrected by uploading the right one. To make
it admin-only, change the single `fastify.requireAuth` hook in
`manual-upload.routes.ts` to `fastify.requireAdmin`.

### Ingest tokens

Tokens attest "a trusted CI system is calling", not which application is
reporting — application identity comes entirely from `app_name`. Configure them
two ways:

- `INGEST_TOKENS=jenkins:<token>,gitlab:<token>` in the environment (also the
  break-glass path if every DB token is revoked)
- Named rows in `ingest_token`, created through the admin API, individually
  revocable

Only SHA-256 hashes are stored. A leaked token can write a scan under any
application name; named tokens exist so the blast radius can be scoped and
rotated per environment.

---

## The rest of the API

All under `/api/v1`, authenticated with the session cookie. Read routes need any
signed-in user; everything under `/admin` needs `role = admin`.

### Read

| Route | Purpose |
|---|---|
| `GET /applications` | List with search, attribute filters, staleness, sorting |
| `GET /applications/:id` | Detail, including CI aliases |
| `GET /applications/:id/components` | Current build's packages |
| `GET /applications/:id/scans` | Scan history, each row carrying `source` and `uploadedByEmail` |
| `POST /applications/:id/scans` | Manual SBOM upload — see the ingestion section above |
| `GET /applications/:id/removed-components` | Ever shipped, not in the current build, with last-seen build |
| `GET /applications/:id/diff` | Compare two builds; defaults to latest vs. previous |
| `GET /scans/:id` | Build provenance, with previous/next ids |
| `GET /scans/:id/components` | That build's packages |
| `GET /scans/:id/raw` | The original CycloneDX bytes, as uploaded |
| `GET /components/search` | Cross-application package search (`scope=current\|historical\|all`) |
| `POST /components/bulk-search` | Search a pasted package list; returns a verdict per line and a saved-list id |
| `GET /components/bulk-search/:id` | Re-run a saved list, with its original text |
| `GET /components/bulk-search/:id/export.xlsx` | The results as a four-sheet Excel workbook |
| `GET /components/bulk-search` | Recently searched lists |
| `GET /dashboard/stats` | Estate counters |
| `GET /dashboard/top-components` | Packages by application count |
| `GET /dashboard/platforms` | OS and runtime counts; also the filter options |
| `GET /analytics/report` | The whole estate report as JSON (`?periodDays=7\|30\|90\|365`, plus the vulnerability filter) |
| `GET /analytics/report.pdf` | The same report as a PDF, curl-able and date-stamped. Accepts the same filter, and prints it |
| `GET /vuln-status` | Whether scanning is enabled, database age, sweep coverage. Readable when disabled |
| `GET /vulnerabilities` | Estate-wide advisory search — "who is affected by CVE-X". 409 when disabled |
| `GET /vulnerabilities/:id` | One advisory's blast radius: applications and the packages carrying it |
| `GET /applications/:id/vulnerabilities` | Findings for an application's current build, with the app/base-image split |
| `GET /scans/:id/vulnerabilities` | Findings for one build, evaluated against today's database |
| `GET /dashboard/vulnerabilities` | Estate posture for the overview. `null` when disabled. `?scope=app\|os\|all&severity=critical,high,…` |

### Admin

| Route | Purpose |
|---|---|
| `POST/PATCH/DELETE /admin/applications[/:id]` | Register, edit, delete |
| `POST /admin/applications/:id/confirm` | Resolve a pending application |
| `POST /admin/applications/:id/merge` | Merge into another, optionally aliasing |
| `POST/DELETE /admin/applications/:id/aliases` | Manage CI name aliases |
| `GET/POST/PATCH/DELETE /admin/users[/:id]` | Account management |
| `POST /admin/users/:id/reset-password` | Issue a new password, returned once |
| `POST/PATCH/DELETE /admin/attribute-definitions[/:id]` | Attribute schema |
| `GET/POST/DELETE /admin/ingest-tokens[/:id]` | CI credentials |
| `GET /admin/vuln/status` | Scanner, database, schedule and coverage, reported separately |
| `PATCH /admin/vuln/settings` | Enable/disable scanning; set the check interval |
| `POST /admin/vuln/update` | Update the database now. 200 with `unreachable` when offline |
| `POST /admin/vuln/import` | Install a database from an uploaded archive (air-gapped) |
| `POST /admin/vuln/sweep` | Match any pending packages now |
| `GET /admin/vuln/history` | Every update attempt, including the ones with no route to the internet |
| `GET/POST/DELETE /admin/vuln/suppressions[/:id]` | Accepted risks |
| `GET /admin/audit-log` | Administrative history |

---

## Design decisions worth knowing

**Attributes are JSONB, not columns.** `application.attributes` holds squad /
owner / severity, described by rows in `attribute_definition`. Adding a fourth
attribute is an admin action, not a migration. GIN-indexed for filtering.

**Vulnerability findings are keyed on the package, not the build.** The consequence
worth knowing: re-evaluating the whole estate after a database update is one pass over
distinct components (~1m41s for 50,000) instead of one Grype run per application (~9s
each), and every historical build is re-evaluated for free. The trade is that a scan does
not carry a frozen record of what was known on its own scan date — `scan_vuln_summary`
keeps per-scan severity counts for that, which also serve as the pre-aggregation the
rankings read so they touch one row per application rather than millions of
`scan_component` rows.

**Manual upload and CI ingest are one code path, not two.** `ingest()` and
`ingestManual()` are thin wrappers over a private `store()` that does the parsing,
blob write, component linking and current-build pointer update. The alternative —
a second write path for the UI — is how a platform ends up with hand-uploaded
scans that are missing from search or that never became the current build, and
those failures look fine on the page that created them and are invisible
everywhere they matter. What differs between the two is pushed to the edges:
`IngestTarget` decides whether the application is resolved from a name or looked
up by id, and `Provenance` carries the token name or the uploader.

**A failed statement aborts the whole Postgres transaction, so catching a unique
violation and recovering inside it does not work.** `resolveApplication` used to
insert the auto-created application, catch `23505` when a concurrent build won the
race, and re-read the winner's row. The recovering SELECT died with `25P02`
("current transaction is aborted") and the loser got a 500 — reproducibly, 9 times
in 10. `ON CONFLICT DO NOTHING` never raises, so the transaction stays usable. This
is the shape to reach for anywhere a write races on a unique index; a `SAVEPOINT`
is the other option, but it is more moving parts for the same outcome. Pinned by a
smoke assertion that fires both requests with `curl --parallel`.

`scan.source` is stored explicitly rather than inferred from
`uploaded_by_user_id IS NOT NULL`. The uploader reference is `ON DELETE SET NULL`,
so deleting an account would otherwise silently reclassify their uploads as CI
scans — and the whole point of the column is that a hand-uploaded build can always
be identified as one.

**Report output is generated server-side, from one payload.** `pdfkit` for the
analytics PDF and `exceljs` for the package-list workbook, rather than
HTML-to-PDF through a headless browser: the API image stays free of a 300 MB
Chromium, and both endpoints are plain curl-able GETs a scheduled job can archive.
Both render from the same service call the screen uses, because a printed
artifact and a UI that disagree about a figure is the failure that destroys trust
in a reporting tool.

`exceljs` pulls in `uuid@8`, which `npm audit` flags (moderate) for a missing
buffer bounds check in v3/v5/v6 when the caller supplies a `buf`. Not reachable
here: exceljs imports only `v4` and calls it with no arguments, in one file that
generates conditional-formatting ids.

**Sessions, not JWT.** An admin deactivating a user has to take effect on the next
request, which means a revocation lookup per request regardless — at which point a
JWT's only remaining advantage is gone, and it brings refresh-token complexity
with it. Cookie values are stored as SHA-256 hashes.

**Auth is behind an interface.** `AuthProvider` (`modules/auth/provider.ts`) has
three capability flags — `canProvisionOnLogin`, `supportsPasswordReset`,
`supportsPasswordChange` — that correspond exactly to how LDAP differs from local
passwords. Adding LDAP means writing one class and registering it in
`context.ts`; no route, session, or permission code changes.

**The admin guard is a scope, not a per-route annotation.** Every route in
`modules/admin/admin.routes.ts` sits behind one `requireAdmin` hook applied to the
whole plugin scope, so a route added to that file is protected whether or not its
author thought about it. A per-route `preHandler` is protected only if someone
remembered. A wiring test asserts the whole scope rejects anonymous callers.

**Merges run in one transaction, and reassign before deleting.**
`scan.application_id` is `ON DELETE CASCADE`, so deleting the source application
first would destroy the history the merge exists to preserve. Scans and their
denormalised `scan_component.application_id` move together, then the destination's
`latest_scan_id` and counters are fully recomputed rather than incremented —
merged builds can interleave with the target's own history, so the newest scan
overall may come from either side.

**Component identity is the purl, not name+version+ecosystem.** Two deb entries
can share a name and version but differ by architecture or epoch, which the purl
qualifiers capture and a bare triple silently collapses. Purls are normalised
(qualifiers sorted) before hashing, so a Syft upgrade that reorders them cannot
fork every OS package into a duplicate row.

**`scan_component` carries a denormalised `application_id` and `created_at`.**
Global historical search becomes a single index scan with no join back to `scan`,
and `created_at` gives a range-partition key later without touching queries.

**Raw SBOMs are content-addressed.** The blob key is derived from the SHA-256 of
the upload, so a rebuild of unchanged code — byte-identical Syft output — stores
nothing new. It also means a blob can be shared by many scans, so deleting a scan
must never unconditionally delete its blob.

**Writes are ordered blob-then-database.** A committed `scan` row pointing at a
blob that was never written is an unrecoverable hole in the audit trail; an
orphaned blob is just garbage for the retention sweep to collect.

---

## Capacity notes

At roughly 1000 applications building a few times a day:

- **Raw SBOMs: ~1.5 GB/day gzipped, ~500 GB/year.** This is the real cost driver.
  Content-addressing removes the unchanged-rebuild fraction. `BLOB_RETENTION_DAYS`
  trims raw blobs independently of scan rows (default `0` = keep forever); scan
  history itself stays append-only.
- **`scan_component`: ~500M rows/year.** Fine for Postgres with the covering
  index, and the table is written so it can be range-partitioned by `created_at`
  later without changing the read layer.
- Both are worth revisiting before year two rather than at 3000 apps.

---

## What is deliberately not built

- **A risk score of the platform's own invention.** Severity, CVSS, EPSS and
  known-exploited status are reported as the upstream feeds state them. Nothing here
  combines them into a single number, because a weighting invented by this platform would
  be carried into a meeting and acted on as though it meant something.
- **Alerting.** No email, no webhooks. The platform is a place to look, not a thing that
  interrupts you — consistent with there being no outbound mail anywhere in it.
- **Per-application or per-squad access control.** Every authenticated user sees
  every application. Deferred to the LDAP phase; nothing in the schema makes an
  `access_grant` table awkward to add.
- **Elasticsearch or a search service.** Postgres with a trigram index is the
  right size for this.
- **Outbound email.** No invites, notifications, or password-reset links, and so
  no SMTP dependency to configure or keep alive. Recovery is admin-driven; see
  [Accounts and passwords](#accounts-and-passwords).
- **Self-service signup.** Accounts are created by an admin only.
