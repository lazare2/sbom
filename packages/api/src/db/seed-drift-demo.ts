import { sql } from "drizzle-orm";
import { getConfig } from "../config.js";
import { IngestionService } from "../modules/ingestion/ingestion.service.js";
import { createBlobStore } from "../services/blob-store/index.js";
import { closeDb, getDb } from "./client.js";

/**
 * A single application whose build history is a worked example of dependency
 * drift, for demonstrating and eyeballing the "No longer used" view.
 *
 * `db:seed:demo` generates broad, semi-random data across eight applications,
 * which is right for exercising search and the list view but makes the drift
 * rules hard to check by hand. This script does the opposite: five builds of one
 * application, hand-written so that every category of change appears exactly
 * once and the expected output can be printed and compared against the UI.
 *
 * Re-runnable: it deletes the application first, so a second run replaces the
 * history rather than doubling it.
 *
 * Scans go through the real IngestionService, then timestamps are backdated —
 * ingestion legitimately stamps everything `now()`, and a history where every
 * build happened in the same second exercises none of the date ordering the
 * views depend on.
 */

const APP_NAME = "drift-demo-service";
const IMAGE = "registry.internal.example.com/demo/drift-demo-service";

interface Pkg {
  name: string;
  version: string;
  ecosystem: string;
  namespace?: string;
}

const p = (name: string, version: string, ecosystem: string, namespace?: string): Pkg =>
  namespace ? { name, version, ecosystem, namespace } : { name, version, ecosystem };

/**
 * Five builds, oldest first. Every column below is deliberate:
 *
 *   lodash        unchanged throughout  -> must NEVER appear as removed
 *   express       upgraded once         -> the old version is "removed"
 *   log4j-core    upgraded twice        -> TWO dead versions in the history
 *   request       dropped for good      -> the genuine removal
 *   moment        dropped, then BACK    -> removed by version, present by name
 *   openssl       rolling OS upgrades   -> two dead versions
 *   axios         added late, upgraded  -> added and then partly superseded
 *   commons-io    added then dropped    -> appeared in one build only
 *
 * `moment` and `commons-io` are the two rows worth staring at. `moment` shows up
 * in the default view (2.29.4 really is gone) but vanishes when version upgrades
 * are hidden, because moment 2.30.1 is back in the current build. `commons-io`
 * survives both filters: it was here, briefly, and no version of it remains.
 */
const BUILDS: Array<{ build: string; branch: string; packages: Pkg[] }> = [
  {
    build: "101",
    branch: "main",
    packages: [
      p("lodash", "4.17.21", "npm"),
      p("express", "4.18.2", "npm"),
      p("log4j-core", "2.14.1", "maven", "org.apache.logging.log4j"),
      p("request", "2.88.2", "npm"),
      p("moment", "2.29.4", "npm"),
      p("openssl", "3.0.11-1~deb12u1", "deb", "debian"),
    ],
  },
  {
    build: "102",
    branch: "main",
    packages: [
      p("lodash", "4.17.21", "npm"),
      p("express", "4.18.2", "npm"),
      // Patched for the log4shell family, but not yet current.
      p("log4j-core", "2.17.1", "maven", "org.apache.logging.log4j"),
      p("request", "2.88.2", "npm"),
      p("moment", "2.29.4", "npm"),
      p("openssl", "3.0.11-1~deb12u1", "deb", "debian"),
    ],
  },
  {
    build: "103",
    branch: "main",
    packages: [
      p("lodash", "4.17.21", "npm"),
      p("express", "4.19.2", "npm"),
      p("log4j-core", "2.17.1", "maven", "org.apache.logging.log4j"),
      // `request` and `moment` both leave here. Only one of them comes back.
      p("openssl", "3.0.14-1~deb12u2", "deb", "debian"),
      p("axios", "1.7.2", "npm"),
    ],
  },
  {
    build: "104",
    branch: "main",
    packages: [
      p("lodash", "4.17.21", "npm"),
      p("express", "4.19.2", "npm"),
      p("log4j-core", "2.24.1", "maven", "org.apache.logging.log4j"),
      p("openssl", "3.0.14-1~deb12u2", "deb", "debian"),
      p("axios", "1.7.2", "npm"),
      // Returns at a newer version, so the package is back but 2.29.4 is not.
      p("moment", "2.30.1", "npm"),
      // Here for exactly one build.
      p("commons-io", "2.11.0", "maven", "commons-io"),
    ],
  },
  {
    build: "105",
    branch: "main",
    packages: [
      p("lodash", "4.17.21", "npm"),
      p("express", "4.19.2", "npm"),
      p("log4j-core", "2.24.1", "maven", "org.apache.logging.log4j"),
      p("openssl", "3.0.15-1~deb12u1", "deb", "debian"),
      p("axios", "1.7.9", "npm"),
      p("moment", "2.30.1", "npm"),
    ],
  },
];

/** Days before now for each build, oldest first. */
const DAYS_AGO = [28, 21, 14, 7, 0];

function purlFor(pkg: Pkg, qualifiers?: string): string {
  const ns = pkg.namespace ? `${pkg.namespace}/` : "";
  return `pkg:${pkg.ecosystem}/${ns}${pkg.name}@${encodeURIComponent(pkg.version)}${
    qualifiers ? `?${qualifiers}` : ""
  }`;
}

function syftTypeFor(ecosystem: string): string {
  switch (ecosystem) {
    case "npm": return "npm";
    case "maven": return "java-archive";
    case "deb": return "deb";
    default: return ecosystem;
  }
}

/**
 * The base image also drifts across the history: Alpine 3.19 with Node 20 for
 * the first three builds, then Alpine 3.20 with Node 22.
 *
 * Emitted the way Syft does — an `operating-system` component carrying
 * `syft:distro:*`, and runtimes marked `syft:package:type=binary` — so the same
 * detection code path runs as for a real scan.
 */
function platformFor(buildIndex: number): { distro: { id: string; version: string; pretty: string }; runtimes: Pkg[] } {
  return buildIndex < 3
    ? {
        distro: { id: "alpine", version: "3.19.4", pretty: "Alpine Linux v3.19" },
        runtimes: [p("node", "20.18.1", "generic")],
      }
    : {
        distro: { id: "alpine", version: "3.20.3", pretty: "Alpine Linux v3.20" },
        runtimes: [p("node", "22.11.0", "generic")],
      };
}

function buildSbom(packages: Pkg[], tag: string, buildIndex: number): Buffer {
  const { distro, runtimes } = platformFor(buildIndex);
  return Buffer.from(
    JSON.stringify(
      {
        bomFormat: "CycloneDX",
        specVersion: "1.5",
        serialNumber: `urn:uuid:${crypto.randomUUID()}`,
        version: 1,
        metadata: {
          timestamp: new Date().toISOString(),
          tools: { components: [{ type: "application", author: "anchore", name: "syft", version: "1.18.1" }] },
          component: { type: "container", name: `${IMAGE}:${tag}` },
        },
        components: [
          {
            "bom-ref": `os:${distro.id}`,
            type: "operating-system",
            name: distro.id,
            version: distro.version,
            description: distro.pretty,
            properties: [
              { name: "syft:distro:id", value: distro.id },
              { name: "syft:distro:versionID", value: distro.version },
              { name: "syft:distro:prettyName", value: distro.pretty },
            ],
          },
          ...runtimes.map((runtime) => ({
            "bom-ref": `binary:${runtime.name}@${runtime.version}`,
            type: "application",
            name: runtime.name,
            version: runtime.version,
            purl: `pkg:generic/${runtime.name}@${runtime.version}`,
            properties: [
              { name: "syft:package:type", value: "binary" },
              { name: "syft:package:foundBy", value: "binary-classifier-cataloger" },
            ],
          })),
          ...packages.map((pkg) => ({
            "bom-ref": purlFor(pkg),
            type: "library",
            name: pkg.name,
            version: pkg.version,
            purl: purlFor(pkg, pkg.ecosystem === "deb" ? "arch=amd64&distro=debian-12" : undefined),
            properties: [{ name: "syft:package:type", value: syftTypeFor(pkg.ecosystem) }],
          })),
        ],
        dependencies: [],
      },
      null,
      2,
    ),
    "utf8",
  );
}

function randomSha(): string {
  return Array.from({ length: 40 }, () => "0123456789abcdef"[Math.floor(Math.random() * 16)]).join("");
}

/** Everything ever shipped, minus what the final build contains. */
function expectedRemoved(): Array<{ label: string; lastSeen: string; gone: boolean }> {
  const latest = BUILDS[BUILDS.length - 1]!.packages;
  const key = (pkg: Pkg) => `${pkg.ecosystem}|${pkg.name}|${pkg.version}`;
  const nameKey = (pkg: Pkg) => `${pkg.ecosystem}|${pkg.name}`;

  const inLatest = new Set(latest.map(key));
  const namesInLatest = new Set(latest.map(nameKey));

  // Last build that contained each exact package+version.
  const lastSeenIn = new Map<string, { pkg: Pkg; build: string }>();
  for (const b of BUILDS) {
    for (const pkg of b.packages) lastSeenIn.set(key(pkg), { pkg, build: b.build });
  }

  return [...lastSeenIn.entries()]
    .filter(([k]) => !inLatest.has(k))
    .map(([, v]) => ({
      label: `${v.pkg.name} ${v.pkg.version}`,
      lastSeen: v.build,
      // True when no version of this package remains — survives the
      // "hide version upgrades" filter.
      gone: !namesInLatest.has(nameKey(v.pkg)),
    }))
    .sort((a, b) => a.label.localeCompare(b.label));
}

async function main(): Promise<void> {
  const config = getConfig();
  if (config.isProduction) {
    throw new Error("refusing to seed demo data with NODE_ENV=production");
  }

  const db = getDb();
  const blobStore = createBlobStore(config);
  await blobStore.verify();

  const ingestion = new IngestionService({
    db,
    blobStore,
    logger: { info: () => undefined, warn: (o, m) => console.warn("[warn]", m ?? "", o) },
  });

  // Replace rather than append, so re-running produces the documented result
  // instead of ten builds with a confusing history. Cascades to this
  // application's scans and scan_component rows; `component` rows are shared
  // across the estate and are deliberately left alone.
  const deleted = await db.execute(sql`DELETE FROM application WHERE lower(name) = ${APP_NAME}`);
  if ((deleted.rowCount ?? 0) > 0) {
    console.log(`[seed:drift] removed the previous "${APP_NAME}" and its history`);
  }

  console.log(`[seed:drift] ingesting ${BUILDS.length} builds of ${APP_NAME}...`);

  const scanIds: string[] = [];
  for (let i = 0; i < BUILDS.length; i++) {
    const b = BUILDS[i]!;
    const result = await ingestion.ingest({
      fields: {
        app_name: APP_NAME,
        commit_sha: randomSha(),
        build_number: b.build,
        pipeline_id: String(94000 + i),
        image_ref: `${IMAGE}:1.${i}.0`,
        branch: b.branch,
      },
      rawSbom: buildSbom(b.packages, `1.${i}.0`, i),
      tokenName: "drift-demo-seed",
    });
    scanIds.push(result.scanId);
    console.log(
      `[seed:drift]   build ${b.build}  ${String(b.packages.length).padStart(2)} packages  ` +
        `${DAYS_AGO[i]}d ago`,
    );
  }

  // Backdate. `scan_component` carries a denormalised `created_at`, so it has to
  // move in step or the "last seen" ordering would disagree with the scan dates.
  for (let i = 0; i < scanIds.length; i++) {
    const interval = sql.raw(`interval '${DAYS_AGO[i]} days'`);
    await db.execute(sql`
      UPDATE scan SET created_at = now() - ${interval} WHERE id = ${scanIds[i]!}::uuid
    `);
    await db.execute(sql`
      UPDATE scan_component SET created_at = now() - ${interval} WHERE scan_id = ${scanIds[i]!}::uuid
    `);
  }

  await db.execute(sql`
    UPDATE application
    SET status = 'active',
        attributes = ${JSON.stringify({ squad: "platform", owner: "demo.owner", severity: "high" })}::jsonb,
        updated_at = now()
    WHERE lower(name) = ${APP_NAME}
  `);

  // Backdating invalidated both denormalised pointers: ingestion set them in
  // insert order, and the newest scan by timestamp is now a different row.
  await db.execute(sql`
    UPDATE application a
    SET last_scan_at   = (SELECT max(created_at) FROM scan WHERE application_id = a.id),
        latest_scan_id = (SELECT id FROM scan WHERE application_id = a.id
                          ORDER BY created_at DESC, id DESC LIMIT 1),
        created_at     = (SELECT min(created_at) FROM scan WHERE application_id = a.id),
        updated_at     = now()
    WHERE lower(a.name) = ${APP_NAME}
  `);

  // --- print the expected answer so the UI can be checked against it --------
  const expected = expectedRemoved();
  const goneEntirely = expected.filter((e) => e.gone);

  console.log("");
  console.log("[seed:drift] Expected under \"No longer used\":");
  console.log("");
  console.log("   PACKAGE                       LAST SEEN IN   NO VERSION LEFT");
  for (const e of expected) {
    console.log(
      `   ${e.label.padEnd(29)} build ${e.lastSeen}      ${e.gone ? "yes" : "no  (upgraded)"}`,
    );
  }
  console.log("");
  console.log(`[seed:drift] default view                  -> ${expected.length} rows`);
  console.log(`[seed:drift] with "Hide version upgrades"  -> ${goneEntirely.length} rows: ` +
    goneEntirely.map((e) => e.label).join(", "));
  console.log("");
  console.log("[seed:drift] the two rows worth understanding:");
  console.log("   moment 2.29.4     left in build 103, but moment 2.30.1 returned in 104,");
  console.log("                     so it is listed by version and hidden by the filter.");
  console.log("   commons-io 2.11.0 shipped in build 104 only. Nothing replaced it, so it");
  console.log("                     survives both views. Same for request 2.88.2.");
  console.log("");
  console.log("[seed:drift] lodash 4.17.21 is in all five builds and must never appear.");
  console.log("[seed:drift] done");
}

main()
  .then(() => closeDb())
  .then(() => process.exit(0))
  .catch(async (err: unknown) => {
    console.error("[seed:drift] failed:", err);
    await closeDb().catch(() => undefined);
    process.exit(1);
  });
