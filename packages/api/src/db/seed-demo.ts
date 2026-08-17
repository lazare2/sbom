import { sql } from "drizzle-orm";
import { getConfig } from "../config.js";
import { IngestionService } from "../modules/ingestion/ingestion.service.js";
import { createBlobStore } from "../services/blob-store/index.js";
import { closeDb, getDb } from "./client.js";

/**
 * Generates realistic demo data for local development and UI work.
 *
 * NOT part of `db:seed` — this is explicitly opt-in (`npm run db:seed:demo`) and
 * refuses to run against NODE_ENV=production.
 *
 * Scans are created through the real `IngestionService` rather than by inserting
 * rows, so the data exercises the actual CycloneDX parser, component dedupe, and
 * `latest_scan_id` bookkeeping. Timestamps are then backdated in a second pass,
 * because ingestion legitimately stamps everything `now()` and a history where
 * every build happened in the same second would exercise none of the
 * date-ordering, staleness, or drift behaviour the UI is built around.
 */

// --- package pools ---------------------------------------------------------
// Deliberately overlapping across applications: cross-application search is only
// interesting when the same package genuinely appears in many places.

interface Pkg {
  name: string;
  version: string;
  ecosystem: string;
  namespace?: string;
}

const NPM: Pkg[] = [
  { name: "express", version: "4.19.2", ecosystem: "npm" },
  { name: "lodash", version: "4.17.21", ecosystem: "npm" },
  { name: "axios", version: "1.7.7", ecosystem: "npm" },
  { name: "react", version: "18.3.1", ecosystem: "npm" },
  { name: "zod", version: "3.23.8", ecosystem: "npm" },
  { name: "pino", version: "9.4.0", ecosystem: "npm" },
];

const PYPI: Pkg[] = [
  { name: "requests", version: "2.32.3", ecosystem: "pypi" },
  { name: "flask", version: "3.0.3", ecosystem: "pypi" },
  { name: "sqlalchemy", version: "2.0.35", ecosystem: "pypi" },
  { name: "pydantic", version: "2.9.2", ecosystem: "pypi" },
];

const MAVEN: Pkg[] = [
  { name: "spring-core", version: "6.1.13", ecosystem: "maven", namespace: "org.springframework" },
  { name: "jackson-databind", version: "2.17.2", ecosystem: "maven", namespace: "com.fasterxml.jackson.core" },
  { name: "guava", version: "33.3.1-jre", ecosystem: "maven", namespace: "com.google.guava" },
];

const DEB: Pkg[] = [
  { name: "libc6", version: "2.36-9+deb12u8", ecosystem: "deb", namespace: "debian" },
  { name: "openssl", version: "3.0.14-1~deb12u2", ecosystem: "deb", namespace: "debian" },
  { name: "zlib1g", version: "1:1.2.13.dfsg-1", ecosystem: "deb", namespace: "debian" },
  { name: "curl", version: "7.88.1-10+deb12u7", ecosystem: "deb", namespace: "debian" },
];

/**
 * The interesting one: an old, widely-deployed package that gets removed over
 * time. It stays in early scans and disappears from later ones, which is what
 * gives the "used historically but not currently" search scope and the
 * removed-packages diff something real to show.
 */
const LEGACY: Pkg = {
  name: "log4j-core",
  version: "2.14.1",
  ecosystem: "maven",
  namespace: "org.apache.logging.log4j",
};

/** Its replacement, which appears in the later scans. */
const LEGACY_REPLACEMENT: Pkg = {
  name: "log4j-core",
  version: "2.24.1",
  ecosystem: "maven",
  namespace: "org.apache.logging.log4j",
};

function purlFor(pkg: Pkg, qualifiers?: string): string {
  const ns = pkg.namespace ? `${pkg.namespace}/` : "";
  const encodedVersion = encodeURIComponent(pkg.version);
  return `pkg:${pkg.ecosystem}/${ns}${pkg.name}@${encodedVersion}${qualifiers ? `?${qualifiers}` : ""}`;
}

/** The base OS an application's image is built on. */
export interface Distro {
  id: string;
  version: string;
  pretty: string;
}

export const DISTROS = {
  alpine320: { id: "alpine", version: "3.20.3", pretty: "Alpine Linux v3.20" },
  alpine319: { id: "alpine", version: "3.19.4", pretty: "Alpine Linux v3.19" },
  debian12: { id: "debian", version: "12", pretty: "Debian GNU/Linux 12 (bookworm)" },
  debian11: { id: "debian", version: "11", pretty: "Debian GNU/Linux 11 (bullseye)" },
  ubuntu2404: { id: "ubuntu", version: "24.04", pretty: "Ubuntu 24.04.1 LTS" },
} satisfies Record<string, Distro>;

/**
 * Real distro packages per base image, so the base-image half of the platform is
 * exercised rather than merely modelled.
 *
 * These are genuine package names and genuinely old versions, which matters: the whole
 * point of the base-image figures is that an ageing image accumulates findings, and
 * Grype can only demonstrate that against packages it can actually match. A seed
 * carrying only the distro marker produces an estate where base-image exposure is
 * always zero, which would make the split look broken and hide the fact that
 * base-image packages normally outnumber application dependencies by two orders of
 * magnitude.
 *
 * Deliberately a handful rather than the ~1,500 a real image would carry: enough for
 * every query, ranking and card to have real data, few enough that seeding stays quick.
 */
const DISTRO_PACKAGES: Record<string, Array<{ name: string; version: string; ecosystem: string }>> = {
  // Old enough to carry known findings, which is the point.
  debian11: [
    { name: "openssl", version: "1.1.1n-0+deb11u3", ecosystem: "deb" },
    { name: "libc6", version: "2.31-13+deb11u5", ecosystem: "deb" },
    { name: "zlib1g", version: "1:1.2.11.dfsg-2+deb11u2", ecosystem: "deb" },
    { name: "curl", version: "7.74.0-1.3+deb11u7", ecosystem: "deb" },
    { name: "perl", version: "5.32.1-4+deb11u2", ecosystem: "deb" },
  ],
  debian12: [
    { name: "openssl", version: "3.0.11-1~deb12u2", ecosystem: "deb" },
    { name: "libc6", version: "2.36-9+deb12u3", ecosystem: "deb" },
    { name: "zlib1g", version: "1:1.2.13.dfsg-1", ecosystem: "deb" },
    { name: "curl", version: "7.88.1-10+deb12u5", ecosystem: "deb" },
  ],
  alpine319: [
    { name: "openssl", version: "3.1.4-r5", ecosystem: "apk" },
    { name: "busybox", version: "1.36.1-r19", ecosystem: "apk" },
    { name: "musl", version: "1.2.4_git20230717-r4", ecosystem: "apk" },
  ],
  alpine320: [
    { name: "openssl", version: "3.3.2-r0", ecosystem: "apk" },
    { name: "busybox", version: "1.36.1-r29", ecosystem: "apk" },
    { name: "musl", version: "1.2.5-r0", ecosystem: "apk" },
  ],
  ubuntu2404: [
    { name: "openssl", version: "3.0.13-0ubuntu3.4", ecosystem: "deb" },
    { name: "libc6", version: "2.39-0ubuntu8.3", ecosystem: "deb" },
  ],
};

/**
 * Emits the distro's own packages as Syft would, with the right qualifiers.
 *
 * The `?distro=` qualifier is what lets Grype match an OS package at all, and it has to
 * name the actual distribution: verified that the qualifier alone is sufficient, with no
 * `operating-system` component required, which is also what makes the platform's
 * batched cross-distro matching sound.
 */
function distroPackageComponents(distro: Distro): unknown[] {
  const key = Object.entries(DISTROS).find(
    ([, value]) => value.id === distro.id && value.version === distro.version,
  )?.[0];
  const entries = key ? DISTRO_PACKAGES[key] : undefined;
  if (!entries) return [];

  return entries.map((entry) => ({
    "bom-ref": `distro:${entry.name}@${entry.version}`,
    // `library`, exactly as Syft emits it — which is the reason the platform splits
    // base image from dependencies on ecosystem rather than on component kind.
    type: "library",
    name: entry.name,
    version: entry.version,
    purl:
      `pkg:${entry.ecosystem}/${distro.id}/${entry.name}@${encodeURIComponent(entry.version)}` +
      `?arch=amd64&distro=${distro.id}-${distro.version}`,
    properties: [{ name: "syft:package:type", value: entry.ecosystem }],
  }));
}

/**
 * Emits the OS component and the binary-cataloged runtimes the way Syft does.
 *
 * Faithful to the real shape, because platform detection reads exactly these
 * markers: the `operating-system` component type with `syft:distro:*`
 * properties, and `syft:package:type=binary` on the runtime entries. A seed that
 * invented its own convention would produce demo data that looks right while
 * exercising none of the detection logic.
 */
function platformComponents(distro: Distro | null, runtimes: Pkg[]): unknown[] {
  const out: unknown[] = [];

  if (distro) {
    out.push({
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
    });
    // The packages the base image actually contributes. Emitted alongside the marker so
    // every application with a distro gets realistic base-image content, and older
    // images genuinely carry more findings than newer ones.
    out.push(...distroPackageComponents(distro));
  }

  for (const runtime of runtimes) {
    out.push({
      "bom-ref": `binary:${runtime.name}@${runtime.version}`,
      type: "application",
      name: runtime.name,
      version: runtime.version,
      purl: `pkg:generic/${runtime.name}@${runtime.version}`,
      properties: [
        { name: "syft:package:type", value: "binary" },
        { name: "syft:package:foundBy", value: "binary-classifier-cataloger" },
      ],
    });
  }

  return out;
}

function buildSbom(opts: {
  image: string;
  packages: Pkg[];
  syftVersion: string;
  distro?: Distro | null;
  runtimes?: Pkg[];
}): Buffer {
  const doc = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: {
        components: [{ type: "application", author: "anchore", name: "syft", version: opts.syftVersion }],
      },
      component: { type: "container", name: opts.image },
    },
    components: [
      ...platformComponents(opts.distro ?? null, opts.runtimes ?? []),
      ...opts.packages.map((p) => ({
        "bom-ref": purlFor(p),
        type: "library",
        name: p.name,
        version: p.version,
        purl: purlFor(p, p.ecosystem === "deb" ? "arch=amd64&distro=debian-12" : undefined),
        properties: [{ name: "syft:package:type", value: syftTypeFor(p.ecosystem) }],
      })),
    ],
    dependencies: [],
  };
  return Buffer.from(JSON.stringify(doc, null, 2), "utf8");
}

function syftTypeFor(ecosystem: string): string {
  switch (ecosystem) {
    case "npm": return "npm";
    case "pypi": return "python";
    case "maven": return "java-archive";
    case "deb": return "deb";
    default: return ecosystem;
  }
}

// --- application definitions -----------------------------------------------

interface DemoApp {
  name: string;
  status: "active" | "inactive" | "pending_confirmation";
  attributes: Record<string, string>;
  image: string;
  basePackages: Pkg[];
  scanCount: number;
  /** Days ago the most recent scan happened. Large values produce a stale app. */
  lastScanDaysAgo: number;
  /** Include the legacy package in the earliest scans, then drop it. */
  hasLegacyDrift: boolean;
  /**
   * Base OS and runtimes, for the early half and the late half of the history.
   *
   * Two entries rather than one so several applications visibly change base
   * image and runtime version partway through — a Debian 11 to 12 bump, or Node
   * 20 to 22. Without that the platform data would be static and the "which
   * apps are behind" view would have nothing to distinguish.
   */
  platformEarly: { distro: Distro | null; runtimes: Pkg[] };
  platformLate: { distro: Distro | null; runtimes: Pkg[] };
}

const rt = (name: string, version: string): Pkg => ({ name, version, ecosystem: "generic" });

/**
 * How far back each build sits, in days, indexed by how many builds back it is
 * from the application's newest one.
 *
 * Graded rather than evenly spaced, for two reasons. It is what a retained
 * history actually looks like — recent builds are dense, older ones are whatever
 * survived — and, more practically, evenly spaced daily builds gave every
 * application a history only a few days deep, which left the analytics report's
 * churn section with nothing before its window to compare against and printed
 * four zeros as though they were measurements.
 *
 * The spread covers every reporting window the UI offers: with 8 builds an
 * application has a baseline before the 7, 30, 90 and 365-day marks.
 */
const BUILD_AGE_OFFSETS = [0, 4, 11, 26, 58, 121, 250, 480];

const DEMO_APPS: DemoApp[] = [
  {
    name: "payments-api",
    status: "active",
    attributes: { squad: "payments", owner: "aisha.khan", severity: "critical" },
    image: "registry.internal.example.com/payments/api",
    basePackages: [...MAVEN, ...DEB],
    // The deepest history in the demo estate: enough builds to reach past the
    // 12-month mark, so every reporting window has something to compare against.
    scanCount: 8,
    lastScanDaysAgo: 0,
    hasLegacyDrift: true,
    platformEarly: { distro: DISTROS.debian11, runtimes: [rt("java", "17.0.13")] },
    platformLate: { distro: DISTROS.debian12, runtimes: [rt("java", "21.0.5")] },
  },
  {
    name: "payments-worker",
    status: "active",
    attributes: { squad: "payments", owner: "aisha.khan", severity: "high" },
    image: "registry.internal.example.com/payments/worker",
    basePackages: [...MAVEN.slice(0, 2), ...DEB.slice(0, 3)],
    scanCount: 4,
    lastScanDaysAgo: 1,
    hasLegacyDrift: true,
    platformEarly: { distro: DISTROS.debian12, runtimes: [rt("java", "21.0.5")] },
    platformLate: { distro: DISTROS.debian12, runtimes: [rt("java", "21.0.5")] },
  },
  {
    name: "checkout-web",
    status: "active",
    attributes: { squad: "storefront", owner: "tomas.silva", severity: "high" },
    image: "registry.internal.example.com/storefront/checkout-web",
    basePackages: [...NPM, ...DEB.slice(0, 2)],
    scanCount: 7,
    lastScanDaysAgo: 0,
    hasLegacyDrift: false,
    platformEarly: { distro: DISTROS.alpine319, runtimes: [rt("node", "20.18.1"), rt("nginx", "1.26.2")] },
    platformLate: { distro: DISTROS.alpine320, runtimes: [rt("node", "22.11.0"), rt("nginx", "1.27.3")] },
  },
  {
    name: "catalogue-service",
    status: "active",
    attributes: { squad: "storefront", owner: "tomas.silva", severity: "medium" },
    image: "registry.internal.example.com/storefront/catalogue",
    basePackages: [...PYPI, ...DEB.slice(0, 3)],
    scanCount: 3,
    lastScanDaysAgo: 2,
    hasLegacyDrift: false,
    platformEarly: { distro: DISTROS.debian12, runtimes: [rt("python", "3.11.2")] },
    platformLate: { distro: DISTROS.debian12, runtimes: [rt("python", "3.12.7")] },
  },
  {
    name: "identity-provider",
    status: "active",
    attributes: { squad: "platform", owner: "marta.novak", severity: "critical" },
    image: "registry.internal.example.com/platform/identity",
    basePackages: [...MAVEN, ...DEB],
    scanCount: 6,
    lastScanDaysAgo: 3,
    hasLegacyDrift: true,
    platformEarly: { distro: DISTROS.ubuntu2404, runtimes: [rt("java", "21.0.5")] },
    platformLate: { distro: DISTROS.ubuntu2404, runtimes: [rt("java", "21.0.5")] },
  },
  {
    name: "notification-relay",
    status: "active",
    attributes: { squad: "platform", owner: "marta.novak", severity: "low" },
    image: "registry.internal.example.com/platform/notifications",
    basePackages: [...NPM.slice(0, 3), ...DEB.slice(0, 2)],
    // Not scanned in a long time -> shows up as stale in the list view.
    scanCount: 2,
    lastScanDaysAgo: 74,
    hasLegacyDrift: false,
    platformEarly: { distro: DISTROS.alpine319, runtimes: [rt("node", "18.20.5")] },
    platformLate: { distro: DISTROS.alpine319, runtimes: [rt("node", "18.20.5")] },
  },
  {
    name: "legacy-reporting",
    status: "inactive",
    attributes: { squad: "data", owner: "unassigned", severity: "low" },
    image: "registry.internal.example.com/data/legacy-reporting",
    basePackages: [...PYPI.slice(0, 2), ...DEB.slice(0, 2)],
    scanCount: 2,
    lastScanDaysAgo: 190,
    hasLegacyDrift: true,
    platformEarly: { distro: DISTROS.debian11, runtimes: [rt("python", "3.9.2")] },
    platformLate: { distro: DISTROS.debian11, runtimes: [rt("python", "3.9.2")] },
  },
  {
    name: "risk-scoring-svc",
    // Arrived from CI under a name nobody pre-registered.
    status: "pending_confirmation",
    attributes: {},
    image: "registry.internal.example.com/risk/scoring",
    basePackages: [...PYPI, ...NPM.slice(0, 2)],
    scanCount: 2,
    lastScanDaysAgo: 0,
    hasLegacyDrift: false,
    platformEarly: { distro: DISTROS.alpine320, runtimes: [rt("python", "3.12.7"), rt("node", "22.11.0")] },
    platformLate: { distro: DISTROS.alpine320, runtimes: [rt("python", "3.12.7"), rt("node", "22.11.0")] },
  },
];

const BRANCHES = ["main", "main", "main", "release/2024.11", "develop"];

function randomSha(): string {
  return Array.from({ length: 40 }, () => "0123456789abcdef"[Math.floor(Math.random() * 16)]).join("");
}

async function main(): Promise<void> {
  const config = getConfig();
  if (config.isProduction) {
    throw new Error("refusing to seed demo data with NODE_ENV=production");
  }

  const db = getDb();
  const blobStore = createBlobStore(config);
  await blobStore.verify();

  const logger = {
    info: () => undefined,
    warn: (obj: unknown, msg?: string) => console.warn("[warn]", msg ?? "", obj),
  };
  const ingestion = new IngestionService({ db, blobStore, logger });

  console.log("[seed:demo] generating demo applications and scan history...");

  for (const app of DEMO_APPS) {
    const scanIds: string[] = [];

    for (let i = 0; i < app.scanCount; i++) {
      const isEarly = i < Math.ceil(app.scanCount / 2);

      // Compose this build's package set. Rotating a slice keeps consecutive
      // builds mostly-but-not-entirely identical, which is what real drift looks
      // like and what makes the diff view non-trivial.
      const packages: Pkg[] = [...app.basePackages];
      if (app.hasLegacyDrift) {
        packages.push(isEarly ? LEGACY : LEGACY_REPLACEMENT);
      }
      if (i >= 2) {
        // A dependency picked up partway through the history.
        packages.push({ name: "opentelemetry-api", version: "1.42.0", ecosystem: "maven", namespace: "io.opentelemetry" });
      }
      if (isEarly && app.basePackages.length > 3) {
        // A dependency that was dropped later on.
        packages.push({ name: "commons-collections", version: "3.2.2", ecosystem: "maven", namespace: "commons-collections" });
      }

      const buildNumber = String(100 + i);
      const platform = isEarly ? app.platformEarly : app.platformLate;
      const sbom = buildSbom({
        image: `${app.image}:1.${i}.0`,
        packages,
        distro: platform.distro,
        runtimes: platform.runtimes,
        // Older builds were scanned by an older Syft. Exercises both the 1.4 and
        // 1.5 metadata shapes being present across history.
        syftVersion: isEarly ? "1.14.0" : "1.18.1",
      });

      const result = await ingestion.ingest({
        fields: {
          app_name: app.name,
          commit_sha: randomSha(),
          build_number: buildNumber,
          pipeline_id: String(90000 + i),
          image_ref: `${app.image}:1.${i}.0`,
          branch: BRANCHES[i % BRANCHES.length]!,
        },
        rawSbom: sbom,
        tokenName: "demo-seed",
      });
      scanIds.push(result.scanId);
    }

    // --- backdate the history ---------------------------------------------
    // Spread over `BUILD_AGE_OFFSETS`, ending `lastScanDaysAgo` days before now.
    // Insert order is chronological, so the last-inserted scan stays the newest
    // and the pointers ingestion set remain correct. `scan_component` carries a
    // denormalised `created_at`, so it has to move in step or the "last seen"
    // ordering in global search would disagree with the scan dates.
    for (let i = 0; i < scanIds.length; i++) {
      const buildsBack = scanIds.length - 1 - i;
      const offset = BUILD_AGE_OFFSETS[buildsBack] ?? BUILD_AGE_OFFSETS[BUILD_AGE_OFFSETS.length - 1]!;
      const daysAgo = app.lastScanDaysAgo + offset;
      const scanId = scanIds[i]!;
      await db.execute(sql`
        UPDATE scan SET created_at = now() - ${sql.raw(`interval '${daysAgo} days'`)}
        WHERE id = ${scanId}::uuid
      `);
      await db.execute(sql`
        UPDATE scan_component SET created_at = now() - ${sql.raw(`interval '${daysAgo} days'`)}
        WHERE scan_id = ${scanId}::uuid
      `);
    }

    // Apply the demo status and attributes. In the real product these are admin
    // actions (Checkpoint C); set directly here because the write API does not
    // exist yet.
    await db.execute(sql`
      UPDATE application
      SET status = ${app.status},
          attributes = ${JSON.stringify(app.attributes)}::jsonb,
          updated_at = now()
      WHERE name = ${app.name}
    `);

    // Re-point the application at its genuinely-newest scan. The backdating above
    // invalidated both denormalised pointers, since ingestion set them in insert
    // order and the newest scan by timestamp is now a different row.
    await db.execute(sql`
      UPDATE application a
      SET last_scan_at   = (SELECT max(created_at) FROM scan WHERE application_id = a.id),
          latest_scan_id = (SELECT id FROM scan WHERE application_id = a.id
                            ORDER BY created_at DESC, id DESC LIMIT 1),
          created_at     = (SELECT min(created_at) FROM scan WHERE application_id = a.id),
          updated_at     = now()
      WHERE a.name = ${app.name}
    `);

    const oldest =
      app.lastScanDaysAgo +
      (BUILD_AGE_OFFSETS[app.scanCount - 1] ?? BUILD_AGE_OFFSETS[BUILD_AGE_OFFSETS.length - 1]!);
    console.log(
      `[seed:demo]   ${app.name.padEnd(20)} ${String(app.scanCount).padStart(2)} scans  ` +
        `status=${app.status}  history ${oldest}d..${app.lastScanDaysAgo}d ago`,
    );
  }

  // --- summary -------------------------------------------------------------
  const summary = await db.execute<Record<string, unknown>>(sql`
    SELECT
      (SELECT count(*) FROM application) AS applications,
      (SELECT count(*) FROM scan) AS scans,
      (SELECT count(*) FROM component) AS components,
      (SELECT count(*) FROM scan_component) AS links
  `);
  const row = (Array.isArray(summary) ? summary[0] : summary.rows[0]) as Record<string, unknown>;

  console.log("");
  console.log(`[seed:demo] applications: ${row.applications}`);
  console.log(`[seed:demo] scans:        ${row.scans}`);
  console.log(`[seed:demo] components:   ${row.components}`);
  console.log(`[seed:demo] links:        ${row.links}`);
  console.log("");
  console.log("[seed:demo] things worth looking at:");
  console.log("  - search log4j-core with scope=historical -> apps that dropped 2.14.1");
  console.log("  - notification-relay and legacy-reporting are stale");
  console.log("  - risk-scoring-svc is pending_confirmation");
  console.log("  - Overview -> Operating systems / Language runtimes: node 18 and Debian 11 stragglers");
  console.log("  - Applications -> filter Runtime = Node.js 18 to find what is behind");
  console.log("[seed:demo] done");
}


main()
  .then(() => closeDb())
  .then(() => process.exit(0))
  .catch(async (err: unknown) => {
    console.error("[seed:demo] failed:", err);
    await closeDb().catch(() => undefined);
    process.exit(1);
  });
