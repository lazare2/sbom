import { sql } from "drizzle-orm";
import {
  type AnyPgColumn,
  bigint,
  bigserial,
  boolean,
  doublePrecision,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";
import type {
  ApplicationStatus,
  Attributes,
  AttributeType,
  AuthProviderName,
  FixState,
  ScanSource,
  ScanVulnStatus,
  SeverityCounts,
  UserRole,
  VulnDbUpdateOutcome,
  VulnDbUpdateTrigger,
  VulnSeverity,
} from "@sbom/shared";

/**
 * The complete relational schema, in one module.
 *
 * Deliberately a single file rather than a `schema/` directory: drizzle-kit
 * loads this file through a CJS require hook that does not resolve ESM `.js`
 * specifiers back to `.ts` sources, so cross-file schema imports break
 * `drizzle-kit generate`. Colocation also lets `application.latest_scan_id` and
 * `scan.application_id` reference each other without a circular import.
 *
 * Conventions:
 *  - `snake_case` in the DB (see `casing` in drizzle.config.ts), camelCase in TS.
 *  - All timestamps are `timestamptz`.
 *  - Secrets (session tokens, reset tokens, ingest tokens) are stored as
 *    SHA-256 hashes only.
 */

// ---------------------------------------------------------------------------
// Users, sessions, credentials
// ---------------------------------------------------------------------------

/**
 * Accounts are created by admins only — there is no self-service signup, and no
 * invite email: the `email` column is a login identifier, not a mailbox, so
 * nothing can be delivered to it. An admin sets or generates a password and
 * hands it over out of band.
 *
 * `passwordHash` is nullable only for accounts owned by an external provider
 * such as a future LDAP, which is what `authProvider` selects. Local accounts
 * always have one.
 */
export const user = pgTable(
  "user",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    email: text("email").notNull(),
    passwordHash: text("password_hash"),
    role: text("role").$type<UserRole>().notNull().default("user"),
    authProvider: text("auth_provider").$type<AuthProviderName>().notNull().default("local"),
    isActive: boolean("is_active").notNull().default(true),
    /**
     * Set whenever an admin issues a password, because at that moment a
     * credential for this account exists in someone else's hands (and possibly
     * in a chat log). Login still succeeds — it has to, or the user could never
     * clear the flag — but every other authenticated route is refused until the
     * password is changed.
     */
    mustChangePassword: boolean("must_change_password").notNull().default(false),
    lastLoginAt: timestamp("last_login_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    // Case-insensitive uniqueness without depending on the citext extension.
    // Emails are normalised to lowercase on write; this index is the backstop
    // that stops `Alice@x.com` from becoming a second account.
    uniqueIndex("user_email_lower_uniq").on(sql`lower(${t.email})`),
    index("user_role_idx").on(t.role),
  ],
);

/**
 * Server-side sessions. We store the SHA-256 of the cookie value, not the value
 * itself, so a dump of this table cannot be replayed as a valid login.
 *
 * Chosen over JWT deliberately: an admin deactivating a user has to take effect
 * immediately, which means a revocation lookup on every request regardless.
 */
export const session = pgTable(
  "session",
  {
    tokenHash: text("token_hash").primaryKey(),
    userId: uuid("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
  },
  (t) => [
    index("session_user_idx").on(t.userId),
    // Drives the expired-session sweep.
    index("session_expires_idx").on(t.expiresAt),
  ],
);

/*
 * There is deliberately no `user_token` table.
 *
 * An earlier revision had one for emailed password-reset and account-setup
 * links. Those links have no delivery channel — user emails are identifiers,
 * not mailboxes — so the only recovery path is an admin issuing a password
 * directly. A token table with no way to send a token is a liability, not a
 * feature: it is a second credential store to keep expired and swept.
 */

// ---------------------------------------------------------------------------
// Applications
// ---------------------------------------------------------------------------

export const application = pgTable(
  "application",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    name: text("name").notNull(),
    status: text("status").$type<ApplicationStatus>().notNull().default("active"),
    /**
     * Admin-editable custom attributes (squad, owner, severity, plus whatever
     * gets added later). JSONB rather than fixed columns so adding an attribute
     * is an admin action against `attributeDefinition`, not a migration.
     */
    attributes: jsonb("attributes").$type<Attributes>().notNull().default({}),
    /**
     * Current-state pointer, maintained on ingest and on merge. Nullable
     * because pre-registered applications exist before their first scan.
     */
    latestScanId: uuid("latest_scan_id").references((): AnyPgColumn => scan.id, {
      onDelete: "set null",
    }),
    /** Denormalised from the latest scan so the list view needs no join. */
    lastScanAt: timestamp("last_scan_at", { withTimezone: true }),
    scanCount: integer("scan_count").notNull().default(0),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    // Ingest matches `app_name` case-insensitively, so uniqueness must be too:
    // `my-service` and `My-Service` are one application, not two.
    uniqueIndex("application_name_lower_uniq").on(sql`lower(${t.name})`),
    index("application_status_idx").on(t.status),
    index("application_last_scan_at_idx").on(t.lastScanAt),
    /**
     * Supports filtering the list view by squad / owner / severity.
     *
     * NOTE for the query layer: a default jsonb GIN index serves the containment
     * operators (`@>`, `?`, `?|`, `?&`) but NOT `attributes->>'squad' = 'x'`.
     * Attribute filters must therefore be written as
     * `attributes @> '{"squad":"payments"}'::jsonb` to be index-assisted — the
     * `->>` form compiles to a sequential scan over every application.
     */
    index("application_attributes_gin").using("gin", t.attributes),
  ],
);

/**
 * Permanent name mappings created by the "merge always" resolution. Ingest
 * consults this after a direct name match fails and before auto-creating a
 * pending application, so future scans under the old CI name land on the right
 * app instead of spawning a fresh pending one every build.
 */
export const applicationAlias = pgTable(
  "application_alias",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    aliasName: text("alias_name").notNull(),
    applicationId: uuid("application_id")
      .notNull()
      .references(() => application.id, { onDelete: "cascade" }),
    createdByUserId: uuid("created_by_user_id").references(() => user.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex("application_alias_name_lower_uniq").on(sql`lower(${t.aliasName})`),
    index("application_alias_app_idx").on(t.applicationId),
  ],
);

/**
 * A named set of applications, for the questions that span several of them.
 *
 * Distinct from `application.attributes`, which is the other way to label an application
 * and cannot do this job: an attribute holds one value per key, so an application has one
 * squad and cannot have three. Membership here is many-to-many in both directions, which is
 * the whole point — an application belongs to its product *and* to "public facing" *and* to
 * "PCI scope" at the same time.
 *
 * Two quite different uses share this one table, deliberately:
 *
 *   - A label. "Public facing" is a trait many unrelated applications happen to have, and
 *     the question is which ones — the answer is a list.
 *   - A composite. Eight images that together are one product, deployed as eight
 *     applications because that is how they are built. The question is how exposed the
 *     product is — the answer is one number.
 *
 * Storing them separately would duplicate the table, the membership table, the admin screens
 * and the filter for no gain: the difference between the two is entirely in how a reader
 * aggregates them, not in what is stored.
 */
export const applicationGroup = pgTable(
  "application_group",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    name: text("name").notNull(),
    /** Free text shown on the group's page. What this group is for, in the owner's words. */
    description: text("description"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    // Case-insensitive, matching how application names are treated: "Public Facing" and
    // "public facing" are one group, and letting both exist would split its membership in
    // two while looking like a single group in every list.
    uniqueIndex("application_group_name_lower_uniq").on(sql`lower(${t.name})`),
  ],
);

/**
 * Membership. Rows are created and removed by an admin, never by ingest.
 *
 * A CI pipeline could plausibly declare its own groups, and that was considered: it would be
 * self-maintaining, since the pipeline knows what product it belongs to. It is not done
 * because any holder of an ingest token could then create a group, and a typo would silently
 * become a real one — "checkuot" alongside "checkout", each with part of the membership and
 * nothing on screen to say they are the same thing.
 */
export const applicationGroupMember = pgTable(
  "application_group_member",
  {
    groupId: uuid("group_id")
      .notNull()
      .references(() => applicationGroup.id, { onDelete: "cascade" }),
    applicationId: uuid("application_id")
      .notNull()
      .references(() => application.id, { onDelete: "cascade" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    /*
      The composite key is the uniqueness guarantee as well as the index: adding an
      application to a group it is already in must be a no-op rather than a second row, or
      "affects 6 of 8 members" would start counting the same member twice.
    */
    primaryKey({ name: "application_group_member_pkey", columns: [t.groupId, t.applicationId] }),
    /*
      The reverse direction. The primary key serves "which applications are in this group";
      this serves "which groups is this application in", which the applications list asks
      once per row to render its chips.
    */
    index("application_group_member_application_idx").on(t.applicationId),
  ],
);

/**
 * Describes the attribute keys the UI renders and validates against. Seeded
 * with squad / owner / severity; an admin can add more without a migration.
 */
export const attributeDefinition = pgTable(
  "attribute_definition",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    key: text("key").notNull(),
    label: text("label").notNull(),
    type: text("type").$type<AttributeType>().notNull().default("string"),
    /** Allowed values when `type` is `select`; null otherwise. */
    options: jsonb("options").$type<string[] | null>(),
    sortOrder: integer("sort_order").notNull().default(0),
    isActive: boolean("is_active").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex("attribute_definition_key_uniq").on(t.key),
    index("attribute_definition_sort_idx").on(t.sortOrder),
  ],
);

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

/**
 * Append-only scan history. One row per CI build that submitted an SBOM.
 *
 * Rows are never deleted except by the two explicit admin actions: deleting an
 * application (cascade) and merging a pending application (rows are reassigned,
 * not removed).
 */
export const scan = pgTable(
  "scan",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    applicationId: uuid("application_id")
      .notNull()
      .references(() => application.id, { onDelete: "cascade" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),

    // --- CI/CD provenance -------------------------------------------------
    commitSha: text("commit_sha"),
    buildNumber: text("build_number"),
    pipelineId: text("pipeline_id"),
    imageRef: text("image_ref"),
    branch: text("branch"),
    /** Which named ingest token submitted this, for traceability. Null for manual uploads. */
    ingestTokenName: text("ingest_token_name"),

    /**
     * `ci` for a pipeline posting to /api/v1/scans, `manual` for a signed-in user
     * uploading from the scan-history tab.
     *
     * Provenance only. Every read path treats the two identically — a manual
     * upload is a real build of the application and becomes its current state, in
     * exactly the way a pipeline's would.
     */
    source: text("source").$type<ScanSource>().notNull().default("ci"),
    /**
     * Who uploaded, when source is `manual`.
     *
     * The email is denormalised alongside the reference for the same reason
     * audit_log denormalises its actor: ON DELETE SET NULL means removing an
     * account would otherwise erase who submitted a scan that is still shaping the
     * estate's current state.
     */
    uploadedByUserId: uuid("uploaded_by_user_id").references(() => user.id, { onDelete: "set null" }),
    uploadedByEmail: text("uploaded_by_email"),
    /** Optional free-text reason supplied at upload time — why this was done by hand. */
    uploadNote: text("upload_note"),

    /**
     * Whether this scan's packages have been matched against the vulnerability
     * database yet.
     *
     * Denormalised so a history table can label each build without a correlated
     * subquery over every one of its components. `pending` is the honest default
     * for a scan that has just been ingested, and for every scan that already
     * existed when vulnerability scanning was switched on.
     *
     * Deliberately not `skipped` when scanning is disabled: the scan genuinely has
     * not been matched, and recording it as skipped would make enabling the feature
     * look like it had nothing to do.
     */
    vulnStatus: text("vuln_status").$type<ScanVulnStatus>().notNull().default("pending"),

    // --- raw SBOM ---------------------------------------------------------
    /** Key into the BlobStore (filesystem or S3), not the payload itself. */
    sbomBlobKey: text("sbom_blob_key").notNull(),
    sbomSizeBytes: bigint("sbom_size_bytes", { mode: "number" }).notNull().default(0),
    /** SHA-256 of the raw upload; also the basis of the content-addressed blob key. */
    sbomSha256: text("sbom_sha256").notNull(),

    // --- SBOM document metadata ------------------------------------------
    specVersion: text("spec_version"),
    serialNumber: text("serial_number"),
    /** From CycloneDX `metadata.tools` — normally syft and its version. */
    toolName: text("tool_name"),
    toolVersion: text("tool_version"),

    componentCount: integer("component_count").notNull().default(0),

    // --- observed runtime platform ---------------------------------------
    /**
     * What the image is built on, derived from the SBOM's own contents:
     * the OS distribution and the language runtimes present.
     *
     * Stored as columns on `scan` rather than as `component` rows because this
     * describes the scan, not a dependency: it is read on every list and detail
     * page and must not require a join through `scan_component`. The OS package
     * itself is still recorded as a component too — these are a denormalised
     * summary, not a replacement.
     *
     * All nullable. A scratch or distroless image genuinely has no OS release
     * file and no runtime binary, and null is the honest answer for it.
     */
    osName: text("os_name"),
    osVersion: text("os_version"),
    /** The distro's own pretty name, e.g. `Alpine Linux v3.20`. */
    osPretty: text("os_pretty"),
    /**
     * `[{ "name": "node", "version": "22.11.0" }]`, canonical names, sorted.
     *
     * jsonb rather than a child table: it is a short list read as a unit on
     * every page that shows a scan, and a `runtime` table would add a join to
     * the hottest read path to model at most a handful of rows per scan.
     */
    runtimes: jsonb("runtimes").$type<Array<{ name: string; version: string | null }>>(),
  },
  (t) => [
    // The scan-history query: newest-first for one application.
    index("scan_application_created_idx").on(t.applicationId, t.createdAt.desc()),
    index("scan_created_idx").on(t.createdAt.desc()),
    index("scan_commit_sha_idx").on(t.commitSha),
    /**
     * Supports the applications-list OS filter and the dashboard's platform
     * breakdown, both of which reach `scan` through `application.latest_scan_id`.
     */
    index("scan_os_idx").on(t.osName, t.osVersion),
    /**
     * Serves `runtimes @> '[{"name":"node"}]'::jsonb`, which is how the runtime
     * filter has to be written — a `->>` comparison on an array element cannot
     * use an index at all.
     */
    index("scan_runtimes_gin").using("gin", t.runtimes),
    /**
     * Serves the manual upload's duplicate check: "has this application already
     * received this exact SBOM". Scoped to one application on purpose — the same
     * bytes legitimately appear under several applications, and the blob store
     * already deduplicates the payload itself.
     */
    index("scan_application_sha_idx").on(t.applicationId, t.sbomSha256),
    /**
     * Partial, like component_kind_idx: `ci` is the overwhelming majority, so a
     * full index on `source` would be almost entirely dead entries. This one
     * answers "every scan that was uploaded by hand" — the question an auditor
     * asks — while costing nothing on the ingest path.
     */
    index("scan_source_idx").on(t.source, t.createdAt.desc()).where(sql`${t.source} <> 'ci'`),
  ],
);

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

/**
 * Deduplicated package identity. One row per distinct package across the whole
 * organisation, referenced by every scan that contains it.
 *
 * `id` is a bigserial rather than a uuid on purpose: it is the foreign key in
 * `scanComponent`, by far the largest table, and 8 bytes per row instead of 16
 * matters at hundreds of millions of rows.
 */
export const component = pgTable(
  "component",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),

    /**
     * Stable dedupe key: SHA-256 of the purl when the SBOM provides one, else of
     * `ecosystem|name|version`.
     *
     * Preferring the purl over a name+version+ecosystem triple matters for OS
     * packages: two deb entries can share name and version but differ by
     * architecture or epoch, which the purl qualifiers capture and a bare triple
     * silently collapses.
     */
    identityHash: text("identity_hash").notNull(),

    name: text("name").notNull(),
    /** Nullable: CycloneDX permits a component with no resolvable version. */
    version: text("version"),

    /**
     * What sort of thing this is: `library` (an ordinary dependency), `os` (the
     * base distribution), or `runtime` (an interpreter or application server
     * found by Syft's binary classifier).
     *
     * All three are genuinely part of the inventory and all three stay
     * searchable — "which images carry nginx" is a real question. The
     * distinction exists because they answer different ones, and mixing them
     * silently distorts aggregates: without it, "most widely deployed packages"
     * ranks `alpine` alongside `log4j-core`, which makes a blast-radius list
     * that nobody should act on.
     */
    kind: text("kind").$type<"library" | "os" | "runtime">().notNull().default("library"),
    /** npm, pypi, deb, apk, maven, golang, ... Free text so unknown types are kept, not dropped. */
    ecosystem: text("ecosystem").notNull().default("unknown"),
    purl: text("purl"),
    /**
     * Primary CPE from the SBOM, if present. Unused in this phase; captured
     * because it is a join key a future CVE-matching phase will want, and it is
     * free to record now but expensive to backfill later.
     */
    cpe: text("cpe"),

    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),

    /**
     * When this component was last matched against the vulnerability database,
     * and which database build it was matched against.
     *
     * These two columns ARE the scanner's work queue. There is no job table: the
     * set of components needing a scan is derived as
     * `vuln_scanned_at IS NULL OR vuln_db_built_at < <current db build>`.
     *
     * That is deliberate and load-bearing. A queue can be lost, double-consumed,
     * or drift out of sync with reality; derived state cannot. The same expression
     * covers all four cases that need a scan — a brand-new package, the first time
     * scanning is enabled, a newly published database, and a sweep that was killed
     * halfway — and a worker restarted mid-sweep resumes exactly where it stopped
     * without any recovery logic.
     */
    vulnScannedAt: timestamp("vuln_scanned_at", { withTimezone: true }),
    /** `built` timestamp of the grype DB that produced this component's findings. */
    vulnDbBuiltAt: timestamp("vuln_db_built_at", { withTimezone: true }),
  },
  (t) => [
    // Must be UNIQUE: ingest dedupes via
    // `INSERT ... ON CONFLICT (identity_hash) DO NOTHING`, which requires it.
    uniqueIndex("component_identity_hash_uniq").on(t.identityHash),
    /**
     * Serves the sweep's "what still needs scanning" claim query. Partial, because
     * once the estate is caught up almost every row is excluded — indexing all of
     * them would be a large, almost entirely dead index on the platform's biggest
     * dimension table.
     */
    index("component_vuln_pending_idx")
      .on(t.vulnDbBuiltAt)
      .where(sql`${t.vulnScannedAt} IS NULL OR ${t.vulnDbBuiltAt} IS NULL`),
    // Partial / fuzzy package-name search. Requires the pg_trgm extension,
    // installed by the first migration.
    index("component_name_trgm_idx").using("gin", sql`${t.name} gin_trgm_ops`),
    // Exact, case-insensitive name lookup — the common search path.
    index("component_name_lower_idx").on(sql`lower(${t.name})`, t.version),
    index("component_ecosystem_idx").on(t.ecosystem),
    index("component_purl_idx").on(t.purl),
    /**
     * Partial index on the non-library rows only. There are a handful of OS and
     * runtime components across the whole estate against potentially millions of
     * libraries, so indexing `kind` in full would be almost entirely dead
     * entries; this way the aggregate queries that exclude them stay cheap
     * without paying for an index on the common value.
     */
    index("component_kind_idx").on(t.kind).where(sql`${t.kind} <> 'library'`),
  ],
);

/**
 * The scan-to-component join. This powers both per-scan dependency listing and
 * global cross-application search, and it is the table that grows without
 * bound: roughly (scans per day) x (packages per image).
 *
 * `applicationId` and `createdAt` are denormalised from `scan` for two reasons:
 *   1. Global historical search ("which apps have ever shipped log4j") becomes a
 *      single index scan with no join back to `scan`.
 *   2. `createdAt` provides a future range-partition key without touching any
 *      query in the read layer.
 */
export const scanComponent = pgTable(
  "scan_component",
  {
    scanId: uuid("scan_id")
      .notNull()
      .references(() => scan.id, { onDelete: "cascade" }),
    componentId: bigint("component_id", { mode: "number" })
      .notNull()
      .references(() => component.id, { onDelete: "restrict" }),
    applicationId: uuid("application_id")
      .notNull()
      .references(() => application.id, { onDelete: "cascade" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    // Per-scan component listing and the diff queries read by scan_id prefix.
    primaryKey({ name: "scan_component_pkey", columns: [t.scanId, t.componentId] }),
    /**
     * The one index that serves global search. Column order is deliberate:
     *   - `component_id` is always the equality predicate
     *   - `application_id` gives the DISTINCT for historical scope
     *   - `scan_id` lets the current-scope query check against
     *     `application.latest_scan_id` without leaving the index
     * One covering index instead of three narrower ones keeps write
     * amplification down on the hottest insert path in the system.
     */
    index("scan_component_search_idx").on(t.componentId, t.applicationId, t.scanId),
    // Used when reassigning scans during a merge.
    index("scan_component_application_idx").on(t.applicationId),
  ],
);

// ---------------------------------------------------------------------------
// Saved package lists
// ---------------------------------------------------------------------------

/**
 * A submitted bulk package list, kept so its results have a shareable URL.
 *
 * Bulk search takes a pasted list, which can be hundreds of lines and therefore
 * has to travel in a request body — and a POST has no address to send someone.
 * Persisting the list gives `/search/list/:id` a real link, which matters because
 * the output of one of these searches is normally pasted into a ticket that other
 * people then read.
 *
 * What is stored is the *question*, never the answer. Results are recomputed on
 * every open: "which applications ship this package" changes with every scan, and
 * a cached result behind a permanent link would be a stale answer wearing a
 * current URL.
 */
export const packageQuery = pgTable(
  "package_query",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    /**
     * SHA-256 of the normalised, deduplicated entry list.
     *
     * Content-addressed so resubmitting the same list returns the same URL rather
     * than accumulating a row per click. Derived from the parsed entries, not the
     * raw text, so reordering lines or changing whitespace still collapses.
     */
    inputHash: text("input_hash").notNull(),
    /**
     * The text exactly as pasted, so reopening the link repopulates the box with
     * what was typed — including the lines that failed to parse, which are the
     * ones someone will want to fix.
     */
    rawInput: text("raw_input").notNull(),
    /** Parsed entry count, for listing saved lists without re-parsing. */
    entryCount: integer("entry_count").notNull().default(0),
    createdByUserId: uuid("created_by_user_id").references(() => user.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    /** Bumped on every open, so a retention sweep can distinguish live links from abandoned ones. */
    lastAccessedAt: timestamp("last_accessed_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    // Must be UNIQUE: the submit path upserts on this to make resubmission
    // idempotent.
    uniqueIndex("package_query_input_hash_uniq").on(t.inputHash),
    index("package_query_last_accessed_idx").on(t.lastAccessedAt),
  ],
);

// ---------------------------------------------------------------------------
// Ingest tokens
// ---------------------------------------------------------------------------

/**
 * Shared bearer tokens presented by CI/CD on `POST /api/v1/scans`.
 *
 * These identify "a trusted CI system", not an application — application
 * identity comes entirely from the `app_name` form field. Multiple named tokens
 * are supported so Jenkins and GitLab (or per-environment runners) can be
 * rotated and revoked independently, even though only one may be in use today.
 *
 * Only the SHA-256 of the token is stored. Env-configured bootstrap tokens
 * (`INGEST_TOKENS`) are accepted in addition to these rows, which gives a
 * break-glass path if every DB token ends up revoked.
 */
export const ingestToken = pgTable(
  "ingest_token",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    name: text("name").notNull(),
    tokenHash: text("token_hash").notNull(),
    /** Last 4 characters of the plaintext, so the UI can tell tokens apart. */
    tokenSuffix: text("token_suffix").notNull(),
    isActive: boolean("is_active").notNull().default(true),
    createdByUserId: uuid("created_by_user_id").references(() => user.id, { onDelete: "set null" }),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex("ingest_token_name_uniq").on(t.name),
    uniqueIndex("ingest_token_hash_uniq").on(t.tokenHash),
    index("ingest_token_active_idx").on(t.isActive),
  ],
);

// ---------------------------------------------------------------------------
// Audit trail
// ---------------------------------------------------------------------------

/**
 * Append-only record of admin write actions.
 *
 * The motivating case is pending-app resolution: a merge moves scan history
 * between applications and then deletes the source app, so without this table
 * "why is this app gone / why does it have someone else's scans" is
 * unanswerable. Kept generic so user and attribute changes land here too.
 *
 * `actorUserId` is nullable and `actorEmail` is denormalised so the trail
 * survives deletion of the actor's account.
 */
export const auditLog = pgTable(
  "audit_log",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    actorUserId: uuid("actor_user_id").references(() => user.id, { onDelete: "set null" }),
    actorEmail: text("actor_email"),
    /** e.g. `application.merge_always`, `user.deactivate`, `application.update`. */
    action: text("action").notNull(),
    /** `application` | `user` | `scan` | `attribute_definition` | `ingest_token` */
    targetType: text("target_type").notNull(),
    targetId: text("target_id"),
    /** Action-specific payload: before/after values, counts, merge source and destination. */
    metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull().default({}),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index("audit_log_created_idx").on(t.createdAt.desc()),
    index("audit_log_target_idx").on(t.targetType, t.targetId),
    index("audit_log_actor_idx").on(t.actorUserId),
  ],
);

// ---------------------------------------------------------------------------
// Vulnerabilities
// ---------------------------------------------------------------------------

/**
 * One row per advisory, as Grype identifies it.
 *
 * The primary key is Grype's own primary id, which is frequently a GHSA rather
 * than a CVE (`GHSA-jfh8-c2jp-5v3q` for Log4Shell, with `CVE-2021-44228` as an
 * alias). Keying on that and holding the CVE ids in `aliases` is what stops the
 * same underlying vulnerability being counted twice under two names, while still
 * letting someone search for the CVE number they read in the news.
 *
 * Severity, CVSS, EPSS and the known-exploited flag are stored as reported rather
 * than combined into a score of our own. The platform does not invent a risk
 * number: it shows what the upstream feeds say.
 */
export const vulnerability = pgTable(
  "vulnerability",
  {
    /** Grype's primary advisory id: GHSA-…, CVE-…, ALAS-…, RHSA-…. */
    id: text("id").primaryKey(),
    severity: text("severity").$type<VulnSeverity>().notNull().default("unknown"),
    /** CVSS base score, when the advisory carries one. Null is common and meaningful. */
    cvssBaseScore: doublePrecision("cvss_base_score"),
    cvssVector: text("cvss_vector"),
    /** Exploit Prediction Scoring System: probability of exploitation in the next 30 days. */
    epssScore: doublePrecision("epss_score"),
    epssPercentile: doublePrecision("epss_percentile"),
    /**
     * On CISA's Known Exploited Vulnerabilities list.
     *
     * Worth its own indexed column rather than being buried in a JSON blob: "is
     * anything we ship being actively exploited right now" is the one question
     * that justifies waking someone up, and it must be answerable in one index
     * scan.
     */
    knownExploited: boolean("known_exploited").notNull().default(false),
    description: text("description"),
    /** Which upstream feed reported it, e.g. `github:language:java`. */
    dataSource: text("data_source"),
    namespace: text("namespace"),
    /** CVE and other ids for the same advisory, so a CVE search reaches a GHSA row. */
    aliases: text("aliases").array().notNull().default([]),
    urls: text("urls").array().notNull().default([]),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index("vulnerability_severity_idx").on(t.severity),
    /** Partial: the KEV list is a few thousand entries against millions of advisories. */
    index("vulnerability_kev_idx").on(t.knownExploited).where(sql`${t.knownExploited}`),
    /** Serves `aliases @> ARRAY['CVE-2021-44228']`, the CVE-number search path. */
    index("vulnerability_aliases_gin").using("gin", t.aliases),
  ],
);

/**
 * The findings table: which package is affected by which advisory.
 *
 * Keyed on `component_id`, NOT on `scan_id`, and that is the single most
 * consequential decision in this feature. A vulnerability is a property of a
 * package version, not of a build that happened to contain it — so matching the
 * platform's globally deduplicated component set covers every scan that has ever
 * contained those packages, including historical builds and applications nobody
 * has confirmed yet.
 *
 * Two things follow that would otherwise be expensive or impossible:
 *   - Re-evaluating the whole estate after a database update is one pass over
 *     distinct components (measured: ~2 minutes per 50,000) rather than one Grype
 *     run per application (measured: ~9 seconds each).
 *   - "Which applications are affected by CVE-2021-44228" is a join through the
 *     existing `scan_component_search_idx`, answered against today's data rather
 *     than against whatever was known on each build's scan date.
 */
export const componentVulnerability = pgTable(
  "component_vulnerability",
  {
    componentId: bigint("component_id", { mode: "number" })
      .notNull()
      .references(() => component.id, { onDelete: "cascade" }),
    vulnerabilityId: text("vulnerability_id")
      .notNull()
      .references(() => vulnerability.id, { onDelete: "cascade" }),
    /** `fixed`, `not-fixed`, `wont-fix` or `unknown`, as Grype reports it. */
    fixState: text("fix_state").$type<FixState>().notNull().default("unknown"),
    /** Versions that resolve it. The actionable half of a finding. */
    fixVersions: text("fix_versions").array().notNull().default([]),
    /** Grype's match type, e.g. `exact-direct-match` — why it believes this matches. */
    matchType: text("match_type"),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
    /** Last sweep that still reported this pairing; lets a withdrawn advisory be pruned. */
    lastConfirmedAt: timestamp("last_confirmed_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ name: "component_vulnerability_pkey", columns: [t.componentId, t.vulnerabilityId] }),
    /**
     * The reverse direction: "who is affected by this advisory". The primary key
     * already covers component-first lookups, so this is the only additional index
     * needed, and it is what makes the CVE search page a single scan.
     */
    index("component_vulnerability_vuln_idx").on(t.vulnerabilityId),
    /** Partial: fixable findings are the actionable worklist, and most are fixable. */
    index("component_vulnerability_fix_idx").on(t.fixState).where(sql`${t.fixState} = 'fixed'`),
  ],
);

/**
 * Per-scan severity counts, frozen when the scan was matched.
 *
 * Serves two purposes that the live findings table cannot:
 *   1. An exposure trend — "how bad were we in June" — which a live join can only
 *      ever answer for today.
 *   2. Pre-aggregated ranking. "Top 10 vulnerable applications" reads one row per
 *      application here instead of joining millions of `scan_component` rows.
 *
 * The split between application dependencies and base image is not cosmetic.
 * Measured on a realistic container SBOM: 2,845 findings, of which 2,817 came from
 * base-image OS packages. Ranked together, every "most vulnerable" list is really a
 * list of who has the oldest base image, and the application's own dependencies —
 * the part a squad can actually act on — are statistically invisible.
 */
export const scanVulnSummary = pgTable(
  "scan_vuln_summary",
  {
    scanId: uuid("scan_id")
      .primaryKey()
      .references(() => scan.id, { onDelete: "cascade" }),
    applicationId: uuid("application_id")
      .notNull()
      .references(() => application.id, { onDelete: "cascade" }),
    computedAt: timestamp("computed_at", { withTimezone: true }).notNull().defaultNow(),
    /** Which database build produced these counts, so a stale figure is explainable. */
    dbBuiltAt: timestamp("db_built_at", { withTimezone: true }),
    grypeVersion: text("grype_version"),

    /*
     * Columns for what is ranked and filtered on; jsonb for the full breakdown
     * that is only ever read as a unit. Splitting it this way keeps the ranking
     * queries indexable without fourteen integer columns whose only job is to be
     * rendered in one chart.
     */
    appFindings: integer("app_findings").notNull().default(0),
    appCritical: integer("app_critical").notNull().default(0),
    appHigh: integer("app_high").notNull().default(0),
    appFixable: integer("app_fixable").notNull().default(0),
    appKnownExploited: integer("app_known_exploited").notNull().default(0),
    /** Distinct packages with at least one finding — a fairer size signal than raw findings. */
    appAffectedPackages: integer("app_affected_packages").notNull().default(0),

    osFindings: integer("os_findings").notNull().default(0),
    osCritical: integer("os_critical").notNull().default(0),
    osHigh: integer("os_high").notNull().default(0),
    osAffectedPackages: integer("os_affected_packages").notNull().default(0),
    /*
     * Symmetric with the application side. "Is a rebuild going to fix this" is the
     * question a reader has the moment they select base image as a scope, and it cannot
     * be answered from the severity breakdown alone.
     */
    osFixable: integer("os_fixable").notNull().default(0),
    osKnownExploited: integer("os_known_exploited").notNull().default(0),

    /** Full severity breakdown for both groups, including negligible and unknown. */
    counts: jsonb("counts").$type<{ app: SeverityCounts; os: SeverityCounts }>(),
  },
  (t) => [
    index("scan_vuln_summary_application_idx").on(t.applicationId, t.computedAt.desc()),
    /** The ranking index: "worst applications first" without a sort over the whole table. */
    index("scan_vuln_summary_rank_idx").on(t.appFindings.desc()),
  ],
);

/**
 * Accepted risk: a finding an administrator has assessed and chosen to exclude.
 *
 * Without this, a vulnerability dashboard only ever grows, and a list nobody can
 * drive to zero is a list people stop reading. Suppressed findings are excluded
 * from every count and ranking but remain visible in their own view, because
 * "hidden" and "deleted" must not be the same thing when someone asks six months
 * later why a known CVE was not being reported.
 *
 * Scope widens with nullability: both ids null suppresses the advisory estate-wide,
 * `componentId` limits it to one package version, `applicationId` to one
 * application.
 */
export const vulnerabilitySuppression = pgTable(
  "vulnerability_suppression",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    vulnerabilityId: text("vulnerability_id").notNull(),
    componentId: bigint("component_id", { mode: "number" }).references(() => component.id, {
      onDelete: "cascade",
    }),
    applicationId: uuid("application_id").references(() => application.id, { onDelete: "cascade" }),
    /** Required. A suppression with no stated reason is indistinguishable from a mistake. */
    reason: text("reason").notNull(),
    /** Optional review date, so an accepted risk can be made to expire rather than persist forever. */
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    createdByUserId: uuid("created_by_user_id").references(() => user.id, { onDelete: "set null" }),
    createdByEmail: text("created_by_email"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index("vulnerability_suppression_vuln_idx").on(t.vulnerabilityId),
    index("vulnerability_suppression_component_idx").on(t.componentId),
    index("vulnerability_suppression_application_idx").on(t.applicationId),
  ],
);

// ---------------------------------------------------------------------------
// Runtime settings
// ---------------------------------------------------------------------------

/**
 * Admin-editable runtime configuration.
 *
 * Distinct from `config.ts`, which reads the environment once at boot and is the
 * deployment operator's domain. This table is for the handful of values an
 * administrator changes from the UI while the service runs — whether vulnerability
 * scanning is on, and how often the database is checked.
 *
 * Deliberately not used for anything that decides what code runs or what the
 * server may execute. Paths and credentials stay in the environment, where
 * changing them requires access to the deployment rather than an admin session.
 */
export const setting = pgTable("setting", {
  key: text("key").primaryKey(),
  value: jsonb("value").notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  updatedByUserId: uuid("updated_by_user_id").references(() => user.id, { onDelete: "set null" }),
  updatedByEmail: text("updated_by_email"),
});

/**
 * One generated report, with the snapshot the next one diffs against.
 *
 * The snapshot is the reason this table exists rather than the report being recomputed on
 * demand. Two things cannot be recovered from live data later:
 *
 *   1. Deleted applications. Once an application is removed its rows are gone, so "which
 *      applications disappeared this month" is unanswerable without a record of what was
 *      there. Diffing live history would silently report no change.
 *   2. What was *known* at the time. Findings are matched against today's vulnerability
 *      database across retained builds, so re-running last month's query today yields
 *      today's answer, not last month's. Without a snapshot, "47 fixed" cannot be
 *      distinguished from "the database changed", which is the distinction the report is
 *      for.
 *
 * `baseline_run_id` records what each report was actually compared against, so a reader can
 * tell whether a delta covers one month or three -- rather than assuming a regular cadence
 * that a missed run would quietly break.
 */
export const reportRun = pgTable(
  "report_run",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    /**
     * `monthly` is the scheduled series; `adhoc` is the button.
     *
     * Kept apart because ad-hoc runs must not move the monthly baseline. If a mid-month
     * click became the next month's comparison point, the monthly report would silently
     * cover a fortnight while still being labelled a month.
     */
    kind: text("kind").notNull(),
    periodStart: timestamp("period_start", { withTimezone: true }).notNull(),
    periodEnd: timestamp("period_end", { withTimezone: true }).notNull(),
    /**
     * `YYYY-MM` of the month covered, and the zone that decided it.
     *
     * Stored rather than derived from `period_start`, because deriving it needs a timezone
     * and the bounds are local midnights: July in UTC+4 starts at 20:00 on 30 June UTC, so
     * formatting the start in UTC labels a July report "June". Recomputing it on read would
     * also let an administrator relabel every historical report by changing one setting,
     * which is not something a record of what management was told should permit.
     */
    periodLabel: text("period_label").notNull(),
    timeZone: text("time_zone").notNull(),
    generatedAt: timestamp("generated_at", { withTimezone: true }).notNull().defaultNow(),
    /** Null for a scheduled run: nobody pressed anything. */
    generatedByUserId: uuid("generated_by_user_id").references(() => user.id, {
      onDelete: "set null",
    }),
    generatedByEmail: text("generated_by_email"),
    /** The run this was compared against. Null for the first report, which has no baseline. */
    baselineRunId: uuid("baseline_run_id"),
    /**
     * Build date of the vulnerability database at generation time.
     *
     * The single most important field for honest attribution: if this moved between two
     * reports, some of the difference in findings is the database rather than the estate,
     * and the report has to say so instead of crediting the change to anyone.
     */
    vulnDbBuiltAt: timestamp("vuln_db_built_at", { withTimezone: true }),
    /**
     * `full` carries per-finding keys, so a change can be attributed to a cause. `aggregate`
     * carries totals only, for an estate too large to snapshot in detail.
     *
     * Explicit rather than inferred from the payload, so a degraded snapshot degrades the
     * report's claims visibly instead of producing confident numbers from thinner data.
     */
    detailLevel: text("detail_level").notNull().default("full"),
    snapshot: jsonb("snapshot").notNull(),
    /** Key in the blob store. Null while a run is still being rendered, or if rendering failed. */
    pdfBlobKey: text("pdf_blob_key"),
    /** Delivery is recorded separately from generation: a report can exist and not be sent. */
    sentAt: timestamp("sent_at", { withTimezone: true }),
    recipients: jsonb("recipients"),
    deliveryError: text("delivery_error"),
  },
  (t) => [
    /*
      The guarantee that a restart cannot send twice, held in the database rather than in
      application logic. A scheduler that checks "have I run this month" and then inserts has
      a window between the two, and process restarts are exactly when that window is hit. A
      unique index makes the second insert fail instead.

      Scoped to the monthly series so ad-hoc runs stay unconstrained -- pressing the button
      twice in a month is a reasonable thing to do.
    */
    uniqueIndex("report_run_monthly_period_key")
      .on(t.kind, t.periodStart)
      .where(sql`kind = 'monthly'`),
    index("report_run_generated_at_idx").on(t.generatedAt),
  ],
);

/**
 * History of vulnerability database update attempts, successful or not.
 *
 * Every attempt is recorded, including the ones that failed because the server has
 * no route to the internet. That is the point: an air-gapped deployment needs to
 * show an administrator *why* the database is three weeks old, with the exact URL
 * that could not be reached, rather than leaving them to guess. A failure here is
 * never an error anywhere else in the platform.
 */
export const vulnDbUpdate = pgTable(
  "vuln_db_update",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
    finishedAt: timestamp("finished_at", { withTimezone: true }),
    /** What asked for it: a button, the schedule, enabling the feature, or a file import. */
    trigger: text("trigger").$type<VulnDbUpdateTrigger>().notNull(),
    outcome: text("outcome").$type<VulnDbUpdateOutcome>(),
    /** Grype's own message on failure, including the URL it could not reach. */
    message: text("message"),
    dbBuiltBefore: timestamp("db_built_before", { withTimezone: true }),
    dbBuiltAfter: timestamp("db_built_after", { withTimezone: true }),
    schemaVersion: text("schema_version"),
    sourceUrl: text("source_url"),
    actorUserId: uuid("actor_user_id").references(() => user.id, { onDelete: "set null" }),
    actorEmail: text("actor_email"),
  },
  (t) => [index("vuln_db_update_started_idx").on(t.startedAt.desc())],
);

// ---------------------------------------------------------------------------
// Inferred row types
// ---------------------------------------------------------------------------

export type UserRow = typeof user.$inferSelect;
export type NewUserRow = typeof user.$inferInsert;
export type SessionRow = typeof session.$inferSelect;
export type ApplicationRow = typeof application.$inferSelect;
export type NewApplicationRow = typeof application.$inferInsert;
export type ApplicationAliasRow = typeof applicationAlias.$inferSelect;
export type ApplicationGroupRow = typeof applicationGroup.$inferSelect;
export type ApplicationGroupMemberRow = typeof applicationGroupMember.$inferSelect;
export type AttributeDefinitionRow = typeof attributeDefinition.$inferSelect;
export type ScanRow = typeof scan.$inferSelect;
export type NewScanRow = typeof scan.$inferInsert;
export type ComponentRow = typeof component.$inferSelect;
export type NewComponentRow = typeof component.$inferInsert;
export type ScanComponentRow = typeof scanComponent.$inferSelect;
export type NewScanComponentRow = typeof scanComponent.$inferInsert;
export type PackageQueryRow = typeof packageQuery.$inferSelect;
export type IngestTokenRow = typeof ingestToken.$inferSelect;
export type AuditLogRow = typeof auditLog.$inferSelect;
export type VulnerabilityRow = typeof vulnerability.$inferSelect;
export type NewVulnerabilityRow = typeof vulnerability.$inferInsert;
export type ComponentVulnerabilityRow = typeof componentVulnerability.$inferSelect;
export type NewComponentVulnerabilityRow = typeof componentVulnerability.$inferInsert;
export type ScanVulnSummaryRow = typeof scanVulnSummary.$inferSelect;
export type VulnerabilitySuppressionRow = typeof vulnerabilitySuppression.$inferSelect;
export type SettingRow = typeof setting.$inferSelect;
export type VulnDbUpdateRow = typeof vulnDbUpdate.$inferSelect;
