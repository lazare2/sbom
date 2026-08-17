import { sql, type SQL } from "drizzle-orm";
import type {
  BulkEntry,
  BulkRollupRow,
  BulkSearchQuery,
  BulkSearchResult,
  BulkSearchSummary,
  ComponentSearchHit,
  SavedPackageList,
  SortDirection,
} from "@sbom/shared";
import { BULK_MATCH_CAP_PER_ENTRY } from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { sha256Hex } from "../../lib/crypto.js";
import { offsetOf, paginate, totalFromRows } from "../../lib/pagination.js";
import { direction, directionNullsLast, orderBy } from "../../lib/sorting.js";
import { rowsOf, toIso, type Row } from "../applications/applications.service.js";
import { matchKeyOf, parseBulkInput } from "./bulk-parse.js";
import { NotFoundError } from "../../lib/errors.js";

/**
 * Sort clause for the flat matches table.
 *
 * The same columns as the single search, over the same row shape, but the aliases differ
 * (`m`/`a` here against a `matched` CTE rather than the search's), so the clause is written
 * out rather than shared. `(m.id, a.id)` is the unique tail — the DISTINCT ON key of
 * `usage`, one row per output row.
 */
function bulkMatchesOrderBy(sortBy: BulkSearchQuery["sortBy"], dir: SortDirection): SQL {
  const dir_ = direction(dir);
  const nulls = directionNullsLast(dir);
  const byPackage = sql`lower(m.name) ASC, m.version ASC NULLS LAST`;
  const byApp = sql`lower(a.name) ASC`;
  const unique = sql`m.id, a.id`;

  switch (sortBy) {
    case "applicationStatus":
      return orderBy([sql`a.status ${dir_}`, byApp, byPackage], unique);
    case "componentName":
      return orderBy([sql`lower(m.name) ${dir_}`, sql`m.version ASC NULLS LAST`, byApp], unique);
    case "componentVersion":
      return orderBy([sql`m.version ${nulls}`, byPackage, byApp], unique);
    case "ecosystem":
      return orderBy([sql`m.ecosystem ${dir_}`, byPackage, byApp], unique);
    case "usage":
      return orderBy([sql`(u.last_seen_scan_id = a.latest_scan_id) ${dir_}`, byApp, byPackage], unique);
    case "lastSeenAt":
      return orderBy([sql`u.last_seen_at ${nulls}`, byApp, byPackage], unique);
    case "applicationName":
    default:
      return orderBy([sql`lower(a.name) ${dir_}`, byPackage], unique);
  }
}

/**
 * How many distinct versions of one package the rollup names before summarising.
 *
 * A row exists to answer "is this here, and at what versions". Listing 60 deb
 * revisions of `libc6` on one line answers it worse than listing six and saying
 * there are more.
 */
const VERSIONS_PER_ROW = 8;

/**
 * Escapes a term for use inside an `ILIKE '%' || … || '%'` pattern.
 *
 * Without this, a pasted name containing `%` or `_` becomes a wildcard: an entry of
 * `foo_bar` would match `fooXbar`, and a stray `%` would match the entire component table
 * while looking like an ordinary line in the input. Postgres treats backslash as the
 * default LIKE escape, so the backslash itself has to be doubled first.
 *
 * Done in JS rather than SQL so the pattern is a plain bound parameter and the arrays stay
 * as they are — the whole query is still four parameters.
 */
export function escapeLikeTerm(term: string): string {
  return term.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
}

/**
 * Bulk package search.
 *
 * The query passes the parsed list to Postgres as parallel arrays and `unnest`s
 * them into a virtual table. That choice does the real work here:
 *
 *   - It is three bind parameters regardless of list length, so a 1000-entry
 *     paste comes nowhere near the 65535-parameter ceiling that a generated
 *     `IN (...)` list would hit.
 *   - It gives every input line a row in the query, so a `LEFT JOIN` onto
 *     `component` keeps the misses alive all the way to the result. The misses are
 *     the point of the feature: if three of forty packages are present, the answer
 *     is mostly about the other thirty-seven.
 *
 * Name matching defaults to exact and case-insensitive, which is what let the original
 * query stay bounded by the input line count alone — an exact match cannot blow up the way
 * a two-character substring can, so no equivalent of the single search's `MATCH_CAP` was
 * needed. `match=contains` removes that guarantee, and pays for it with
 * BULK_MATCH_CAP_PER_ENTRY: a `dense_rank()` window per input line, so one broad entry
 * degrades its own row and reports that it did, rather than consuming a shared budget and
 * making every other line look absent.
 */
export class BulkSearchService {
  constructor(private readonly deps: { db: Database }) {}

  /**
   * The name-match predicate, and the per-line cap that has to accompany it.
   *
   * Returned together because they are one decision: substring matching without the cap is
   * the unbounded query this service was originally written to avoid, and the cap without
   * substring matching would silently truncate version lists that exact mode is supposed
   * to return whole.
   */
  private nameMatch(query: BulkSearchQuery): { condition: (nameKey: SQL) => SQL; cap: number | null } {
    if (query.match === "contains") {
      return {
        condition: (nameKey) => sql`c.name ILIKE '%' || ${nameKey} || '%'`,
        cap: BULK_MATCH_CAP_PER_ENTRY,
      };
    }
    return {
      // Served by component_name_lower_idx: one index probe per entry rather than a scan.
      condition: (nameKey) => sql`lower(c.name) = ${nameKey}`,
      // No cap: exact mode must keep returning every version of a name, which is what
      // `versionsFound` reports and what makes a version miss explainable.
      cap: null,
    };
  }

  /**
   * The name keys to bind, prepared for whichever comparison is in play.
   *
   * Lowercased for the exact path because it compares against `lower(c.name)`; escaped for
   * the contains path because it becomes a LIKE pattern. Keeping both in one place is what
   * stops an unescaped term reaching a pattern.
   */
  private nameKeys(entries: readonly BulkEntry[], query: BulkSearchQuery): string[] {
    return entries.map((e) =>
      query.match === "contains" ? escapeLikeTerm(e.name.toLowerCase()) : e.name.toLowerCase(),
    );
  }

  /**
   * Parse, persist, and run a list.
   *
   * Persisting is unconditional and has no separate "save" action: the list is the
   * question, the question is what is worth linking to, and a submit that did not
   * produce a URL would make the shareable case a second workflow nobody uses.
   */
  async submit(args: {
    input: string;
    query: BulkSearchQuery;
    userId: string | null;
  }): Promise<BulkSearchResult> {
    const { entries, summary } = parseBulkInput(args.input);

    const queryId = await this.saveList({
      rawInput: args.input,
      entries,
      userId: args.userId,
    });

    return this.run({ queryId, entries, parse: summary, query: args.query });
  }

  /**
   * Re-run a saved list.
   *
   * Results are recomputed, never cached. "Which applications ship this package"
   * changes with every scan, and a stored answer behind a permanent link would be
   * a stale result wearing a current URL.
   */
  async rerun(args: { queryId: string; query: BulkSearchQuery }): Promise<BulkSearchResult> {
    const { db } = this.deps;

    const rows = await db.execute<Row<{ raw_input: string }>>(sql`
      UPDATE package_query
      SET last_accessed_at = now()
      WHERE id = ${args.queryId}::uuid
      RETURNING raw_input
    `);

    const row = rowsOf(rows)[0];
    if (!row) throw new NotFoundError("This package list no longer exists.");

    const { entries, summary } = parseBulkInput(row.raw_input);
    return this.run({ queryId: args.queryId, entries, parse: summary, query: args.query });
  }

  /** The raw text of a saved list, so the UI can repopulate its input box. */
  async savedInput(queryId: string): Promise<string> {
    const rows = await this.deps.db.execute<Row<{ raw_input: string }>>(sql`
      SELECT raw_input FROM package_query WHERE id = ${queryId}::uuid
    `);
    const row = rowsOf(rows)[0];
    if (!row) throw new NotFoundError("This package list no longer exists.");
    return row.raw_input;
  }

  /** Recently submitted lists, newest use first. */
  async recentLists(limit: number): Promise<SavedPackageList[]> {
    const rows = await this.deps.db.execute<Row<RecentListRow>>(sql`
      SELECT q.id, q.entry_count, q.raw_input, q.created_at, q.last_accessed_at, u.email
      FROM package_query q
      LEFT JOIN "user" u ON u.id = q.created_by_user_id
      ORDER BY q.last_accessed_at DESC
      LIMIT ${limit}
    `);

    return rowsOf(rows).map((r) => ({
      id: r.id,
      entryCount: Number(r.entry_count),
      // Parsed rather than stored: a preview derived from the text cannot drift
      // out of step with what the list actually contains.
      preview: parseBulkInput(r.raw_input).entries.slice(0, 4).map((e) => e.name),
      createdBy: r.email,
      createdAt: toIso(r.created_at)!,
      lastAccessedAt: toIso(r.last_accessed_at)!,
    }));
  }

  /**
   * Content-address the list so resubmitting it returns the same URL instead of
   * accumulating a row per click.
   *
   * The hash covers the normalised match keys, not the raw text, so reordering
   * lines, changing case, or editing a comment still collapses onto one row. The
   * raw text is stored alongside so reopening the link shows what was typed —
   * including the lines that failed to parse, which are the ones someone will want
   * to fix.
   */
  private async saveList(args: {
    rawInput: string;
    entries: readonly BulkEntry[];
    userId: string | null;
  }): Promise<string> {
    const fingerprint = args.entries.map(matchKeyOf).sort().join("\n");
    const inputHash = sha256Hex(Buffer.from(fingerprint, "utf8"));

    const rows = await this.deps.db.execute<Row<{ id: string }>>(sql`
      INSERT INTO package_query (input_hash, raw_input, entry_count, created_by_user_id)
      VALUES (${inputHash}, ${args.rawInput}, ${args.entries.length},
              ${args.userId}::uuid)
      ON CONFLICT (input_hash) DO UPDATE
        /*
         * Only the timestamp. raw_input is deliberately NOT overwritten: two
         * texts that parse to the same entries collide here, so updating it would
         * let someone pasting a bare list silently replace the annotated version
         * behind a link a colleague had already shared. First writer wins keeps a
         * shared URL stable, which is the entire reason the row exists.
         */
        SET last_accessed_at = now()
      RETURNING id
    `);

    const row = rowsOf(rows)[0];
    if (!row) throw new Error("failed to persist package list");
    return row.id;
  }

  private async run(args: {
    queryId: string;
    entries: readonly BulkEntry[];
    parse: BulkSearchResult["parse"];
    query: BulkSearchQuery;
  }): Promise<BulkSearchResult> {
    const { queryId, entries, parse, query } = args;

    if (entries.length === 0) {
      return {
        queryId,
        scope: query.scope,
        parse,
        summary: { found: 0, notFound: 0, inCurrentUse: 0, applicationsAffected: 0 },
        rollup: [],
        ...(query.view === "matches"
          ? { matches: { items: [], page: query.page, pageSize: query.pageSize, total: 0, totalPages: 0 } }
          : {}),
      };
    }

    const { rows: rollup, applicationsAffected } = await this.rollup(entries, query);
    const summary = summarise(rollup, applicationsAffected);

    const matches =
      query.view === "matches" ? await this.matches(entries, query) : undefined;

    return {
      queryId,
      scope: query.scope,
      parse,
      summary,
      rollup,
      ...(matches ? { matches } : {}),
    };
  }

  /**
   * One row per input entry.
   *
   * `currentApplications` and `historicalApplications` are both computed
   * regardless of the requested scope, and that is deliberate: without the
   * historical count, "not found" conflates *never been here* with *we removed it
   * last month*, and those are very different answers to a security question.
   * Scope filters the flat match table, not this verdict.
   */
  private async rollup(
    entries: readonly BulkEntry[],
    query: BulkSearchQuery,
  ): Promise<{ rows: BulkRollupRow[]; applicationsAffected: number }> {
    const lines = entries.map((e) => e.line);
    const names = this.nameKeys(entries, query);
    // Only an `exact` entry constrains the version. A dropped specifier matches
    // every version, which is what makes the over-reporting visible rather than
    // silently wrong.
    const versions = entries.map((e) => (e.versionKind === "exact" ? e.version : null));
    const ecosystems = entries.map((e) => e.ecosystem);
    const { condition: nameCondition, cap } = this.nameMatch(query);

    /*
      `dense_rank`, not `row_number`, and the distinction matters.

      The cap counts distinct package *names*, because that is what the row reports —
      "12 packages matched". Ranking rows instead would count (name, version) pairs, and a
      single deb package with sixty revisions of libc6 in the estate would consume the whole
      budget on its own. The row would then read "1 package matched (partial)", which is
      both useless and alarming, while genuinely different matches went unreported.

      dense_rank gives every version of the first name rank 1, every version of the second
      name rank 2, and so on, so `rn <= cap` keeps the first `cap` names *whole*.

      `matched` keeps one rank beyond the cap so overflow is detectable; `capped` is what
      everything downstream reads. With no cap the two are the same relation and Postgres
      flattens the extra CTE away.
    */
    const rankColumn = cap
      ? sql`, dense_rank() OVER (PARTITION BY q.line ORDER BY lower(c.name) ASC) AS rn`
      : sql`, 1::bigint AS rn`;
    const rankFilter = cap ? sql`WHERE rn <= ${cap + 1}` : sql``;
    const capFilter = cap ? sql`WHERE rn <= ${cap}` : sql``;
    const overflowExpr = cap ? sql`bool_or(m.rn > ${cap})` : sql`FALSE`;

    const statusCondition = query.includeInactive ? sql`` : sql`AND a.status <> 'inactive'`;

    /**
     * Scope narrowing for the estate-wide affected count only.
     *
     * The per-line current/historical counts below are deliberately *not* scoped —
     * a reader needs both to tell "never here" from "removed last month". This
     * filter exists because the headline "N applications affected" should mean what
     * the chosen scope says it means.
     */
    const affectedScope =
      query.scope === "current"
        ? sql`AND in_latest IS TRUE`
        : query.scope === "historical"
          ? sql`AND in_latest IS FALSE`
          : sql``;

    const rows = await this.deps.db.execute<Row<RollupRow>>(sql`
      WITH q AS (
        /*
         * sql.param is required here, not stylistic. Interpolating a JS array into
         * a drizzle template expands it into a parenthesised list of placeholders —
         * a record — and Postgres refuses to cast a record to an array. Wrapping it
         * binds the whole array as one parameter, which is also what keeps this to
         * four parameters no matter how long the list is.
         */
        SELECT *
        FROM unnest(
          ${sql.param(lines)}::int[],
          ${sql.param(names)}::text[],
          ${sql.param(versions)}::text[],
          ${sql.param(ecosystems)}::text[]
        ) AS t(line, name_key, want_version, want_ecosystem)
      ),
      /*
       * LEFT JOIN, not INNER: an entry that matches nothing must survive to the
       * result as a "not found" row. This is the single most important line in the
       * query — an inner join would turn the feature back into the single search.
       *
       * The name comparison is served by component_name_lower_idx, so this is one
       * index probe per entry rather than a scan.
       */
      /*
       * The version is a flag, not a join condition.
       *
       * Joining on it would collapse "this package is absent" and "this package is
       * here but not at that version" into one indistinguishable miss. For an
       * advisory audit the difference is the answer, so the name is matched first
       * and the version is evaluated per row.
       */
      ranked AS (
        SELECT
          q.line, q.name_key,
          c.id AS component_id, c.name AS component_name, c.version, c.ecosystem,
          (q.want_version IS NULL OR c.version = q.want_version) AS version_matches
          ${rankColumn}
        FROM q
        LEFT JOIN component c
          ON ${nameCondition(sql`q.name_key`)}
         AND (q.want_ecosystem IS NULL OR c.ecosystem = q.want_ecosystem)
         AND c.kind = 'library'
      ),
      /*
       * One row past the cap, so matched_names_truncated can be told apart from a line
       * that happened to match exactly the cap. A partial list that reads as complete is
       * the failure mode worth spending a row to avoid.
       */
      matched AS (SELECT * FROM ranked ${rankFilter}),
      capped AS (SELECT * FROM matched ${capFilter}),
      /*
       * Most recent occurrence of each component in each application. Mirrors the
       * single search's shape so both agree about what "currently used" means, and
       * reads straight down scan_component_search_idx.
       */
      usage AS (
        SELECT DISTINCT ON (sc.component_id, sc.application_id)
               sc.component_id, sc.application_id, sc.scan_id AS last_seen_scan_id
        FROM scan_component sc
        WHERE sc.component_id IN (SELECT component_id FROM capped WHERE component_id IS NOT NULL)
        ORDER BY sc.component_id, sc.application_id, sc.created_at DESC, sc.scan_id DESC
      ),
      hits AS (
        SELECT
          m.line,
          m.component_id,
          m.component_name,
          m.version,
          m.ecosystem,
          m.version_matches,
          u.application_id,
          (u.last_seen_scan_id = a.latest_scan_id) AS in_latest
        FROM capped m
        LEFT JOIN usage u      ON u.component_id = m.component_id
        LEFT JOIN application a ON a.id = u.application_id ${statusCondition}
      ),
      /* Overflow is a property of the match, so it is read off matched, before the cap. */
      overflow AS (
        SELECT m.line, ${overflowExpr} AS truncated
        FROM matched m
        GROUP BY m.line
      ),
      /*
       * Distinct applications across the whole list. Cannot be summed from the
       * per-line counts: one application shipping three of the listed packages
       * would be counted three times, which overstates the very figure someone
       * uses to size the work.
       */
      affected AS (
        SELECT count(DISTINCT application_id)::int AS applications_affected
        FROM hits
        WHERE application_id IS NOT NULL AND version_matches ${affectedScope}
      )
      SELECT
        h.line,
        (SELECT applications_affected FROM affected) AS applications_affected,
        -- The name exists in the inventory, at any version.
        bool_or(h.component_id IS NOT NULL) AS name_found,
        -- The query as asked matched, pinned version included.
        bool_or(h.component_id IS NOT NULL AND h.version_matches) AS found,
        array_remove(array_agg(DISTINCT h.ecosystem), NULL) AS ecosystems,
        -- Every version of the name, so a miss can report what IS deployed.
        array_remove(array_agg(DISTINCT h.version), NULL) AS versions,
        -- Distinct packages the line matched. Always one name in exact mode.
        array_remove(array_agg(DISTINCT h.component_name), NULL) AS matched_names,
        (SELECT o.truncated FROM overflow o WHERE o.line = h.line) AS matched_names_truncated,
        count(DISTINCT h.application_id)
          FILTER (WHERE h.in_latest IS TRUE AND h.version_matches)::int AS current_applications,
        count(DISTINCT h.application_id)
          FILTER (WHERE h.in_latest IS FALSE AND h.version_matches)::int AS historical_applications
      FROM hits h
      GROUP BY h.line
    `);

    const resultRows = rowsOf(rows);
    const byLine = new Map<number, RollupRow>();
    for (const row of resultRows) byLine.set(Number(row.line), row);

    // The same scalar on every row; zero when the list matched nothing at all and
    // there are no rows to read it from.
    const applicationsAffected = Number(resultRows[0]?.applications_affected ?? 0);

    // Driven off `entries`, not the query result, so the output order matches the
    // order the list was pasted in. A reader checking their own list against the
    // results should not have to re-sort it.
    const mapped = entries.map((entry) => {
      const row = byLine.get(entry.line);
      const versions = toStringArray(row?.versions).sort();
      const matchedNames = toStringArray(row?.matched_names).sort();
      return {
        line: entry.line,
        raw: entry.raw,
        name: entry.name,
        version: entry.version,
        versionKind: entry.versionKind,
        found: row?.found === true,
        nameFound: row?.name_found === true,
        ecosystems: toStringArray(row?.ecosystems).sort(),
        versionsFound: versions.slice(0, VERSIONS_PER_ROW),
        versionsTruncated: versions.length > VERSIONS_PER_ROW,
        currentApplications: Number(row?.current_applications ?? 0),
        historicalApplications: Number(row?.historical_applications ?? 0),
        matchedNames,
        matchedNameCount: matchedNames.length,
        matchedNamesTruncated: row?.matched_names_truncated === true,
      };
    });

    return { rows: mapped, applicationsAffected };
  }

  /**
   * The flat package × application table, paginated.
   *
   * Returns the single search's `ComponentSearchHit` shape so the web UI renders
   * both with one component and the two views cannot drift apart in how they
   * describe a hit.
   */
  private async matches(
    entries: readonly BulkEntry[],
    query: BulkSearchQuery,
  ): Promise<NonNullable<BulkSearchResult["matches"]>> {
    const names = this.nameKeys(entries, query);
    const versions = entries.map((e) => (e.versionKind === "exact" ? e.version : null));
    const ecosystems = entries.map((e) => e.ecosystem);
    const { condition: nameCondition, cap } = this.nameMatch(query);

    /*
      Capped per input line here too, and it has to be: without it a 200-line paste in
      contains mode joins an unbounded component set against scan_component, which is the
      table this service was written to avoid scanning. The partition is the name key
      rather than the line because this query does not carry line numbers — two entries
      resolving to the same term should share one budget, not two.

      `dense_rank` over the name for the same reason as the rollup: the cap counts packages,
      so every version of a kept package is kept. A flat table that showed 40 of a package's
      50 versions would be a partial answer that looks complete.
    */
    const rankColumn = cap
      ? sql`, dense_rank() OVER (PARTITION BY q.name_key ORDER BY lower(c.name) ASC) AS rn`
      : sql`, 1::bigint AS rn`;
    const capFilter = cap ? sql`WHERE rn <= ${cap}` : sql``;

    const scopeCondition =
      query.scope === "current"
        ? sql`AND u.last_seen_scan_id = a.latest_scan_id`
        : query.scope === "historical"
          ? sql`AND (a.latest_scan_id IS NULL OR u.last_seen_scan_id <> a.latest_scan_id)`
          : sql``;
    const statusCondition = query.includeInactive ? sql`` : sql`AND a.status <> 'inactive'`;

    const rows = await this.deps.db.execute<Row<MatchRow>>(sql`
      WITH q AS (
        -- See the rollup query: sql.param binds each array as one parameter.
        SELECT *
        FROM unnest(
          ${sql.param(names)}::text[],
          ${sql.param(versions)}::text[],
          ${sql.param(ecosystems)}::text[]
        ) AS t(name_key, want_version, want_ecosystem)
      ),
      ranked AS (
        SELECT q.name_key, c.id, c.name, c.version, c.ecosystem, c.purl
          ${rankColumn}
        FROM q
        JOIN component c
          ON ${nameCondition(sql`q.name_key`)}
         AND (q.want_version IS NULL OR c.version = q.want_version)
         AND (q.want_ecosystem IS NULL OR c.ecosystem = q.want_ecosystem)
         AND c.kind = 'library'
      ),
      matched AS (
        -- DISTINCT: two entries can legitimately resolve to the same component
        -- (a bare name and a purl for it), and without this the row appears twice.
        SELECT DISTINCT id, name, version, ecosystem, purl
        FROM ranked ${capFilter}
      ),
      usage AS (
        SELECT DISTINCT ON (sc.component_id, sc.application_id)
               sc.component_id, sc.application_id,
               sc.scan_id AS last_seen_scan_id, sc.created_at AS last_seen_at
        FROM scan_component sc
        WHERE sc.component_id IN (SELECT id FROM matched)
        ORDER BY sc.component_id, sc.application_id, sc.created_at DESC, sc.scan_id DESC
      )
      SELECT
        a.id AS application_id, a.name AS application_name, a.status AS application_status,
        m.id AS component_id, m.name AS component_name, m.version AS component_version,
        m.ecosystem, m.purl,
        (u.last_seen_scan_id = a.latest_scan_id) AS in_latest,
        u.last_seen_scan_id, u.last_seen_at,
        s.build_number AS last_seen_build_number,
        count(*) OVER () AS total
      FROM usage u
      JOIN matched m      ON m.id = u.component_id
      JOIN application a  ON a.id = u.application_id
      JOIN scan s         ON s.id = u.last_seen_scan_id
      WHERE true ${scopeCondition} ${statusCondition}
      ${bulkMatchesOrderBy(query.sortBy, query.sortDir)}
      LIMIT ${query.pageSize} OFFSET ${offsetOf(query)}
    `);

    const resultRows = rowsOf(rows);
    return paginate(resultRows.map(toSearchHit), totalFromRows(resultRows), query);
  }

  /**
   * Every match, unpaginated, for the Excel export.
   *
   * Separate from `matches` because a spreadsheet is the one consumer that wants
   * the whole set — a paginated export would be a file that silently omits rows.
   * Capped so a pathological list cannot exhaust memory building a workbook.
   */
  async allMatches(
    entries: readonly BulkEntry[],
    query: BulkSearchQuery,
    cap: number,
  ): Promise<{ items: ComponentSearchHit[]; truncated: boolean }> {
    const page = await this.matches(entries, { ...query, page: 1, pageSize: cap + 1 });
    return {
      items: page.items.slice(0, cap),
      truncated: page.items.length > cap,
    };
  }

  /** Parses without touching the database, for the export path. */
  parse(input: string) {
    return parseBulkInput(input);
  }
}

function summarise(
  rollup: readonly BulkRollupRow[],
  applicationsAffected: number,
): BulkSearchSummary {
  let found = 0;
  let inCurrentUse = 0;
  for (const row of rollup) {
    if (row.found) found++;
    if (row.currentApplications > 0) inCurrentUse++;
  }
  return {
    found,
    notFound: rollup.length - found,
    inCurrentUse,
    // Comes from the query, not from summing the rows: one application shipping
    // several of the listed packages must count once.
    applicationsAffected,
  };
}

interface RollupRow {
  line: number | string;
  applications_affected: number | string;
  found: boolean | null;
  name_found: boolean | null;
  ecosystems: unknown;
  versions: unknown;
  matched_names: unknown;
  matched_names_truncated: boolean | null;
  current_applications: number | string;
  historical_applications: number | string;
}

interface RecentListRow {
  id: string;
  entry_count: number | string;
  raw_input: string;
  created_at: Date | string;
  last_accessed_at: Date | string;
  email: string | null;
}

interface MatchRow {
  application_id: string;
  application_name: string;
  application_status: "active" | "inactive" | "pending_confirmation";
  component_id: number | string;
  component_name: string;
  component_version: string | null;
  ecosystem: string;
  purl: string | null;
  in_latest: boolean;
  last_seen_scan_id: string;
  last_seen_at: Date | string;
  last_seen_build_number: string | null;
  total?: number | string;
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === "string" && v !== "");
}

function toSearchHit(row: MatchRow): ComponentSearchHit {
  return {
    applicationId: row.application_id,
    applicationName: row.application_name,
    applicationStatus: row.application_status,
    componentId: String(row.component_id),
    componentName: row.component_name,
    componentVersion: row.component_version,
    ecosystem: row.ecosystem,
    purl: row.purl,
    usage: row.in_latest === true ? "current" : "historical",
    lastSeenScanId: row.last_seen_scan_id,
    lastSeenAt: toIso(row.last_seen_at)!,
    lastSeenBuildNumber: row.last_seen_build_number,
  };
}
