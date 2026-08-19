import { sql, type SQL } from "drizzle-orm";
import {
  osPackageEcosystems,
  severitiesForBuckets,
  type DashboardSeverityBucket,
  type VulnScope,
} from "@sbom/shared";

/**
 * The application-dependency vs base-image split, defined once.
 *
 * Every count, ranking, filter and snapshot in this feature derives from these two
 * fragments. They exist as shared expressions rather than being written inline at each
 * site because there are a dozen such sites, and two hand-written copies of a
 * four-clause predicate is how a package ends up counted as a dependency in the ranking
 * and as base image in the detail view.
 *
 * The rule, and why it is not simply `kind = 'library'`:
 *
 *   A real Syft SBOM of a Debian image contains one `operating-system` component (the
 *   distro marker, stored as `kind = 'os'`) and roughly fifteen hundred ordinary
 *   `library` components carrying `pkg:deb/debian/...` purls. Those fifteen hundred are
 *   the base image, and they are `kind = 'library'`. Splitting on `kind` alone would
 *   file all of them as application dependencies — and since base-image packages
 *   outnumber real dependencies by around a hundred to one (measured: 2,817 of 2,845
 *   findings), the "application dependencies" ranking would become a base-image-age
 *   ranking wearing the wrong label. Which is the precise outcome the split exists to
 *   prevent.
 */

/** Expression assumed to be available as `c` (the component table alias). */
export const BASE_IMAGE_PREDICATE: SQL = sql`(
  c.kind IN ('os', 'runtime')
  OR lower(c.ecosystem) = ANY(${sql.param([...osPackageEcosystems])}::text[])
)`;

export const APP_DEPENDENCY_PREDICATE: SQL = sql`NOT ${BASE_IMAGE_PREDICATE}`;

/**
 * `'app'` / `'os'` label for grouping, matching the two predicates above.
 *
 * Used where a query needs to bucket rows rather than filter them, so a GROUP BY and a
 * WHERE in the same file cannot disagree about which side a package falls on.
 */
export const SCOPE_GROUP_EXPR: SQL = sql`CASE WHEN ${BASE_IMAGE_PREDICATE} THEN 'os' ELSE 'app' END`;

/** Filter for the `scope` query parameter. */
export function scopePredicate(scope: VulnScope): SQL {
  if (scope === "app") return APP_DEPENDENCY_PREDICATE;
  if (scope === "os") return BASE_IMAGE_PREDICATE;
  return sql`TRUE`;
}

/**
 * Filter for the dashboard's severity buckets, over `v` (the vulnerability alias).
 *
 * An empty selection means every severity, and returns `TRUE` rather than a six-way `IN`
 * list. That is not only tidier: `TRUE` is what lets the caller recognise an inert filter
 * and take the pre-aggregated snapshot path instead of joining over findings.
 */
export function severityBucketPredicate(buckets: readonly DashboardSeverityBucket[]): SQL {
  if (buckets.length === 0) return sql`TRUE`;
  return sql`v.severity = ANY(${sql.param(severitiesForBuckets(buckets))}::text[])`;
}

/**
 * Suppression exclusion, over `v` (vulnerability), `c` (component) and `a` (application).
 *
 * Lives here rather than beside any one query because it is the rule that decides whether an
 * accepted risk is counted, and it is now asked by three independent readers: the sweep that
 * freezes per-scan summaries, the dashboard's findings-side figures, and a group's distinct
 * advisory count. Two hand-written copies is how a suppressed CVE ends up excluded from one
 * panel and included in the one beside it — which reads as a bug in the suppression feature
 * rather than in the query, and sends whoever investigates to the wrong file.
 *
 * Nullable columns widen the scope rather than narrow it: both ids null suppresses estate-
 * wide, `component_id` limits it to one package version, `application_id` to one application.
 */
export const NOT_SUPPRESSED: SQL = sql`NOT EXISTS (
  SELECT 1 FROM vulnerability_suppression sup
  WHERE sup.vulnerability_id = v.id
    AND (sup.expires_at IS NULL OR sup.expires_at > now())
    AND (sup.component_id IS NULL OR sup.component_id = c.id)
    AND (sup.application_id IS NULL OR sup.application_id = a.id)
)`;

/**
 * Restricts an aggregate to the applications in one group, over the `application` alias given.
 *
 * `TRUE` for no group, which is the same trick `severityBucketPredicate` uses: an inert filter
 * that is still a valid expression means every call site interpolates it unconditionally, and
 * a site that forgot to is a compile error rather than a silently unscoped figure.
 *
 * EXISTS rather than a join, at every site, for a reason that bites specifically here. Several
 * of these queries carry `count(*) OVER ()` for pagination or aggregate over `scan_component`;
 * joining the membership table would multiply each application row by its group count and
 * inflate both. Membership is also indexed from the application side
 * (`application_group_member_application_idx`), so the EXISTS is a lookup rather than a scan.
 *
 * The alias is passed because these queries do not agree on one — the analytics estate query
 * self-joins as `a2` — and hardcoding `a` would produce a predicate that silently referenced
 * the wrong row.
 */
export function groupMemberPredicate(groupId: string | null | undefined, alias = "a"): SQL {
  if (!groupId) return sql`TRUE`;
  return sql`EXISTS (
    SELECT 1 FROM application_group_member gm
    WHERE gm.application_id = ${sql.raw(alias)}.id AND gm.group_id = ${groupId}::uuid
  )`;
}
