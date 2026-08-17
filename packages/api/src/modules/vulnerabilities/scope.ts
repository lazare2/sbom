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
