import { sql } from "drizzle-orm";
import type { VulnSeverity } from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import { planPackages } from "./fix-advisor.js";

/**
 * The one recommended version per package, in one environment.
 *
 * The package page and every project's action plan recommend the same version, so this is the
 * only place it is worked out: the lowest version that clears every advisory with a fix reported
 * against any version of the package in a current build anywhere in the environment, and never
 * below the newest version already shipped there (recommending it would be advising a
 * downgrade). Accepted risks do not lower it: a risk accepted in one project is not a reason to
 * recommend a version that is still affected for the next one.
 *
 * Reads every project in the environment, not only those the reader may open: the answer is a
 * version number, and it has to be the same for everybody who asks.
 */
export interface Recommendation {
  version: string | null;
  /** Advisories with a fix that the version clears. */
  clears: number;
  /** Advisories with no fix anywhere: no version clears these. */
  withoutFix: number;
}

export function packageKey(ecosystem: string, name: string): string {
  return `${ecosystem.toLowerCase()}:${name.toLowerCase()}`;
}

export async function recommendedVersions(
  db: Database,
  environmentId: string,
  packages: ReadonlyArray<{ ecosystem: string; name: string }>,
): Promise<Map<string, Recommendation>> {
  const out = new Map<string, Recommendation>();
  if (packages.length === 0) return out;
  const keys = [...new Set(packages.map((p) => packageKey(p.ecosystem, p.name)))];
  const rows = await db.execute<
    Row<{
      component_id: number | string;
      name: string;
      version: string | null;
      ecosystem: string;
      purl: string | null;
      vulnerability_id: string;
      severity: VulnSeverity;
      known_exploited: boolean;
      fix_state: string;
      fix_versions: string[] | null;
    }>
  >(sql`
    SELECT DISTINCT c.id AS component_id, c.name, c.version, c.ecosystem, c.purl,
           v.id AS vulnerability_id, v.severity, v.known_exploited, cv.fix_state, cv.fix_versions
      FROM application a
      JOIN scan_component sc ON sc.scan_id = a.latest_scan_id
      JOIN component c ON c.id = sc.component_id
      JOIN component_vulnerability cv ON cv.component_id = c.id
      JOIN vulnerability v ON v.id = cv.vulnerability_id
     WHERE a.environment_id = ${environmentId}::uuid
       AND a.status <> 'inactive'
       AND lower(c.ecosystem) || ':' || lower(c.name) = ANY(${sql.param(keys)}::text[])
  `);
  const plans = planPackages(
    rowsOf(rows).map((r) => ({
      componentId: Number(r.component_id),
      name: r.name,
      version: r.version,
      ecosystem: r.ecosystem,
      purl: r.purl,
      origin: "app" as const,
      vulnerabilityId: r.vulnerability_id,
      severity: r.severity,
      knownExploited: r.known_exploited === true,
      fixState: r.fix_state,
      fixVersions: r.fix_versions ?? [],
    })),
  );
  for (const plan of plans) {
    out.set(plan.key, {
      version: plan.minimumVersion,
      clears: plan.resolvedByMinimum,
      withoutFix: plan.advisories.length - plan.resolvedByMinimum,
    });
  }
  return out;
}
