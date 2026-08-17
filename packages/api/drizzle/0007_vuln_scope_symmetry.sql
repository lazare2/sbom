ALTER TABLE "scan_vuln_summary" ADD COLUMN "os_fixable" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "scan_vuln_summary" ADD COLUMN "os_known_exploited" integer DEFAULT 0 NOT NULL;--> statement-breakpoint

-- Backfill, rather than waiting for the next sweep to recompute the snapshots.
--
-- The two columns above make the per-scan snapshot symmetric: base image is now a scope a
-- reader can select on its own, and "how much of this is fixed by rebuilding on a newer
-- image" is the first question they will have. It cannot be answered from the severity
-- breakdown.
--
-- The default of 0 is indistinguishable from "no base-image package has a fix available",
-- which is a false and reassuring thing for a dashboard to say. Sweeps only run when the
-- database changes, so leaving these to be filled in later would mean hours of a panel
-- reporting placeholder zeroes with nothing to mark them as such.
--
-- This repeats the aggregate from `refreshScanSummaries` for the two new columns only. It
-- applies suppressions and the ecosystem-based app/base split the same way, so a
-- backfilled row and a freshly swept one agree. The ecosystem list is spelled out here
-- rather than shared with `scope.ts`: a migration has to describe the world as it was when
-- it ran, and pulling in a constant that changes later would silently rewrite history.
WITH os_findings AS (
  SELECT
    vs.scan_id,
    count(*) FILTER (WHERE cv.fix_state = 'fixed')::int AS fixable,
    count(*) FILTER (WHERE v.known_exploited)::int AS known_exploited
  FROM "scan_vuln_summary" vs
  JOIN "scan_component" sc ON sc.scan_id = vs.scan_id
  JOIN "component" c ON c.id = sc.component_id
  JOIN "component_vulnerability" cv ON cv.component_id = c.id
  JOIN "vulnerability" v ON v.id = cv.vulnerability_id
  WHERE (
    c.kind IN ('os', 'runtime')
    OR lower(c.ecosystem) = ANY(ARRAY['deb', 'rpm', 'apk', 'alpm', 'portage', 'nix'])
  )
  AND NOT EXISTS (
    SELECT 1 FROM "vulnerability_suppression" sup
    WHERE sup.vulnerability_id = v.id
      AND (sup.expires_at IS NULL OR sup.expires_at > now())
      AND (sup.component_id IS NULL OR sup.component_id = c.id)
      AND (sup.application_id IS NULL OR sup.application_id = vs.application_id)
  )
  GROUP BY vs.scan_id
)
UPDATE "scan_vuln_summary" vs
SET os_fixable = f.fixable,
    os_known_exploited = f.known_exploited
FROM os_findings f
WHERE f.scan_id = vs.scan_id;
