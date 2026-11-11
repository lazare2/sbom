import { z } from "zod";
import type { EcosystemBreakdownEntry } from "./admin.js";
import type { FragmentationEntry, TopProjectEntry } from "./analytics.js";

// ---------------------------------------------------------------------------
// Team filter - shared by Inventory and Analytics
// ---------------------------------------------------------------------------

const teamName = z.string().trim().min(1).max(200);

/** One value or several, as a repeated query parameter arrives. */
function names() {
  return z
    .union([teamName, z.array(teamName).max(200)])
    .optional()
    .transform((v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]));
}

/**
 * Narrowing an estate-level page to some squads, tribes or groups.
 *
 * Named rather than referenced by id, matched case-insensitively, exactly like the advisory
 * list's filter: the URL of a filtered view stays readable when pasted into a ticket. A squad or
 * tribe means a direct assignment. Several values within one kind are alternatives (squad A or
 * squad B); different kinds narrow together (squad A and tribe X).
 *
 * This only ever narrows. The reader's own access is applied first and unconditionally, so
 * naming a squad whose applications the reader cannot see yields nothing rather than more.
 */
export const teamFilterSchema = z.object({
  squad: names(),
  tribe: names(),
  group: names(),
});
export type TeamFilter = z.infer<typeof teamFilterSchema>;

export const EMPTY_TEAM_FILTER: TeamFilter = { squad: [], tribe: [], group: [] };

export function teamFilterActive(filter: TeamFilter): boolean {
  return filter.squad.length + filter.tribe.length + filter.group.length > 0;
}

/** A short human label for a filter, for page headers and the PDF cover. Null when inactive. */
export function teamFilterLabel(filter: TeamFilter): string | null {
  const parts: string[] = [];
  if (filter.squad.length > 0) parts.push(`squad ${filter.squad.join(" or ")}`);
  if (filter.tribe.length > 0) parts.push(`tribe ${filter.tribe.join(" or ")}`);
  if (filter.group.length > 0) parts.push(`group ${filter.group.join(" or ")}`);
  return parts.length > 0 ? parts.join(", ") : null;
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

export const inventoryQuerySchema = teamFilterSchema.extend({
  /** Rows per ranked table. */
  limit: z.coerce.number().int().min(1).max(200).default(25),
});
export type InventoryQuery = z.infer<typeof inventoryQuerySchema>;

/**
 * What the vulnerability database says about a package's versions in current builds.
 * Distinct advisories, accepted risks excluded - the same rules as package search.
 */
export interface InventoryPackageVulns {
  /** False when no version in use has been matched yet: the zeros below would be unchecked. */
  assessed: boolean;
  advisories: number;
  critical: number;
  high: number;
  knownExploited: number;
  /** Advisories with a fixed version available. */
  fixable: number;
  /** Applications shipping a version with at least one advisory. */
  vulnerableApplications: number;
}

/** One application dependency (never a base-image package) across current builds. */
export interface InventoryPackageEntry {
  name: string;
  ecosystem: string;
  applications: number;
  /** Capped at EXPANDABLE_LIST_CAP; produced by the same aggregate as `applications`. */
  applicationList: string[];
  versions: number;
  versionSample: string[];
  /** Null with scanning switched off. */
  vulnerabilities: InventoryPackageVulns | null;
}

/**
 * Base-image findings for the applications on one distribution.
 *
 * Read from each application's frozen per-build summary - the same figures the overview and the
 * application pages show - so nothing here can disagree with them. Findings are package and
 * advisory pairs per application, which is why an average per application is the comparable
 * figure across distributions with very different numbers of applications.
 */
export interface InventoryOsVulns {
  /** Applications on this distribution whose current build has been matched. */
  assessedApplications: number;
  findings: number;
  critical: number;
  high: number;
  fixable: number;
  knownExploited: number;
  /** findings / assessedApplications, one decimal. Null when none is assessed. */
  averageFindings: number | null;
  averageCritical: number | null;
  averageHigh: number | null;
}

export interface InventoryOsEntry {
  /** Distro id as reported, e.g. `debian`. */
  name: string;
  version: string | null;
  /** The distro's own pretty name, e.g. `Debian GNU/Linux 12 (bookworm)`, when reported. */
  pretty: string | null;
  applications: number;
  applicationList: string[];
  /** Null with scanning switched off, or when the active database cannot assess OS packages. */
  vulnerabilities: InventoryOsVulns | null;
}

export interface InventoryRuntimeEntry {
  name: string;
  version: string | null;
  applications: number;
  applicationList: string[];
}

export interface InventoryReport {
  generatedAt: string;
  environmentId: string;
  environmentName: string;
  filter: TeamFilter;
  /** `teamFilterLabel(filter)`, carried so every rendering states the same thing. */
  filterLabel: string | null;
  vulnScanningEnabled: boolean;
  totals: {
    /** Active or unconfirmed applications with a current build, in the filtered population. */
    applications: number;
    /** Distinct application dependencies (name within ecosystem) in current builds. */
    packages: number;
    /** Distinct distribution + version pairs. */
    operatingSystems: number;
    /** Distinct runtime + version pairs. */
    runtimes: number;
    /** Applications with neither an OS nor a runtime detected. */
    unknownPlatform: number;
  };
  /** Application dependencies in the most applications. */
  mostUsedPackages: InventoryPackageEntry[];
  /** Application dependencies with the most critical, then high, advisories in current use. */
  mostVulnerablePackages: InventoryPackageEntry[];
  operatingSystems: InventoryOsEntry[];
  runtimes: InventoryRuntimeEntry[];
  ecosystems: EcosystemBreakdownEntry[];
  fragmentation: FragmentationEntry[];
  /** Applications with the most packages in their current build. A size ranking, not a risk one. */
  largestApplications: TopProjectEntry[];
}
