/**
 * When operating systems and language runtimes stop receiving security fixes.
 *
 * Shipped with each release, so it works on a server with no internet: the dates come from the
 * vendors' published schedules (collected via endoflife.date) and are updated with every
 * release. `SUPPORT_LIST_AS_OF` says how current the list is; a product or version that is not
 * listed is shown as unknown, never as supported.
 *
 * For distributions with paid or community extended support (Debian LTS, Ubuntu Pro, RHEL ELS),
 * the date is the end of free security updates for everybody: Debian including LTS, Ubuntu
 * standard support, RHEL maintenance support.
 */

export const SUPPORT_LIST_AS_OF = "2026-11-01";

export interface SupportCycle {
  /** Canonical product: the scan's `os_name` for a distribution, the runtime's name otherwise. */
  product: string;
  /** The release line, matched against the start of the version: "12", "22.04", "3.18". */
  cycle: string;
  /** Last day of security support. */
  endsOn: string;
  label: string;
}

const os = (product: string, label: string, cycles: Array<[string, string]>): SupportCycle[] =>
  cycles.map(([cycle, endsOn]) => ({ product, cycle, endsOn, label: `${label} ${cycle}` }));

export const SUPPORT_CYCLES: readonly SupportCycle[] = [
  ...os("debian", "Debian", [
    ["9", "2022-06-30"],
    ["10", "2024-06-30"],
    ["11", "2026-08-31"],
    ["12", "2028-06-30"],
    ["13", "2030-06-30"],
  ]),
  ...os("ubuntu", "Ubuntu", [
    ["16.04", "2021-04-30"],
    ["18.04", "2023-05-31"],
    ["20.04", "2025-05-31"],
    ["22.04", "2027-06-01"],
    ["23.04", "2024-01-25"],
    ["23.10", "2024-07-11"],
    ["24.04", "2029-05-31"],
    ["24.10", "2025-07-10"],
  ]),
  ...os("alpine", "Alpine Linux", [
    ["3.14", "2023-05-01"],
    ["3.15", "2023-11-01"],
    ["3.16", "2024-05-23"],
    ["3.17", "2024-11-22"],
    ["3.18", "2025-05-09"],
    ["3.19", "2025-11-01"],
    ["3.20", "2026-04-01"],
    ["3.21", "2026-11-01"],
    ["3.22", "2027-05-01"],
  ]),
  ...os("rhel", "Red Hat Enterprise Linux", [
    ["7", "2024-06-30"],
    ["8", "2029-05-31"],
    ["9", "2032-05-31"],
  ]),
  ...os("centos", "CentOS", [
    ["7", "2024-06-30"],
    ["8", "2021-12-31"],
  ]),
  ...os("node", "Node.js", [
    ["14", "2023-04-30"],
    ["16", "2023-09-11"],
    ["18", "2025-04-30"],
    ["19", "2023-06-01"],
    ["20", "2026-04-30"],
    ["21", "2024-06-01"],
    ["22", "2027-04-30"],
    ["23", "2025-06-01"],
    ["24", "2028-04-30"],
  ]),
  ...os("python", "Python", [
    ["3.6", "2021-12-23"],
    ["3.7", "2023-06-27"],
    ["3.8", "2024-10-07"],
    ["3.9", "2025-10-31"],
    ["3.10", "2026-10-31"],
    ["3.11", "2027-10-31"],
    ["3.12", "2028-10-31"],
    ["3.13", "2029-10-31"],
  ]),
];

export interface SupportStatus {
  kind: "os" | "runtime";
  label: string;
  endsOn: string;
  /** Past `endsOn` on the day asked. */
  ended: boolean;
  /** Ends within ENDS_SOON_DAYS. */
  endsSoon: boolean;
}

export const ENDS_SOON_DAYS = 180;

/** The cycle a version belongs to: the longest listed cycle it starts with ("3.18.4" -> "3.18"). */
export function findCycle(product: string, version: string | null | undefined): SupportCycle | null {
  if (!version) return null;
  const p = product.toLowerCase();
  const v = version.trim().replace(/^v/i, "");
  const matches = SUPPORT_CYCLES.filter(
    (c) => c.product === p && (v === c.cycle || v.startsWith(`${c.cycle}.`) || v.startsWith(`${c.cycle}-`)),
  );
  return matches.sort((a, b) => b.cycle.length - a.cycle.length)[0] ?? null;
}

/**
 * Support status of a build's base image and runtimes. Only what is listed: anything else is
 * left out rather than reported as supported.
 */
export function supportStatus(
  platform: { osName: string | null; osVersion: string | null; runtimes?: Array<{ name: string; version: string | null }> } | null,
  today: Date = new Date(),
): SupportStatus[] {
  if (!platform) return [];
  const out: SupportStatus[] = [];
  const add = (kind: SupportStatus["kind"], cycle: SupportCycle | null) => {
    if (!cycle) return;
    const ends = new Date(`${cycle.endsOn}T23:59:59Z`).getTime();
    out.push({
      kind,
      label: cycle.label,
      endsOn: cycle.endsOn,
      ended: ends < today.getTime(),
      endsSoon: ends >= today.getTime() && ends - today.getTime() <= ENDS_SOON_DAYS * 86_400_000,
    });
  };
  if (platform.osName) add("os", findCycle(platform.osName, platform.osVersion));
  for (const r of platform.runtimes ?? []) add("runtime", findCycle(r.name, r.version));
  return out;
}
