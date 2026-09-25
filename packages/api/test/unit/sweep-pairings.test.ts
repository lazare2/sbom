import { describe, expect, it } from "vitest";
import { collapsePairings } from "../../src/modules/vulnerabilities/sweep.service.js";
import { toFindings, type XrayMapping } from "../../src/services/scanner/xray-findings.js";
import type { ParsedFinding } from "../../src/services/scanner/grype-output.js";
import type { XrayVulnerability } from "../../src/services/scanner/xray-client.js";

/**
 * What the sweep is allowed to hand to one `INSERT ... ON CONFLICT` statement.
 *
 * The pairing upsert conflicts on `(component_id, vulnerability_id)`, and Postgres rejects
 * a statement whose VALUES list proposes that pair twice -- SQLSTATE 21000. It rejects the
 * *whole statement*, so a single duplicate loses the batch and aborts the sweep.
 *
 * The failure that matters is the silent one. An aborted sweep stamps no component, so the
 * previous provider's findings stay on every dashboard and the estate reads as though
 * nothing had changed. That is exactly how this reached a running deployment: switching to
 * Xray appeared to do nothing at all, rather than to fail.
 *
 * Uniqueness in the table is enforced by the primary key, not here. This decides only what
 * is safe to put in one statement.
 */

const finding = (over: Partial<ParsedFinding> = {}): ParsedFinding => ({
  componentId: 101,
  vulnerabilityId: "CVE-2021-44228",
  severity: "critical",
  aliases: [],
  cvssBaseScore: 10,
  cvssVector: null,
  epssScore: null,
  epssPercentile: null,
  knownExploited: false,
  description: null,
  dataSource: "jfrog-xray",
  namespace: "maven",
  urls: [],
  fixState: "unknown",
  fixVersions: [],
  matchType: "xray-graph",
  ...over,
});

describe("collapsing findings onto the pairing conflict target", () => {
  it("collapses two records of the same component and advisory into one", () => {
    const collapsed = collapsePairings([finding(), finding()]);
    expect(collapsed).toHaveLength(1);
  });

  it("keeps pairs that differ in either half", () => {
    // Over-collapsing would silently drop real findings, which is the opposite failure and
    // just as invisible on a dashboard.
    const collapsed = collapsePairings([
      finding({ componentId: 101, vulnerabilityId: "CVE-2021-44228" }),
      finding({ componentId: 202, vulnerabilityId: "CVE-2021-44228" }),
      finding({ componentId: 101, vulnerabilityId: "CVE-2021-45046" }),
    ]);
    expect(collapsed).toHaveLength(3);
  });

  it("keeps the copy that names a fix, whichever order it arrives in", () => {
    const withFix = finding({ fixState: "fixed", fixVersions: ["2.15.0"] });
    const withoutFix = finding();

    for (const order of [
      [withFix, withoutFix],
      [withoutFix, withFix],
    ]) {
      const collapsed = collapsePairings(order);
      expect(collapsed).toHaveLength(1);
      expect(collapsed[0]!.fixVersions).toEqual(["2.15.0"]);
      expect(collapsed[0]!.fixState).toBe("fixed");
    }
  });

  it("prefers the record naming more fixed versions", () => {
    const collapsed = collapsePairings([
      finding({ fixState: "fixed", fixVersions: ["2.15.0"] }),
      finding({ fixState: "fixed", fixVersions: ["2.15.0", "2.12.2"] }),
    ]);
    expect(collapsed[0]!.fixVersions).toEqual(["2.15.0", "2.12.2"]);
  });
});

/*
  The reason the collapse exists, pinned against the mapper that produces the duplicates.

  Xray reports per *issue*, not per advisory. One CVE is routinely carried by more than one
  issue record -- the OSS advisory and JFrog's own research entry, say -- and both name the
  same component. Identity resolves both to the CVE, so both become the same pair.
*/
const COORDINATE = "gav://org.apache.logging.log4j:log4j-core:2.14.1";

const mapping: XrayMapping = { byCoordinate: new Map([[COORDINATE, [101]]]) };

const OSS_ISSUE: XrayVulnerability = {
  issue_id: "XRAY-192503",
  summary: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
  severity: "Critical",
  cves: [{ cve: "CVE-2021-44228", cvss_v3_score: "10.0", cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }],
  components: { [COORDINATE]: { fixed_versions: ["[2.15.0]"], package_type: "maven" } },
  references: ["https://logging.apache.org/log4j/2.x/security.html"],
};

// The same CVE under a second issue id, which is what a real response looks like. This one
// states no fixed version, so it must not be the copy that survives.
const RESEARCH_ISSUE: XrayVulnerability = {
  issue_id: "XRAY-533585",
  summary: "Log4Shell remote code execution.",
  severity: "Critical",
  cves: [{ cve: "CVE-2021-44228", cvss_v3_score: "10.0", cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }],
  components: { [COORDINATE]: { fixed_versions: [], package_type: "maven" } },
  references: [],
};

describe("against what the Xray mapper actually emits", () => {
  it("really does produce the duplicate pair, so the collapse is load-bearing", () => {
    const { findings } = toFindings([OSS_ISSUE, RESEARCH_ISSUE], mapping);

    // Asserted rather than assumed: if the mapper ever stopped emitting duplicates, the
    // tests above would still pass while protecting nothing, and this states the premise.
    expect(findings.length).toBeGreaterThan(1);
    const pairs = findings.map((f) => `${f.componentId}:${f.vulnerabilityId}`);
    expect(new Set(pairs).size).toBeLessThan(pairs.length);
  });

  it("yields one pairing, still carrying the fix, once collapsed", () => {
    const { findings } = toFindings([OSS_ISSUE, RESEARCH_ISSUE], mapping);
    const collapsed = collapsePairings(findings);

    expect(collapsed).toHaveLength(1);
    expect(collapsed[0]!.vulnerabilityId).toBe("CVE-2021-44228");
    expect(collapsed[0]!.fixVersions).toEqual(["[2.15.0]"]);
  });
});
