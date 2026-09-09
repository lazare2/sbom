import { describe, expect, it } from "vitest";
import { toFindings, type XrayMapping } from "../../src/services/scanner/xray-findings.js";
import type { XrayVulnerability } from "../../src/services/scanner/xray-client.js";

/**
 * Translating an Xray graph-scan result into this platform's findings.
 *
 * The shape is fixed by what downstream already expects: the sweep, the frozen per-scan
 * summaries and every dashboard figure are written against `ParsedFinding` and must not be
 * able to tell which provider produced one. So the tests below are mostly about the places
 * where Xray's answer and Grype's answer differ in kind rather than in content — identity,
 * fix state, and the two fields Xray simply does not publish.
 *
 * The fixture is shaped like a real response: the Log4Shell issue that the original manual
 * investigation used to prove the database was live, with the multiple CVEs that issue
 * genuinely carries.
 */

const mapping: XrayMapping = {
  byCoordinate: new Map([
    ["gav://org.apache.logging.log4j:log4j-core:2.14.1", [101]],
    ["npm://lodash:4.17.15", [202]],
  ]),
};

const LOG4SHELL: XrayVulnerability = {
  issue_id: "XRAY-192503",
  summary: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
  severity: "Critical",
  cves: [
    { cve: "CVE-2021-45046", cvss_v3_score: 9, cvss_v3_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H" },
    { cve: "CVE-2021-44228", cvss_v3_score: "10.0", cvss_v3_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" },
  ],
  components: {
    "gav://org.apache.logging.log4j:log4j-core:2.14.1": {
      fixed_versions: ["[2.15.0]", "[2.12.2]"],
      package_type: "maven",
    },
  },
  references: ["https://logging.apache.org/log4j/2.x/security.html"],
};

describe("mapping an Xray scan onto findings", () => {
  it("keys the advisory on a CVE and keeps the Xray id as an alias", () => {
    /*
      A CVE is what a reader recognises and searches for. XRAY-192503 is meaningful only
      inside JFrog, so keying on it would make this advisory unrecognisable against anything
      else the platform stores — and against the same advisory seen under Grype.
    */
    const { findings } = toFindings([LOG4SHELL], mapping);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.vulnerabilityId).toBe("CVE-2021-44228");
    expect(findings[0]!.aliases).toContain("CVE-2021-45046");
    expect(findings[0]!.aliases).toContain("XRAY-192503");
  });

  it("picks the same CVE every run when an issue carries several", () => {
    // Chosen by sort rather than by response order. Xray is under no obligation to return
    // them in a stable order, and an advisory whose primary id changed between sweeps would
    // read as resolved-and-reintroduced in the monthly report.
    const reordered: XrayVulnerability = { ...LOG4SHELL, cves: [...LOG4SHELL.cves!].reverse() };
    const first = toFindings([LOG4SHELL], mapping).findings[0]!;
    const second = toFindings([reordered], mapping).findings[0]!;
    expect(first.vulnerabilityId).toBe(second.vulnerabilityId);
  });

  it("takes the highest CVSS v3 score and its vector together", () => {
    const { findings } = toFindings([LOG4SHELL], mapping);
    expect(findings[0]!.cvssBaseScore).toBe(10);
    // The vector has to belong to the score it is shown beside, or the page displays a 10.0
    // next to the vector of a 9.0 and neither figure can be checked against the other.
    expect(findings[0]!.cvssVector).toContain("AC:L");
  });

  it("does not claim EPSS or known-exploited data that Xray never sent", () => {
    // Grype supplies both. Xray publishes neither, and a zero EPSS or a `true` here would be
    // an assertion about the advisory rather than the absence of an answer.
    const { findings } = toFindings([LOG4SHELL], mapping);
    expect(findings[0]!.epssScore).toBeNull();
    expect(findings[0]!.epssPercentile).toBeNull();
    expect(findings[0]!.knownExploited).toBe(false);
  });

  it("treats no fix versions as unknown rather than as not-fixed", () => {
    /*
      Xray reports the versions that fix an issue, not a fix *state*. An empty list means
      Xray knows of no fix — which is not the same claim as "the maintainers will not fix
      this", and the two differ by whether anybody looked.
    */
    const noFix: XrayVulnerability = {
      ...LOG4SHELL,
      components: { "npm://lodash:4.17.15": { fixed_versions: [] } },
    };
    const { findings } = toFindings([noFix], mapping);
    expect(findings[0]!.fixState).toBe("unknown");
    expect(findings[0]!.fixVersions).toEqual([]);
  });

  it("maps Xray's severity ladder onto this platform's", () => {
    const severities = ["Critical", "High", "Medium", "Low", "Information", "Unknown", "nonsense"];
    const mapped = severities.map(
      (severity) =>
        toFindings([{ ...LOG4SHELL, severity }], mapping).findings[0]!.severity,
    );
    // `Information` is a rating and becomes negligible; `Unknown` is the absence of one and
    // stays unknown. Promoting either to `low` would overstate what the feed said.
    expect(mapped).toEqual([
      "critical",
      "high",
      "medium",
      "low",
      "negligible",
      "unknown",
      "unknown",
    ]);
  });

  it("reaches every component that produced the same coordinate", () => {
    /*
      One-to-many on purpose. The same package recorded once with a distro qualifier and once
      without has two identity hashes and one Xray coordinate; a finding that reached only the
      first would leave the second reading as clean.
    */
    const shared: XrayMapping = {
      byCoordinate: new Map([["npm://lodash:4.17.15", [1, 2, 3]]]),
    };
    const { findings } = toFindings(
      [{ ...LOG4SHELL, components: { "npm://lodash:4.17.15": {} } }],
      shared,
    );
    expect(findings.map((f) => f.componentId).sort()).toEqual([1, 2, 3]);
  });

  it("counts references it never submitted rather than discarding them quietly", () => {
    // Should always be zero. A non-zero value means the coordinate written on the way out is
    // not the one that came back, and every finding for those packages is being dropped.
    const { findings, unmatchedReferences } = toFindings(
      [{ ...LOG4SHELL, components: { "npm://never-sent:1.0.0": {} } }],
      mapping,
    );
    expect(findings).toEqual([]);
    expect(unmatchedReferences).toBe(1);
  });

  it("drops an issue with no identity rather than inventing one", () => {
    /*
      A finding keyed on a generated id would be a brand-new advisory on every sweep, and the
      "introduced since the last report" figure sent to management would grow forever.
    */
    const anonymous: XrayVulnerability = {
      severity: "High",
      components: { "npm://lodash:4.17.15": {} },
    };
    const { findings, unidentified } = toFindings([anonymous], mapping);
    expect(findings).toEqual([]);
    expect(unidentified).toBe(1);
  });

  it("survives a response with nothing in it", () => {
    // A clean scan and a broken one must be distinguishable by the caller, not by a crash
    // here. This returns empty; whether that means "clean" is the sweep's decision.
    expect(toFindings([], mapping)).toEqual({
      findings: [],
      unmatchedReferences: 0,
      unidentified: 0,
    });
  });
});
