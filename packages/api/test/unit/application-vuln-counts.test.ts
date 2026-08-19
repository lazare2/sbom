import { describe, expect, it } from "vitest";
import { toVulnCounts } from "../../src/modules/applications/applications.service.js";

/**
 * The applications list reports findings per application, and the only failure that matters
 * here is silent: an unassessed application rendered as `0`.
 *
 * Zero means "matched against the database and nothing was found" — a clean bill of health. An
 * application whose scan predates the feature being switched on, or which is waiting for the
 * next sweep, has no summary row at all, and every path that turns that absence into a number
 * makes a claim the platform never checked. There is no error, no empty state, and nothing on
 * screen to suggest the figure is not real, which is why it is pinned here rather than left to
 * a reviewer to notice.
 */

/** A summary row as the driver returns it: integers arrive as strings on these columns. */
function summaryRow(over: Record<string, number | string | null> = {}) {
  return {
    app_findings: "12",
    os_findings: "2817",
    app_critical: "3",
    os_critical: "40",
    app_high: "5",
    os_high: "200",
    ...over,
  };
}

/** The shape of a LEFT JOIN that matched nothing. */
const NO_SUMMARY = {
  app_findings: null,
  os_findings: null,
  app_critical: null,
  os_critical: null,
  app_high: null,
  os_high: null,
};

describe("application vulnerability counts", () => {
  it("totals both halves and keeps each one separately", () => {
    const counts = toVulnCounts(summaryRow(), true);

    expect(counts).toEqual({
      total: 2829,
      app: 12,
      os: 2817,
      // Spanning both halves, matching the total. A critical in the base image is still a
      // critical; which half it came from is what app and os are for.
      critical: 43,
      high: 205,
    });
  });

  it("reports null, not zero, when the build has not been matched yet", () => {
    // The state of every scan ingested before scanning was switched on.
    expect(toVulnCounts(NO_SUMMARY, true)).toBeNull();
  });

  it("reports null, not zero, while scanning is switched off", () => {
    // Summary rows survive the feature being disabled. Serving them anyway would present
    // counts from a database of unknown age as the current position.
    expect(toVulnCounts(summaryRow(), false)).toBeNull();
  });

  it("reports a genuine zero as zero", () => {
    // The one case that is allowed to be zero, and it has to remain distinguishable from the
    // two nulls above — this is the whole point of the type being nullable.
    const counts = toVulnCounts(
      summaryRow({
        app_findings: "0",
        os_findings: "0",
        app_critical: "0",
        os_critical: "0",
        app_high: "0",
        os_high: "0",
      }),
      true,
    );

    expect(counts).not.toBeNull();
    expect(counts).toMatchObject({ total: 0, app: 0, os: 0 });
  });

  it("treats a missing base-image half as zero rather than discarding the row", () => {
    // An SBOM with no OS packages at all — a scratch or distroless image — is a real estate,
    // not missing data. The application half decides whether the row exists.
    const counts = toVulnCounts(
      summaryRow({ os_findings: null, os_critical: null, os_high: null }),
      true,
    );

    expect(counts).toMatchObject({ total: 12, app: 12, os: 0, critical: 3, high: 5 });
  });

  it("accepts counts as numbers as well as strings", () => {
    // Which of the two the driver produces depends on the column type, and a Number() that
    // was dropped would concatenate instead of adding: "12" + "2817" is 122817.
    const counts = toVulnCounts(
      { app_findings: 12, os_findings: 2817, app_critical: 3, os_critical: 40, app_high: 5, os_high: 200 },
      true,
    );

    expect(counts?.total).toBe(2829);
  });
});
