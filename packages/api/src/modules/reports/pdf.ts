import PDFDocument from "pdfkit";
import {
  bucketize,
  INERT_VULN_FILTER,
  dashboardSeverityBuckets,
  SEVERITY_BUCKET_LABELS,
  totalOf,
  type AnalyticsReport,
  type DashboardSeverityBucket,
} from "@sbom/shared";
import { osLabel, runtimeLabel } from "../ingestion/platform.js";
import {
  CONTENT_WIDTH,
  COLOR,
  Layout,
  MARGIN,
  PAGE,
  fit,
  fmt,
  fmtDate,
  fmtDateTime,
  stampFooters,
  statRow,
  table,
  type Column,
  type Doc,
} from "./pdf-layout.js";

export interface RenderReportOptions {
  /** Shown in the footer next to the page number. */
  title?: string;
}



/**
 * Renders the estate report as a PDF.
 *
 * Server-side with pdfkit rather than HTML-to-PDF through a headless browser.
 * The output is vector text in a ~50 KB file, the API image stays free of a
 * 300 MB Chromium, and `GET /reports/estate.pdf` is a plain curl-able URL — so a
 * scheduled job can archive a monthly snapshot with no client involved. The cost
 * is that layout is manual, which is why the helpers below exist.
 *
 * Only the standard-14 fonts are used, so no font files ship with the build.
 * Those cover Latin-1; a package name in Cyrillic or CJK would render as
 * substituted glyphs. Package names are ASCII in every ecosystem the platform
 * ingests, and the alternative — embedding a full Unicode TTF — costs several
 * megabytes on every single report for a case that has not occurred.
 */

/**
 * Builds the PDF and resolves with the complete buffer.
 *
 * Buffered rather than streamed straight to the reply: the whole document is
 * tens of kilobytes, and having it in hand means a rendering failure becomes a
 * clean 500 instead of a truncated file that a CI job would happily archive as
 * a valid report.
 */
export async function renderReportPdf(
  report: AnalyticsReport,
  options: RenderReportOptions = {},
): Promise<Buffer> {
  const title = options.title ?? "SBOM estate report";

  const doc = new PDFDocument({
    size: [PAGE.width, PAGE.height],
    margin: MARGIN,
    // Surfaces in the PDF viewer's title bar and document properties, which is
    // what a reader sees when the file has been renamed by whoever forwarded it.
    info: {
      Title: title,
      Author: "SBOM Platform",
      Subject: `Dependency inventory report, ${report.meta.periodDays}-day window`,
      CreationDate: new Date(report.meta.generatedAt),
    },
    // pdfkit's automatic page breaks would fire mid-table and mid-heading; every
    // break in this document is placed deliberately by `ensureSpace`.
    autoFirstPage: true,
    bufferPages: true,
  });

  const chunks: Buffer[] = [];
  doc.on("data", (chunk: Buffer) => chunks.push(chunk));
  const finished = new Promise<Buffer>((resolve, reject) => {
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);
  });

  const ctx = new Layout(doc);

  coverBlock(ctx, report);
  // Immediately after the cover, ahead of the inventory sections: when a reader opens
  // this file to answer one question, it is almost always this one.
  vulnerabilitySection(ctx, report);
  coverageSection(ctx, report);
  topPackagesSection(ctx, report);
  topProjectsSection(ctx, report);
  fragmentationSection(ctx, report);
  velocitySection(ctx, report);
  newPackagesSection(ctx, report);
  platformSection(ctx, report);
  ecosystemSection(ctx, report);
  methodologySection(ctx, report);

  // Footers last: the page count is only known once the content is laid out.
  stampFooters(doc, title, report.meta.generatedAt);

  doc.end();
  return finished;
}

// ---------------------------------------------------------------------------
// sections
// ---------------------------------------------------------------------------

function coverBlock(ctx: Layout, report: AnalyticsReport): void {
  const { doc } = ctx;
  const { meta, totals, coverage } = report;

  doc.y = MARGIN;

  doc
    .font("Helvetica-Bold")
    .fontSize(20)
    .fillColor(COLOR.text)
    .text("SBOM estate report", MARGIN, doc.y, { width: CONTENT_WIDTH });

  ctx.gap(2);
  doc
    .font("Helvetica")
    .fontSize(9)
    .fillColor(COLOR.muted)
    .text(
      `Generated ${fmtDateTime(meta.generatedAt)}` +
        (meta.generatedBy ? ` by ${meta.generatedBy}` : "") +
        ` · ${meta.periodDays}-day window from ${fmtDate(meta.periodStart)}`,
      MARGIN,
      doc.y,
      { width: CONTENT_WIDTH },
    );

  /*
   * The vulnerability filter, on the cover.
   *
   * A filtered report is forwarded and quoted like any other, so the fact that it is
   * filtered has to survive being read by someone who never saw the screen it came from.
   * The first page is the only place that reliably gets read, which is why this is here
   * as well as beside the figures themselves.
   */
  if (report.vulnerabilities?.filter?.active) {
    ctx.gap(6);
    doc
      .font("Helvetica-Bold")
      .fontSize(9)
      .fillColor(COLOR.warn)
      .text(
        `Vulnerability figures filtered: ${report.vulnerabilities.filter.label ?? ""}`,
        MARGIN,
        doc.y,
        { width: CONTENT_WIDTH },
      );
    ctx.gap(1);
    doc
      .font("Helvetica")
      .fontSize(8)
      .fillColor(COLOR.muted)
      .text(
        "Inventory, coverage and churn figures are unfiltered and describe the whole estate. Unfiltered vulnerability totals are printed alongside the filtered ones.",
        MARGIN,
        doc.y,
        { width: CONTENT_WIDTH },
      );
  }

  ctx.gap(10);
  ctx.rule();
  ctx.gap(12);

  statRow(ctx, [
    { label: "Applications", value: fmt(totals.applications), note: `${fmt(totals.activeApplications)} active` },
    { label: "Packages in use", value: fmt(totals.packagesInUse), note: `${fmt(totals.distinctPackages)} all-time` },
    { label: "Scans received", value: fmt(totals.scans), note: `${fmt(totals.scansInPeriod)} in window` },
    {
      label: "Scan coverage",
      value: `${coverage.coveragePct}%`,
      note: `${fmt(coverage.covered)}/${fmt(coverage.eligible)} active apps`,
      tone: coverage.coveragePct >= 90 ? "ok" : "warn",
    },
  ]);

  statRow(ctx, [
    {
      label: "Stale",
      value: fmt(coverage.stale),
      note: `no build in ${meta.staleThresholdDays} days`,
      tone: coverage.stale > 0 ? "warn" : "ok",
    },
    {
      label: "Never scanned",
      value: fmt(coverage.neverScanned),
      note: "registered, no SBOM",
      tone: coverage.neverScanned > 0 ? "warn" : "ok",
    },
    {
      label: "Unconfirmed",
      value: fmt(coverage.pendingConfirmation),
      note: "awaiting admin triage",
      tone: coverage.pendingConfirmation > 0 ? "warn" : "ok",
    },
    { label: "Last scan", value: fmtDate(totals.latestScanAt), note: "most recent build seen" },
  ]);

  /**
   * The qualifier on everything above.
   *
   * Deliberately on page one and not in an appendix: totals over an inventory
   * with gaps get quoted as if the gaps were not there, and by the time someone
   * reaches a methodology note at the back they have already written the number
   * into a slide.
   */
  ctx.gap(2);
  const caveat =
    coverage.coveragePct >= 100 && coverage.neverScanned === 0
      ? `Every active application has reported a build within ${meta.staleThresholdDays} days, so the figures below describe the whole estate.`
      : `Figures below describe only what has been scanned. ${fmt(coverage.stale)} active application${
          coverage.stale === 1 ? " has" : "s have"
        } not reported a build in ${meta.staleThresholdDays} days and ${fmt(coverage.neverScanned)} ${
          coverage.neverScanned === 1 ? "has" : "have"
        } never reported one; their dependencies are absent from every count in this report.`;
  ctx.paragraph(caveat, { color: coverage.coveragePct >= 100 ? COLOR.muted : COLOR.warn, size: 8.5 });
  ctx.gap(14);
}

function coverageSection(ctx: Layout, report: AnalyticsReport): void {
  const rows = report.coverage.worstOffenders;
  ctx.heading(
    "Coverage gaps",
    "Active applications the inventory cannot currently see, longest-silent first. Never-scanned applications sort above stale ones.",
  );

  if (rows.length === 0) {
    ctx.emptyNote("No active application is stale or unscanned.");
    ctx.gap(10);
    return;
  }

  table(
    ctx,
    [
      { header: "#", width: 0.05, align: "right", value: (_r, i) => String(i + 1) },
      { header: "Application", width: 0.5, value: (r) => r.name },
      { header: "Last build", width: 0.25, value: (r) => fmtDate(r.lastScanAt), mono: true },
      {
        header: "Silent for",
        width: 0.2,
        align: "right",
        value: (r) => (r.daysSinceScan === null ? "never scanned" : `${fmt(r.daysSinceScan)} days`),
      },
    ],
    rows,
  );
}

/**
 * One row of the app/base-image breakdown table.
 *
 * Shared by the filtered figures and the unfiltered reference block so the two cannot be
 * laid out differently — a reader comparing them is comparing rows, and rows that do not
 * line up make that comparison work rather than a glance.
 */
interface BreakdownRow {
  label: string;
  total: number;
  buckets: Record<DashboardSeverityBucket, number>;
  /** Null where the figure is not available for that block, printed as a dash. */
  fixable: number | null;
  knownExploited: number | null;
  packages: number | null;
}

/**
 * Abbreviated headers for the breakdown table.
 *
 * Nine columns on a 507pt content width leaves about 40pt each, and `MEDIUM` does not fit
 * — `truncate()` would silently clip it, printing a header that is not the word it means.
 * Matches the `Crit` / `High` abbreviations the ranking tables already use.
 */
const BUCKET_HEADER: Record<DashboardSeverityBucket, string> = {
  critical: "Crit",
  high: "High",
  medium: "Med",
  low: "Low",
  other: "Other",
};

function breakdownTable(ctx: Layout, rows: BreakdownRow[], options: { detail: boolean }): void {
  const severityColumns = dashboardSeverityBuckets.map((bucket) => ({
    header: BUCKET_HEADER[bucket],
    width: options.detail ? 0.08 : 0.11,
    align: "right" as const,
    value: (r: BreakdownRow) => fmt(r.buckets[bucket]),
  }));

  table(
    ctx,
    [
      { header: "Scope", width: options.detail ? 0.25 : 0.3, value: (r: BreakdownRow) => r.label },
      {
        header: "Total",
        width: options.detail ? 0.09 : 0.15,
        align: "right" as const,
        value: (r: BreakdownRow) => fmt(r.total),
      },
      ...severityColumns,
      ...(options.detail
        ? [
            {
              header: "Fixable",
              width: 0.09,
              align: "right" as const,
              value: (r: BreakdownRow) => (r.fixable === null ? "—" : fmt(r.fixable)),
            },
            {
              header: "Exploit",
              width: 0.09,
              align: "right" as const,
              value: (r: BreakdownRow) => (r.knownExploited === null ? "—" : fmt(r.knownExploited)),
            },
            {
              header: "Pkgs",
              width: 0.08,
              align: "right" as const,
              value: (r: BreakdownRow) => (r.packages === null ? "—" : fmt(r.packages)),
            },
          ]
        : []),
    ],
    rows,
  );
}

/**
 * Vulnerability findings, or an explicit statement that nothing was assessed.
 *
 * The disabled branch is the important one. A printed report is forwarded, renamed and
 * quoted months later, so a page that silently omitted this section — or worse, showed
 * zeros — would be read as a clean bill of health for an estate nobody ever scanned.
 * It says so in as many words instead.
 *
 * When a filter is active the same concern applies one level down, which is why this
 * section names the filter before printing any figure and then prints the unfiltered
 * totals underneath. A filtered report that circulates without its filter stated is read
 * as the whole picture, and the reader has no way to discover what was left out.
 */
function vulnerabilitySection(ctx: Layout, report: AnalyticsReport): void {
  const vuln = report.vulnerabilities;

  /*
   * `== null`, not `=== null`: the field is typed as nullable, but a payload that
   * predates it — a cached response, or a partially-built object — arrives with the
   * key absent. Treating undefined as 'not assessed' is both correct and the safe
   * direction to fail, since the alternative is a crash mid-render.
   */
  if (vuln == null) {
    ctx.heading(
      "Vulnerability findings",
      "Not assessed. Vulnerability scanning is disabled on this platform, so no package in this report has been matched against a vulnerability database.",
    );
    ctx.emptyNote(
      "The absence of findings below is not a clean result — nothing was checked. An administrator can enable scanning under Admin → Vulnerability scanning.",
    );
    ctx.gap(12);
    return;
  }

  /*
   * Same defensive reading as the null check above, for the same reason: this renderer is
   * what a scheduled job emails, so a payload assembled before `filter` existed must
   * produce an unfiltered report rather than a stack trace.
   */
  const filter = vuln.filter ?? INERT_VULN_FILTER;

  const appTotal = vuln.app == null ? null : totalOf(vuln.app.counts);
  const osTotal = vuln.baseImage == null ? null : totalOf(vuln.baseImage.counts);
  const grandTotal = (appTotal ?? 0) + (osTotal ?? 0);

  ctx.heading(
    "Vulnerability findings",
    `Matched against the Grype database built ${fmtDateTime(vuln.dbBuiltAt)}` +
      (vuln.dbAgeHours === null ? "" : ` (${fmt(Math.round(vuln.dbAgeHours))}h old)`) +
      ". Application dependencies and base-image packages are counted separately as well as together — base packages routinely outnumber dependencies by two orders of magnitude, so the combined total says more about base-image age than about anything a team chose.",
  );

  /*
   * The filter, before any number it produced. Placed here rather than in a footnote for
   * the same reason the coverage banner sits above the totals: by the time a reader
   * reaches a footnote they have already believed the figure.
   */
  if (filter.active) {
    ctx.paragraph(`Filtered: ${filter.label ?? ""}`, { color: COLOR.warn, size: 9 });
    ctx.paragraph(
      "Every figure in this section counts only findings matching that filter. The inventory sections elsewhere in this report describe the whole estate and are unaffected — severity does not apply to a package count.",
      { color: COLOR.muted, size: 8 },
    );
    ctx.gap(4);
  }

  statRow(ctx, [
    { label: "Total findings", value: fmt(grandTotal) },
    { label: "Application deps", value: appTotal === null ? "excluded" : fmt(appTotal) },
    { label: "Base image", value: osTotal === null ? "excluded" : fmt(osTotal) },
    { label: "Apps affected", value: fmt(vuln.applicationsAffected) },
  ]);

  const rows: BreakdownRow[] = [];
  if (vuln.app !== null) {
    rows.push({
      label: "Application dependencies",
      total: appTotal ?? 0,
      buckets: bucketize(vuln.app.counts),
      fixable: vuln.app.fixable,
      knownExploited: vuln.app.knownExploited,
      packages: vuln.app.affectedPackages,
    });
  }
  if (vuln.baseImage !== null) {
    rows.push({
      label: "Base image and runtimes",
      total: osTotal ?? 0,
      buckets: bucketize(vuln.baseImage.counts),
      fixable: vuln.baseImage.fixable,
      knownExploited: vuln.baseImage.knownExploited,
      packages: vuln.baseImage.affectedPackages,
    });
  }

  ctx.gap(4);
  breakdownTable(ctx, rows, { detail: true });

  /*
   * "Other" is negligible plus unknown, and unknown is a real answer rather than missing
   * data — stated because a reader who assumes it means "not yet rated" will treat it as
   * a queue of work that does not exist.
   */
  ctx.paragraph(
    "Other combines negligible and unrated advisories. Unrated is a real answer: many advisories carry no severity from any upstream feed, and promoting them to low would overstate them. Accepted risks are excluded from every figure above.",
    { color: COLOR.muted, size: 8 },
  );

  if (filter.scope !== "all") {
    ctx.paragraph(
      filter.scope === "app"
        ? "Base-image and runtime findings were excluded by the filter and are not counted anywhere above. Their absence here is not evidence that there are none."
        : "Application-dependency findings were excluded by the filter and are not counted anywhere above. Their absence here is not evidence that there are none.",
      { color: COLOR.muted, size: 8 },
    );
  }

  if (vuln.applicationsPending > 0) {
    // Said plainly: a partially-swept estate's totals are lower bounds, and a reader
    // comparing two reports needs to know which one was still catching up.
    ctx.paragraph(
      `${fmt(vuln.applicationsPending)} application${vuln.applicationsPending === 1 ? " has" : "s have"} not been matched yet, so the counts above are a lower bound.`,
      { color: COLOR.muted, size: 8 },
    );
  }
  ctx.gap(8);

  // --- unfiltered reference ------------------------------------------------
  /*
   * Present only when a filter narrowed the figures. This is what makes a filtered report
   * safe to forward: whoever receives it can see the size of what was excluded without
   * having to ask, or having to re-run the report themselves.
   */
  if (vuln.unfiltered != null) {
    ctx.heading(
      "For reference: unfiltered totals",
      "The same estate with no filter applied, so the figures above can be read against the whole. Fix availability and package counts are omitted here — they belong to the filtered view and repeating them unfiltered would invite the two to be mixed.",
    );
    breakdownTable(
      ctx,
      [
        {
          label: "Application dependencies",
          total: totalOf(vuln.unfiltered.app),
          buckets: bucketize(vuln.unfiltered.app),
          fixable: null,
          knownExploited: null,
          packages: null,
        },
        {
          label: "Base image and runtimes",
          total: totalOf(vuln.unfiltered.baseImage),
          buckets: bucketize(vuln.unfiltered.baseImage),
          fixable: null,
          knownExploited: null,
          packages: null,
        },
      ],
      { detail: false },
    );
    ctx.gap(8);
  }

  // --- top vulnerable applications -----------------------------------------
  const rankedByBaseImage = vuln.topVulnerableApplications[0]?.rankedBy === "os";
  ctx.heading(
    `Top ${vuln.topVulnerableApplications.length || 10} vulnerable applications`,
    rankedByBaseImage
      ? "Ranked by base-image findings, because the filter excluded application dependencies. Every count on a row is base-image only."
      : "Ranked by findings in application dependencies only. Base-image findings are shown for context but take no part in the ranking — including them would rank base-image age instead.",
  );

  if (vuln.topVulnerableApplications.length === 0) {
    ctx.emptyNote(
      vuln.applicationsScanned === 0
        ? "No application has been matched yet."
        : filter.active
          ? "No application has a finding matching this filter."
          : "No application dependency has a known vulnerability.",
    );
    ctx.gap(10);
  } else {
    table(
      ctx,
      [
        { header: "#", width: 0.05, align: "right", value: (_r, i) => String(i + 1) },
        { header: "Application", width: 0.37, value: (r) => r.name },
        {
          // One column, matching the dashboards: two adjacent numbers under one heading
          // read as a pair, where two separate columns invited them to be added up.
          header: "Findings app/base",
          width: 0.19,
          align: "right",
          value: (r) =>
            `${r.findings === null ? "—" : fmt(r.findings)} / ${
              r.baseImageFindings === null ? "—" : fmt(r.baseImageFindings)
            }`,
        },
        { header: "Crit", width: 0.08, align: "right", value: (r) => fmt(r.critical) },
        { header: "High", width: 0.08, align: "right", value: (r) => fmt(r.high) },
        { header: "Fixable", width: 0.11, align: "right", value: (r) => fmt(r.fixable) },
        { header: "Packages", width: 0.12, align: "right", value: (r) => fmt(r.affectedPackages) },
      ],
      vuln.topVulnerableApplications,
    );
  }

  // --- top vulnerable packages ---------------------------------------------
  ctx.heading(
    `Top ${vuln.topVulnerablePackages.length || 10} vulnerable packages in use`,
    (rankedByBaseImage
      ? "Base-image packages present in some application's current build"
      : "Application dependencies present in some application's current build") +
      ", ranked by the number of distinct advisories against that exact version. `Apps` is the blast radius of fixing it.",
  );

  if (vuln.topVulnerablePackages.length === 0) {
    ctx.emptyNote(
      filter.active
        ? "No package in current use has a finding matching this filter."
        : "No package in current use has a known vulnerability.",
    );
    ctx.gap(10);
  } else {
    table(
      ctx,
      [
        { header: "#", width: 0.05, align: "right", value: (_r, i) => String(i + 1) },
        { header: "Package", width: 0.26, value: (r) => r.name },
        { header: "Version", width: 0.17, value: (r) => r.version ?? "—", mono: true },
        { header: "Advisories", width: 0.12, align: "right", value: (r) => fmt(r.findings) },
        { header: "Crit", width: 0.07, align: "right", value: (r) => fmt(r.critical) },
        { header: "High", width: 0.07, align: "right", value: (r) => fmt(r.high) },
        { header: "Apps", width: 0.08, align: "right", value: (r) => fmt(r.applications) },
        {
          header: "Fixed in",
          width: 0.18,
          value: (r) => (r.fixVersions.length > 0 ? r.fixVersions[0]! : r.fixAvailable ? "yes" : "no fix"),
          mono: true,
        },
      ],
      vuln.topVulnerablePackages,
    );
  }

  // --- base image exposure -------------------------------------------------
  /*
   * Null means the filter excluded base-image packages entirely. Saying so beats printing
   * an empty table, which would read as "no base image has a vulnerability" — a far
   * stronger and quite different claim.
   */
  if (vuln.baseImageExposure == null) {
    ctx.heading(
      "Base image exposure",
      "Not included. The active filter covers application dependencies only, so no base-image package was counted.",
    );
    ctx.gap(10);
    return;
  }

  ctx.heading(
    "Base image exposure",
    "Findings from distribution packages and language runtimes, grouped by base image. Grouped this way because that is the unit of work: twelve services on one old image are a single upgrade, not twelve tasks.",
  );

  if (vuln.baseImageExposure.length === 0) {
    ctx.emptyNote(
      filter.active
        ? "No base-image package has a finding matching this filter."
        : "No base-image package has a known vulnerability.",
    );
    ctx.gap(10);
  } else {
    table(
      ctx,
      [
        { header: "Base image", width: 0.4, value: (r) => [r.osName ?? "unknown", r.osVersion ?? ""].join(" ").trim() },
        { header: "Applications", width: 0.2, align: "right", value: (r) => fmt(r.applications) },
        { header: "Findings", width: 0.16, align: "right", value: (r) => fmt(r.findings) },
        { header: "Critical", width: 0.12, align: "right", value: (r) => fmt(r.critical) },
        { header: "High", width: 0.12, align: "right", value: (r) => fmt(r.high) },
      ],
      vuln.baseImageExposure,
    );
  }
}

function topPackagesSection(ctx: Layout, report: AnalyticsReport): void {
  ctx.heading(
    `Top ${report.topPackages.length} most widely deployed packages`,
    "Present in the most applications' current builds. This is blast radius: the number that decides whether a problem package is one team's afternoon or an estate-wide exercise. Operating systems and language runtimes are excluded and reported separately.",
  );

  if (report.topPackages.length === 0) {
    ctx.emptyNote("No package data yet — counts appear once the first SBOM is ingested.");
    ctx.gap(10);
    return;
  }

  const max = report.topPackages[0]?.applications ?? 0;
  table(
    ctx,
    [
      { header: "#", width: 0.05, align: "right", value: (_r, i) => String(i + 1) },
      { header: "Package", width: 0.42, value: (r) => r.name },
      { header: "Version", width: 0.23, value: (r) => r.version ?? "—", mono: true },
      { header: "Ecosystem", width: 0.16, value: (r) => r.ecosystem, mono: true },
      {
        header: "Apps",
        width: 0.14,
        align: "right",
        value: (r) =>
          max > 0 ? `${fmt(r.applications)}  (${Math.round((r.applications / max) * 100)}%)` : fmt(r.applications),
      },
    ],
    report.topPackages,
  );
}

function topProjectsSection(ctx: Layout, report: AnalyticsReport): void {
  ctx.heading(
    `Top ${report.topProjects.length} applications by package count`,
    "Largest current builds. A size ranking, not a risk ranking — a big image costs more to review, rebuild and patch, but is not automatically in worse shape than a small one.",
  );

  if (report.topProjects.length === 0) {
    ctx.emptyNote("No application has reported a build yet.");
    ctx.gap(10);
    return;
  }

  table(
    ctx,
    [
      { header: "#", width: 0.05, align: "right", value: (_r, i) => String(i + 1) },
      { header: "Application", width: 0.24, value: (r) => r.name },
      // Not mono, and the widest column: a three-part platform summary is ~46
      // characters, which Courier at this size cannot fit without truncating away
      // the runtime version — the most useful part of the string.
      { header: "Runs on", width: 0.4, value: (r) => r.platform ?? "not detected" },
      { header: "Build date", width: 0.17, value: (r) => fmtDate(r.scanAt), mono: true },
      { header: "Packages", width: 0.14, align: "right", value: (r) => fmt(r.packages) },
    ],
    report.topProjects,
  );
}

function fragmentationSection(ctx: Layout, report: AnalyticsReport): void {
  ctx.heading(
    "Version fragmentation",
    "Packages the estate runs several versions of at once. Each extra concurrent version multiplies the cost of the next upgrade of that package, which makes this the section that names work that can actually be finished.",
  );

  if (report.fragmentation.length === 0) {
    ctx.emptyNote("Every deployed package is on a single version across the estate.");
    ctx.gap(10);
    return;
  }

  table(
    ctx,
    [
      { header: "Package", width: 0.26, value: (r) => r.name },
      { header: "Ecosystem", width: 0.12, value: (r) => r.ecosystem, mono: true },
      {
        header: "Versions in use",
        width: 0.42,
        value: (r) => r.examples.join(", ") + (r.versions > r.examples.length ? ", …" : ""),
        mono: true,
      },
      { header: "Versions", width: 0.1, align: "right", value: (r) => fmt(r.versions) },
      { header: "Apps", width: 0.1, align: "right", value: (r) => fmt(r.applications) },
    ],
    report.fragmentation,
  );
}

function velocitySection(ctx: Layout, report: AnalyticsReport): void {
  const v = report.velocity;
  ctx.heading(
    `Dependency churn, last ${report.meta.periodDays} days`,
    "Each application's current build compared against its last build from before the window. Counted by package name, so a version bump is one upgrade rather than one addition plus one removal.",
  );

  /**
   * With nothing to compare against, the three package figures are all zero —
   * and zero would read as "nothing changed" rather than "nothing was measured".
   * Those two mean opposite things to someone deciding whether dependency churn
   * is under control, so the tiles are suppressed rather than printed.
   */
  if (v.applicationsCompared === 0) {
    statRow(ctx, [
      { label: "Scans received", value: fmt(v.scans), note: `${fmt(v.applicationsScanned)} applications reported` },
      { label: "First-time scans", value: fmt(v.applicationsWithoutBaseline), note: "no earlier build" },
    ]);
    ctx.paragraph(
      v.applicationsWithoutBaseline > 0
        ? `No application has a build from before this window, so there is nothing to compare against and no churn figures can be produced. ${fmt(
            v.applicationsWithoutBaseline,
          )} application${
            v.applicationsWithoutBaseline === 1 ? " was" : "s were"
          } scanned for the first time during it. A shorter window, or more retained history, will produce comparable figures.`
        : "No application reported a build inside this window, so there is no churn to report.",
      { color: COLOR.warn, size: 8.5 },
    );
    ctx.gap(10);
    activityChart(ctx, report);
    return;
  }

  statRow(ctx, [
    { label: "Scans received", value: fmt(v.scans), note: `${fmt(v.applicationsScanned)} applications reported` },
    { label: "Packages added", value: fmt(v.packagesAdded), note: "new to that application" },
    { label: "Packages removed", value: fmt(v.packagesRemoved), note: "no longer shipped" },
    { label: "Packages upgraded", value: fmt(v.packagesUpgraded), note: "version changed" },
  ]);

  const notes: string[] = [
    `${fmt(v.applicationsCompared)} application${v.applicationsCompared === 1 ? "" : "s"} had builds on both sides of the window and are included in the three package figures above.`,
  ];
  if (v.applicationsWithoutBaseline > 0) {
    notes.push(
      `${fmt(v.applicationsWithoutBaseline)} application${
        v.applicationsWithoutBaseline === 1 ? " was" : "s were"
      } scanned for the first time during the window and ${
        v.applicationsWithoutBaseline === 1 ? "is" : "are"
      } excluded — every package in a first build would otherwise register as an addition and swamp the real churn.`,
    );
  }
  if (v.applicationsUnchanged > 0) {
    notes.push(
      `A further ${fmt(v.applicationsUnchanged)} application${
        v.applicationsUnchanged === 1 ? " has" : "s have"
      } not built inside the window at all and are unchanged by definition; see Coverage gaps.`,
    );
  }
  ctx.paragraph(notes.join(" "), { color: COLOR.muted, size: 8 });
  ctx.gap(10);

  activityChart(ctx, report);
}

/**
 * Scan activity over the window as a bar chart.
 *
 * Drawn with rectangles rather than through a charting library: the shape needed
 * is one series of bars, and a chart dependency would be a larger surface to keep
 * current than the twenty lines below.
 */
function activityChart(ctx: Layout, report: AnalyticsReport): void {
  const buckets = report.activity;
  if (buckets.length === 0) return;

  const { doc } = ctx;
  const chartHeight = 58;
  const labelBand = 12;

  ctx.ensureSpace(chartHeight + labelBand + 26);

  doc
    .font("Helvetica-Bold")
    .fontSize(8)
    .fillColor(COLOR.muted)
    .text(
      report.meta.periodDays <= 45 ? "Scans per day" : "Scans per week",
      MARGIN,
      doc.y,
      { width: CONTENT_WIDTH },
    );
  ctx.gap(4);

  const top = doc.y;
  const max = buckets.reduce((m, b) => Math.max(m, b.scans), 0);
  const slot = CONTENT_WIDTH / buckets.length;
  const barWidth = Math.max(1.5, Math.min(slot - 1.5, 14));

  // Baseline first, so a window with no activity at all still renders as an axis
  // with nothing on it rather than as blank space that reads like a bug.
  doc
    .moveTo(MARGIN, top + chartHeight)
    .lineTo(MARGIN + CONTENT_WIDTH, top + chartHeight)
    .lineWidth(0.5)
    .strokeColor(COLOR.rule)
    .stroke();

  buckets.forEach((bucket, i) => {
    if (max === 0 || bucket.scans === 0) return;
    const height = Math.max(1, (bucket.scans / max) * chartHeight);
    const x = MARGIN + i * slot + (slot - barWidth) / 2;
    doc.rect(x, top + chartHeight - height, barWidth, height).fillColor(COLOR.accent).fill();
  });

  // First and last labels only. Labelling every bucket at this width overlaps
  // into unreadability, and the two endpoints are what fix the axis in time.
  const first = buckets[0];
  const last = buckets[buckets.length - 1];
  doc.font("Helvetica").fontSize(6.5).fillColor(COLOR.faint);
  if (first) {
    doc.text(fmtDate(first.bucketStart), MARGIN, top + chartHeight + 3, {
      width: CONTENT_WIDTH / 2,
      lineBreak: false,
    });
  }
  if (last && buckets.length > 1) {
    doc.text(fmtDate(last.bucketStart), MARGIN + CONTENT_WIDTH / 2, top + chartHeight + 3, {
      width: CONTENT_WIDTH / 2,
      align: "right",
      lineBreak: false,
    });
  }
  if (max > 0) {
    doc
      .font("Helvetica")
      .fontSize(6.5)
      .fillColor(COLOR.faint)
      .text(`peak ${fmt(max)}`, MARGIN, top - 0.5, { width: CONTENT_WIDTH, align: "right", lineBreak: false });
  }

  doc.y = top + chartHeight + labelBand + 8;
}

function newPackagesSection(ctx: Layout, report: AnalyticsReport): void {
  ctx.heading(
    `Packages new to the estate, last ${report.meta.periodDays} days`,
    "First seen in a build inside the window and still deployed. The supply-chain review queue: what is in our images now that was not here before.",
  );

  if (report.newPackages.length === 0) {
    ctx.emptyNote("No package currently deployed first appeared inside this window.");
    ctx.gap(10);
    return;
  }

  table(
    ctx,
    [
      { header: "Package", width: 0.34, value: (r) => r.name },
      { header: "Version", width: 0.22, value: (r) => r.version ?? "—", mono: true },
      { header: "Ecosystem", width: 0.14, value: (r) => r.ecosystem, mono: true },
      { header: "First seen", width: 0.19, value: (r) => fmtDate(r.firstSeenAt), mono: true },
      { header: "Apps", width: 0.11, align: "right", value: (r) => fmt(r.applications) },
    ],
    report.newPackages,
  );
}

function platformSection(ctx: Layout, report: AnalyticsReport): void {
  const { operatingSystems, runtimes, unknown } = report.platforms;

  ctx.heading(
    "Platform inventory",
    "Observed contents of each application's current build, read from the SBOM itself. This is what the image contains, not what its Dockerfile said: an SBOM describes a flattened filesystem, so the base image name is not recoverable from it.",
  );

  if (operatingSystems.length === 0 && runtimes.length === 0) {
    ctx.emptyNote(
      "No OS or runtime detected in any current build. Scans ingested before platform detection existed need the backfill.",
    );
    ctx.gap(10);
    return;
  }

  if (operatingSystems.length > 0) {
    ctx.paragraph("Operating systems", { color: COLOR.muted, size: 8.5 });
    ctx.gap(3);
    table(
      ctx,
      [
        { header: "Distribution", width: 0.5, value: (r) => osLabel(r.name) ?? "not detected" },
        { header: "Version", width: 0.3, value: (r) => r.version ?? "—", mono: true },
        { header: "Applications", width: 0.2, align: "right", value: (r) => fmt(r.applications) },
      ],
      operatingSystems,
    );
  }

  if (runtimes.length > 0) {
    ctx.paragraph("Language runtimes and application servers", { color: COLOR.muted, size: 8.5 });
    ctx.gap(3);
    table(
      ctx,
      [
        { header: "Runtime", width: 0.5, value: (r) => runtimeLabel(r.name) },
        { header: "Version", width: 0.3, value: (r) => r.version ?? "—", mono: true },
        { header: "Applications", width: 0.2, align: "right", value: (r) => fmt(r.applications) },
      ],
      runtimes,
    );
    ctx.paragraph(
      "An application appears once per runtime it ships, so these counts can legitimately sum to more than the application total.",
      { color: COLOR.faint, size: 7.5 },
    );
    ctx.gap(6);
  }

  if (unknown > 0) {
    ctx.paragraph(
      `${fmt(unknown)} application${unknown === 1 ? "" : "s"} reported neither an OS nor a runtime, which is the expected result for a scratch or distroless image.`,
      { color: COLOR.muted, size: 8 },
    );
    ctx.gap(8);
  }
}

function ecosystemSection(ctx: Layout, report: AnalyticsReport): void {
  ctx.heading("Ecosystem mix", "Distinct packages in current builds, by package manager.");

  if (report.ecosystems.length === 0) {
    ctx.emptyNote("No components recorded yet.");
    return;
  }

  table(
    ctx,
    [
      { header: "Ecosystem", width: 0.4, value: (r) => r.ecosystem, mono: true },
      { header: "Distinct packages", width: 0.3, align: "right", value: (r) => fmt(r.components) },
      { header: "Applications", width: 0.3, align: "right", value: (r) => fmt(r.applications) },
    ],
    report.ecosystems.slice(0, 14),
  );
}

/**
 * What the numbers mean, and what they do not.
 *
 * At the back because it is reference, not news — but present, because a report
 * that circulates without its definitions gets its figures compared against
 * other tools' differently-defined ones.
 */
function methodologySection(ctx: Layout, report: AnalyticsReport): void {
  ctx.heading("How to read this report");

  const items: Array<[string, string]> = [
    /*
     * This entry has to track the feature flag. It previously stated flatly that the
     * platform holds no vulnerability data, which is the right thing to say when
     * scanning is off and a falsehood when it is on — and a methodology note that
     * contradicts the tables above it discredits both.
     */
    report.vulnerabilities == null
      ? [
          "No vulnerability data",
          "Vulnerability scanning is disabled on this platform, so no package here has been matched against a vulnerability database. Nothing in this report ranks anything by vulnerability, and a package appearing near the top of a list means it is widely deployed, not that it is a problem.",
        ]
      : [
          "Vulnerability data",
          `Findings come from Grype matching this estate's SBOM contents against its vulnerability database, built ${fmtDateTime(report.vulnerabilities.dbBuiltAt)}. Severity, CVSS, EPSS and known-exploited status are reported as the upstream feeds state them; the platform computes no risk score of its own. Findings an administrator has accepted as risks are excluded from every count.`,
        ],
    report.vulnerabilities == null
      ? [
          "Rankings measure size, not risk",
          "The package and application rankings below count how widely something is deployed or how large a build is.",
        ]
      : [
          "App dependencies vs base image",
          "The two are totalled separately as well as together, and every ranking is computed on one of them rather than on the sum — application dependencies, unless a filter excludes them. Measured on a typical container image, distribution packages and language runtimes account for around 99% of all findings, so a ranking on the combined figure would order applications by base-image age and bury everything a team chose. That is also why the combined total is the least useful number here despite being the one most often quoted.",
        ],
    [
      "Current build",
      "Every 'in use' figure counts each application's most recent scan. Historical scans are retained in full and searchable, but excluded from these counts.",
    ],
    [
      "Inactive applications",
      "Excluded from every count. A decommissioned service inflating a figure being used to size an upgrade is worse than omitting it.",
    ],
    [
      "Packages vs platform",
      "Package counts cover libraries and OS packages. The base distribution and language runtimes are excluded from those rankings and reported under Platform inventory instead.",
    ],
    [
      "Staleness",
      `An active application is stale when its most recent build is older than ${report.meta.staleThresholdDays} days. It is a signal about the pipeline, not about the application.`,
    ],
    [
      "Coverage",
      "The share of active applications with a build inside the staleness threshold. Treat it as the confidence interval on everything else in this report.",
    ],
  ];

  for (const [term, body] of items) {
    ctx.ensureSpace(30);
    const { doc } = ctx;
    const top = doc.y;
    doc
      .font("Helvetica-Bold")
      .fontSize(8)
      .fillColor(COLOR.text)
      .text(term, MARGIN, top, { width: CONTENT_WIDTH * 0.24 });
    const afterTerm = doc.y;
    doc
      .font("Helvetica")
      .fontSize(8)
      .fillColor(COLOR.muted)
      .text(body, MARGIN + CONTENT_WIDTH * 0.26, top, { width: CONTENT_WIDTH * 0.74, lineGap: 1 });
    doc.y = Math.max(afterTerm, doc.y) + 5;
  }
}

/**
 * Writes the footer onto every page.
 *
 * Deferred to the end because "page 3 of 7" needs the total, which is only known
 * once all the content has been laid out. `bufferPages` is what makes going back
 * possible.
 *
 * The footer sits below the page's bottom margin, and pdfkit responds to text
 * that far down by flowing it onto a *new* page — which appended one blank page
 * per footer fragment and left the real content pages unfooted, while the labels
 * still counted only the original pages. Zeroing the bottom margin on each page
 * before writing is what keeps the text where it was put.
 */
