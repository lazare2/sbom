import PDFDocument from "pdfkit";
import type {
  AnalyticsReport,
  BuildDeltaCounts,
  BuildDeltaSide,
  ProgressRollup,
  ProjectBuildDeltas,
  ProjectProgress,
} from "@sbom/shared";
import {
  CONTENT_WIDTH,
  COLOR,
  Layout,
  MARGIN,
  PAGE,
  fmt,
  fmtDate,
  fmtDateTime,
  stampFooters,
  statRow,
  table,
} from "./pdf-layout.js";

export interface RenderReportOptions {
  /** Shown in the footer next to the page number. */
  title?: string;
}

/**
 * Renders the analytics report as a PDF - the same payload the Analytics page shows, so a
 * printed figure is always one the screen shows too. Also what the monthly email attaches.
 *
 * Server-side with pdfkit rather than HTML-to-PDF through a headless browser: vector text in
 * a small file, no Chromium in the API image, and a plain curl-able URL. Only the standard-14
 * fonts are used, which cover Latin-1; package names are ASCII in every ecosystem ingested.
 *
 * Buffered rather than streamed, so a rendering failure is a clean 500 instead of a truncated
 * file that a scheduled job would archive as a valid report.
 */
export async function renderReportPdf(
  report: AnalyticsReport,
  options: RenderReportOptions = {},
): Promise<Buffer> {
  const title = options.title ?? "SBOM analytics report";

  const doc = new PDFDocument({
    size: [PAGE.width, PAGE.height],
    margin: MARGIN,
    info: {
      Title: title,
      Author: "SBOM Platform",
      Subject: `Progress report for ${report.meta.environmentName}, ${report.meta.periodDays}-day window`,
      CreationDate: new Date(report.meta.generatedAt),
    },
    // Every page break is placed deliberately by `ensureSpace`.
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
  attentionSection(ctx, report);
  progressSection(ctx, report);
  rollupSection(ctx, report, "squads");
  rollupSection(ctx, report, "tribes");
  buildDeltaSection(ctx, report, "app");
  buildDeltaSection(ctx, report, "os");
  attentionPackagesSection(ctx, report);
  fragmentationRisingSection(ctx, report);
  coverageSection(ctx, report);
  velocitySection(ctx, report);
  newPackagesSection(ctx, report);
  methodologySection(ctx, report);

  // Footers last: the page count is only known once the content is laid out.
  stampFooters(doc, title, report.meta.generatedAt);

  doc.end();
  return finished;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

const dash = " - ";
const signed = (n: number) => (n > 0 ? `+${fmt(n)}` : fmt(n));
const days = (n: number | null) => (n === null ? dash : `${n}`);

/** Every project's in-window movement summed, for the cover. */
function windowTotals(projects: readonly ProjectProgress[]) {
  let fixed = 0;
  let introduced = 0;
  let compared = 0;
  for (const p of projects) {
    if (!p.vulnerabilities) continue;
    fixed += p.vulnerabilities.fixed;
    introduced += p.vulnerabilities.introduced;
    compared += p.vulnerabilities.comparedBuilds;
  }
  return { fixed, introduced, compared };
}

// ---------------------------------------------------------------------------
// sections
// ---------------------------------------------------------------------------

function coverBlock(ctx: Layout, report: AnalyticsReport): void {
  const { doc } = ctx;
  const { meta, totals, coverage, progress, attention } = report;

  doc.y = MARGIN;
  doc
    .font("Helvetica-Bold")
    .fontSize(20)
    .fillColor(COLOR.text)
    .text(`Analytics: ${meta.environmentName}`, MARGIN, doc.y, { width: CONTENT_WIDTH });

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
    The team filter, on the cover. A filtered report is forwarded and quoted like any other,
    so the fact that it is filtered has to survive being read by someone who never saw the
    screen it came from.
  */
  if (meta.filterLabel) {
    ctx.gap(6);
    doc
      .font("Helvetica-Bold")
      .fontSize(9)
      .fillColor(COLOR.warn)
      .text(`Only applications in ${meta.filterLabel}.`, MARGIN, doc.y, { width: CONTENT_WIDTH });
  }

  ctx.gap(10);
  ctx.rule();
  ctx.gap(12);

  const moved = windowTotals(progress.projects);
  const net = moved.introduced - moved.fixed;
  statRow(ctx, [
    { label: "Applications", value: fmt(totals.applications), note: `${fmt(totals.activeApplications)} active` },
    { label: "Builds in window", value: fmt(totals.scansInPeriod), note: `${fmt(totals.scans)} in total` },
    {
      label: "Need attention",
      value: fmt(attention.projects.length),
      note: "projects with at least one flag",
      tone: attention.projects.length > 0 ? "warn" : "ok",
    },
    {
      label: "Scan coverage",
      value: `${coverage.coveragePct}%`,
      note: `${fmt(coverage.covered)}/${fmt(coverage.eligible)} active apps`,
      tone: coverage.coveragePct >= 90 ? "ok" : "warn",
    },
  ]);

  if (meta.vulnScanningEnabled) {
    statRow(ctx, [
      { label: "Findings fixed", value: fmt(moved.fixed), note: "removed by a build in the window" },
      { label: "Findings introduced", value: fmt(moved.introduced), note: "brought in by a build" },
      { label: "Net change", value: signed(net), note: "introduced minus fixed", tone: net > 0 ? "warn" : "ok" },
      { label: "Builds compared", value: fmt(moved.compared), note: "consecutive pairs, rebuilds skipped" },
    ]);
  }

  ctx.gap(2);
  const caveat =
    coverage.coveragePct >= 100 && coverage.neverScanned === 0
      ? `Every active application has reported a build within ${meta.staleThresholdDays} days, so the figures below describe the whole estate.`
      : `Figures below describe only what has been scanned. ${fmt(coverage.stale)} active application${
          coverage.stale === 1 ? " has" : "s have"
        } not reported a build in ${meta.staleThresholdDays} days and ${fmt(coverage.neverScanned)} ${
          coverage.neverScanned === 1 ? "has" : "have"
        } never reported one.`;
  ctx.paragraph(caveat, { color: coverage.coveragePct >= 100 ? COLOR.muted : COLOR.warn, size: 8.5 });
  if (meta.vulnScanningEnabled) {
    ctx.gap(3);
    ctx.paragraph(
      "Every build is judged by today's vulnerability database, so 'introduced' means a change to a project's dependencies or base image brought a finding in; an advisory published between two builds is not counted against the team. Accepted risks are excluded throughout.",
      { color: COLOR.muted, size: 8 },
    );
  }
  ctx.gap(14);
}

/** Projects with at least one flag, each with the sentence that explains it. */
function attentionSection(ctx: Layout, report: AnalyticsReport): void {
  const projects = report.attention.projects;
  ctx.heading(
    "Projects that need attention",
    "A project is flagged for an open known-exploited advisory, a critical finding with a fix left open too long, a build overdue against its usual pace, or builds that introduced more than they fixed. Each flag states its reason.",
  );
  if (projects.length === 0) {
    ctx.emptyNote("No project is flagged.");
    ctx.gap(10);
    return;
  }

  const { doc } = ctx;
  for (const project of projects) {
    ctx.ensureSpace(30 + project.flags.length * 12);
    doc
      .font("Helvetica-Bold")
      .fontSize(9)
      .fillColor(COLOR.text)
      .text(
        project.name + (project.squads.length > 0 ? `  ·  ${project.squads.join(", ")}` : ""),
        MARGIN,
        doc.y,
        { width: CONTENT_WIDTH },
      );
    for (const flag of project.flags) {
      const urgent = flag.kind === "known_exploited" || flag.kind === "critical_fix_overdue";
      doc
        .font("Helvetica")
        .fontSize(8)
        .fillColor(urgent ? COLOR.warn : COLOR.muted)
        .text(`-  ${flag.reason}`, MARGIN + 10, doc.y + 1, { width: CONTENT_WIDTH - 10, lineGap: 1 });
    }
    ctx.gap(6);
  }
  ctx.gap(6);
}

function progressSection(ctx: Layout, report: AnalyticsReport): void {
  const vulns = report.meta.vulnScanningEnabled;
  ctx.heading(
    "Progress by project",
    vulns
      ? "Findings fixed and introduced by builds inside the window, what is open now and how that compares with the start, how often each project builds, and the average days a critical or high finding stayed before a build removed it."
      : "How often each project builds. Vulnerability scanning is switched off, so no finding movement is shown.",
  );
  const rows = [...report.progress.projects].sort(
    (a, b) => (b.vulnerabilities?.fixed ?? 0) - (a.vulnerabilities?.fixed ?? 0) || a.name.localeCompare(b.name),
  );
  if (rows.length === 0) {
    ctx.emptyNote("No application in scope.");
    ctx.gap(10);
    return;
  }

  if (vulns) {
    table(
      ctx,
      [
        { header: "Project", width: 0.25, value: (p) => p.name },
        { header: "Fixed", width: 0.08, align: "right", value: (p) => fmt(p.vulnerabilities?.fixed ?? 0) },
        { header: "New", width: 0.08, align: "right", value: (p) => fmt(p.vulnerabilities?.introduced ?? 0) },
        { header: "Net", width: 0.07, align: "right", value: (p) => signed(p.vulnerabilities?.net ?? 0) },
        {
          header: "Open C / H",
          width: 0.11,
          align: "right",
          value: (p) =>
            p.vulnerabilities?.openCritical == null
              ? dash
              : `${fmt(p.vulnerabilities.openCritical)} / ${fmt(p.vulnerabilities.openHigh ?? 0)}`,
        },
        {
          header: "C+H chg",
          width: 0.1,
          align: "right",
          value: (p) => (p.vulnerabilities?.criticalHighChange == null ? dash : signed(p.vulnerabilities.criticalHighChange)),
        },
        { header: "Builds", width: 0.09, align: "right", value: (p) => fmt(p.builds.inWindow) },
        { header: "Every (d)", width: 0.1, align: "right", value: (p) => days(p.builds.averageDaysBetweenBuilds) },
        { header: "Fix (d)", width: 0.1, align: "right", value: (p) => days(p.vulnerabilities?.meanDaysToFix ?? null) },
      ],
      rows,
    );
  } else {
    table(
      ctx,
      [
        { header: "Project", width: 0.4, value: (p) => p.name },
        { header: "Builds in window", width: 0.2, align: "right", value: (p) => fmt(p.builds.inWindow) },
        { header: "Every (d)", width: 0.2, align: "right", value: (p) => days(p.builds.averageDaysBetweenBuilds) },
        { header: "Last build", width: 0.2, align: "right", value: (p) => fmtDate(p.builds.lastBuildAt) },
      ],
      rows,
    );
  }
  ctx.gap(10);
}

function rollupSection(ctx: Layout, report: AnalyticsReport, key: "squads" | "tribes"): void {
  const rows = report.progress[key];
  // A rollup where every project is unassigned says nothing the project table did not.
  if (rows.length === 0 || rows.every((r) => r.name === null)) return;
  const noun = key === "squads" ? "squad" : "tribe";
  const header = noun[0]!.toUpperCase() + noun.slice(1);
  ctx.heading(
    `Progress by ${noun}`,
    `The project figures rolled up. A project on two ${key} counts in both; projects on none are grouped at the end.`,
  );
  const label = (r: ProgressRollup) => r.name ?? `(no ${noun})`;
  table(
    ctx,
    report.meta.vulnScanningEnabled
      ? [
          { header, width: 0.21, value: label },
          { header: "Apps", width: 0.07, align: "right", value: (r) => fmt(r.applications) },
          { header: "Fixed", width: 0.08, align: "right", value: (r) => fmt(r.vulnerabilities?.fixed ?? 0) },
          { header: "New", width: 0.08, align: "right", value: (r) => fmt(r.vulnerabilities?.introduced ?? 0) },
          { header: "Net", width: 0.07, align: "right", value: (r) => signed(r.vulnerabilities?.net ?? 0) },
          {
            header: "Open C / H",
            width: 0.11,
            align: "right",
            value: (r) =>
              r.vulnerabilities ? `${fmt(r.vulnerabilities.openCritical)} / ${fmt(r.vulnerabilities.openHigh)}` : dash,
          },
          { header: "Builds", width: 0.08, align: "right", value: (r) => fmt(r.buildsInWindow) },
          { header: "Every (d)", width: 0.1, align: "right", value: (r) => days(r.averageDaysBetweenBuilds) },
          { header: "Fix (d)", width: 0.09, align: "right", value: (r) => days(r.vulnerabilities?.meanDaysToFix ?? null) },
          { header: "Flags", width: 0.11, align: "right", value: (r) => fmt(r.flaggedApplications) },
        ]
      : [
          { header, width: 0.4, value: label },
          { header: "Apps", width: 0.15, align: "right", value: (r) => fmt(r.applications) },
          { header: "Builds", width: 0.15, align: "right", value: (r) => fmt(r.buildsInWindow) },
          { header: "Every (d)", width: 0.15, align: "right", value: (r) => days(r.averageDaysBetweenBuilds) },
          { header: "Flagged", width: 0.15, align: "right", value: (r) => fmt(r.flaggedApplications) },
        ],
    rows,
  );
  ctx.gap(10);
}

/** "12 (2C 3H)" - a total with its critical and high counts, the shape every cell here uses. */
function countsCell(c: BuildDeltaCounts | undefined): string {
  if (!c) return dash;
  const parts = [c.critical > 0 ? `${c.critical}C` : null, c.high > 0 ? `${c.high}H` : null].filter(Boolean);
  return parts.length > 0 ? `${c.total} (${parts.join(" ")})` : `${c.total}`;
}

function buildDeltaSection(ctx: Layout, report: AnalyticsReport, half: "app" | "os"): void {
  const section = report.buildDeltas;
  if (!section) return;
  const name = half === "app" ? "application dependencies" : "base image";
  ctx.heading(
    `Build to build: ${name}`,
    "What each build did to the findings of the build before it, on average per build inside the window and for the latest build. " +
      `Byte-identical rebuilds are skipped (${fmt(section.identicalRebuildsSkipped)} in this window). ` +
      "F / N / S are fixed, new (introduced) and still there (unchanged); C+H counts critical and high only. A finding is a package name with an advisory, so an upgrade that leaves a package affected is unchanged.",
  );
  const rows = section.projects.filter((p) => p.average !== null || p.last !== null);
  if (rows.length === 0) {
    ctx.emptyNote("No project has two matched builds to compare yet.");
    ctx.gap(10);
    return;
  }
  const pick = (p: ProjectBuildDeltas, which: "average" | "last"): BuildDeltaSide | undefined =>
    which === "average" ? p.average?.[half] : p.last?.[half];
  const triple = (side: BuildDeltaSide | undefined, level: "all" | "ch") =>
    side
      ? [side.fixed, side.introduced, side.unchanged]
          .map((c) => (level === "all" ? c.total : Math.round((c.critical + c.high) * 10) / 10))
          .join(" / ")
      : dash;
  table(
    ctx,
    [
      { header: "Project", width: 0.2, value: (p) => p.name },
      { header: "Pairs", width: 0.08, align: "right", value: (p) => fmt(p.comparedBuilds) },
      { header: "Avg F/N/S", width: 0.18, align: "right", value: (p) => triple(pick(p, "average"), "all") },
      { header: "Avg C+H F/N/S", width: 0.18, align: "right", value: (p) => triple(pick(p, "average"), "ch") },
      { header: "Last F/N/S", width: 0.18, align: "right", value: (p) => triple(pick(p, "last"), "all") },
      { header: "Last C+H F/N/S", width: 0.18, align: "right", value: (p) => triple(pick(p, "last"), "ch") },
    ],
    rows,
  );
  const estate = section.estateAverage?.[half];
  if (estate) {
    ctx.gap(3);
    ctx.paragraph(
      `Estate average per build (every project weighs the same): ${countsCell(estate.fixed)} fixed, ${countsCell(estate.introduced)} introduced, ${countsCell(estate.unchanged)} unchanged.`,
      { color: COLOR.muted, size: 8 },
    );
  }
  ctx.gap(10);
}

function attentionPackagesSection(ctx: Layout, report: AnalyticsReport): void {
  if (!report.meta.vulnScanningEnabled) return;
  ctx.heading(
    "Packages to upgrade first",
    "Application dependencies with critical or known-exploited advisories that have a fixed version, ranked by how many applications one upgrade clears.",
  );
  const rows = report.attention.packages;
  if (rows.length === 0) {
    ctx.emptyNote("No application dependency carries a critical or known-exploited advisory with a fix.");
    ctx.gap(10);
    return;
  }
  table(
    ctx,
    [
      { header: "Package", width: 0.26, value: (r) => r.name },
      { header: "Ecosystem", width: 0.11, value: (r) => r.ecosystem, mono: true },
      { header: "Apps", width: 0.07, align: "right", value: (r) => fmt(r.applications) },
      { header: "Critical", width: 0.09, align: "right", value: (r) => fmt(r.critical) },
      { header: "KEV", width: 0.07, align: "right", value: (r) => fmt(r.knownExploited) },
      { header: "Versions", width: 0.09, align: "right", value: (r) => fmt(r.versionsInUse) },
      { header: "Fixed in", width: 0.31, value: (r) => (r.fixVersions.length > 0 ? r.fixVersions.join(", ") : dash), mono: true },
    ],
    rows,
  );
  ctx.gap(10);
}

function fragmentationRisingSection(ctx: Layout, report: AnalyticsReport): void {
  const rows = report.attention.fragmentationRising;
  ctx.heading(
    "Fragmentation getting worse",
    "Application dependencies now run in more versions than at the start of the window, across projects that built on both sides of it.",
  );
  if (rows.length === 0) {
    ctx.emptyNote("No package spread into more versions during the window.");
    ctx.gap(10);
    return;
  }
  table(
    ctx,
    [
      { header: "Package", width: 0.4, value: (r) => r.name },
      { header: "Ecosystem", width: 0.15, value: (r) => r.ecosystem, mono: true },
      { header: "Versions then", width: 0.15, align: "right", value: (r) => fmt(r.versionsAtStart) },
      { header: "Versions now", width: 0.15, align: "right", value: (r) => fmt(r.versionsNow) },
      { header: "Apps", width: 0.15, align: "right", value: (r) => fmt(r.applications) },
    ],
    rows,
  );
  ctx.gap(10);
}

function methodologySection(ctx: Layout, report: AnalyticsReport): void {
  ctx.heading("How to read this report");
  const s = report.meta.attentionSettings;
  const overdue =
    s.buildOverdueMode === "fixed"
      ? `A project is overdue for a build after ${s.fixedDays} days without one.`
      : `A project is overdue for a build once it has gone ${s.useMultiplier ? `${s.multiplier} times` : "longer than"} its own average gap between builds over the last ${s.cadenceWindowDays} days, and never sooner than ${s.minimumDays} days. A project with fewer than ${s.minimumBuilds} builds in that time has no usable average, and the fixed ${s.fixedDays}-day limit applies to it instead.`;

  const items: Array<[string, string]> = [
    report.meta.vulnScanningEnabled
      ? [
          "Today's knowledge",
          "Every build is compared using today's vulnerability database. 'Fixed' means a later build no longer carries a finding the earlier one did; 'introduced' means it carries one the earlier did not. An advisory published between two builds therefore appears in both and counts as unchanged - the report credits and blames changes the team made, not the calendar. Accepted risks are excluded everywhere.",
        ]
      : ["No vulnerability data", "Vulnerability scanning is switched off, so the report shows build activity only."],
    [
      "Finding identity",
      "A finding is a package name within its ecosystem plus an advisory. Upgrading a package from one affected version to another leaves the finding unchanged rather than counting a fix and a new finding.",
    ],
    [
      "Identical rebuilds",
      "A build whose SBOM is byte-identical to the build before changed nothing, so the build-to-build comparison skips it. Build counts and the usual build pace still include it - a pipeline that ran is evidence the project is alive.",
    ],
    ["Build overdue", overdue],
    [
      "Critical fix overdue",
      `A critical finding with a fixed version available, open in the current build for longer than ${s.criticalFixDays} days - counted from the later of when the project first shipped the package and when the finding was first recorded.`,
    ],
    [
      "Days to fix",
      "For critical and high findings removed by a build inside the window: the days from the first build of the project that carried the finding to the build that removed it.",
    ],
    [
      "Inactive applications",
      "Excluded from every count. A decommissioned service inflating a figure being used to judge work is worse than omitting it.",
    ],
    ["Staleness", `An active application is stale when its most recent build is older than ${report.meta.staleThresholdDays} days.`],
  ];

  for (const [term, body] of items) {
    ctx.ensureSpace(30);
    const { doc } = ctx;
    const top = doc.y;
    doc.font("Helvetica-Bold").fontSize(8).fillColor(COLOR.text).text(term, MARGIN, top, { width: CONTENT_WIDTH * 0.24 });
    const afterTerm = doc.y;
    doc
      .font("Helvetica")
      .fontSize(8)
      .fillColor(COLOR.muted)
      .text(body, MARGIN + CONTENT_WIDTH * 0.26, top, { width: CONTENT_WIDTH * 0.74, lineGap: 1 });
    doc.y = Math.max(afterTerm, doc.y) + 5;
  }
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

function velocitySection(ctx: Layout, report: AnalyticsReport): void {
  const v = report.velocity;
  ctx.heading(
    `Dependency churn, last ${report.meta.periodDays} days`,
    "Each application's current build compared against its last build from before the window. Counted by package name, so a version bump is one upgrade rather than one addition plus one removal.",
  );

  /**
   * With nothing to compare against, the three package figures are all zero -
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
      } excluded - every package in a first build would otherwise register as an addition and swamp the real churn.`,
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
      { header: "Version", width: 0.22, value: (r) => r.version ?? " - ", mono: true },
      { header: "Ecosystem", width: 0.14, value: (r) => r.ecosystem, mono: true },
      { header: "First seen", width: 0.19, value: (r) => fmtDate(r.firstSeenAt), mono: true },
      { header: "Apps", width: 0.11, align: "right", value: (r) => fmt(r.applications) },
    ],
    report.newPackages,
  );
}
