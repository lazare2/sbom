import PDFDocument from "pdfkit";
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
  type Column,
} from "./pdf-layout.js";
import type {
  ApplicationRisk,
  CauseBreakdown,
  MonthlyReportView,
  PackageExposure,
  SeverityMovement,
} from "./monthly-view.js";

/**
 * The monthly management report, as a PDF.
 *
 * Written for an audience that will read the first page and skim the rest, and that will
 * quote one number from it in a meeting. Three consequences run through the layout:
 *
 *  - The caveat about the vulnerability database sits above the figures, not in a footnote.
 *    A reader who quotes "43 fixed" without it has been misled by the document's ordering.
 *  - Every count that can be misread is followed by the sentence that says what it means.
 *  - Base-image findings are separated from application dependencies everywhere. They
 *    outnumber real dependency findings by roughly four to one here, so a combined headline
 *    would say almost nothing about the work any team can actually do.
 *
 * A separate renderer from the estate report rather than a variant of it: that one is an
 * inventory of what exists, this one is an argument about what changed, and the two would
 * fight over every section if they shared a template.
 */

const TITLE = "Monthly dependency and vulnerability report";

/** Fixed en-GB rendering so an archived report reads the same on any machine. */
function monthName(periodLabel: string): string {
  const [year, month] = periodLabel.split("-");
  const date = new Date(Date.UTC(Number(year), Number(month) - 1, 1));
  if (Number.isNaN(date.getTime())) return periodLabel;
  return date.toLocaleDateString("en-GB", { month: "long", year: "numeric", timeZone: "UTC" });
}

/** Movement as a tile caption, where an em dash would read as missing data. */
function describeChange(value: number): string {
  if (value === 0) return "unchanged since last report";
  return `${signed(value)} since last report`;
}

/** A signed count, so a table column reads as movement rather than as a total. */
function signed(value: number): string {
  if (value === 0) return "—";
  return value > 0 ? `+${fmt(value)}` : `-${fmt(Math.abs(value))}`;
}

const SEVERITY_LABELS: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  negligible: "Negligible",
  unknown: "Unknown",
};

export async function renderMonthlyReportPdf(view: MonthlyReportView): Promise<Buffer> {
  const period = monthName(view.run.periodLabel);
  const title = `${TITLE} — ${period}`;

  const doc = new PDFDocument({
    size: [PAGE.width, PAGE.height],
    margin: MARGIN,
    info: {
      Title: title,
      Author: "SBOM Platform",
      Subject: `Dependency and vulnerability movement for ${period}`,
      CreationDate: new Date(view.run.generatedAt),
    },
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

  coverBlock(ctx, view, period);
  movementSection(ctx, view);
  severitySection(ctx, view);
  estateSection(ctx, view);
  applicationSection(ctx, view);
  packageSection(ctx, view);
  newFindingsSection(ctx, view);
  methodologySection(ctx, view);

  stampFooters(doc, `${TITLE} · ${period}`, view.run.generatedAt);

  doc.end();
  return finished;
}

// ---------------------------------------------------------------------------
// cover
// ---------------------------------------------------------------------------

function coverBlock(ctx: Layout, view: MonthlyReportView, period: string): void {
  const { doc } = ctx;
  const { headline, run } = view;

  doc.font("Helvetica-Bold").fontSize(20).fillColor(COLOR.text);
  doc.text(TITLE, MARGIN, MARGIN, { width: CONTENT_WIDTH });

  doc.moveDown(0.2);
  doc.font("Helvetica").fontSize(13).fillColor(COLOR.accent);
  doc.text(period, { width: CONTENT_WIDTH });

  doc.moveDown(0.5);
  doc.font("Helvetica").fontSize(8).fillColor(COLOR.muted);
  doc.text(
    [
      `Period ${fmtDate(run.periodStart)} to ${fmtDate(run.periodEnd)} (${run.timeZone})`,
      `Generated ${fmtDateTime(run.generatedAt)}`,
      run.generatedBy ? `Requested by ${run.generatedBy}` : "Generated automatically",
    ].join("   ·   "),
    { width: CONTENT_WIDTH },
  );

  ctx.gap(10);
  ctx.rule();
  ctx.gap(10);

  /*
    The caveat before the numbers. Placing it after would make the document technically
    complete and practically misleading, since the figures are what gets quoted.
  */
  if (view.databaseCaveat) {
    const height = doc.heightOfString(view.databaseCaveat, { width: CONTENT_WIDTH - 20 }) + 16;
    ctx.ensureSpace(height + 10);
    const top = doc.y;
    doc.roundedRect(MARGIN, top, CONTENT_WIDTH, height, 3).fillColor("#fffbeb").fill();
    doc
      .roundedRect(MARGIN, top, CONTENT_WIDTH, height, 3)
      .lineWidth(0.5)
      .strokeColor("#fcd34d")
      .stroke();
    doc.font("Helvetica-Bold").fontSize(8).fillColor(COLOR.warn);
    doc.text("Read this first", MARGIN + 10, top + 7, { width: CONTENT_WIDTH - 20 });
    doc.font("Helvetica").fontSize(8).fillColor(COLOR.text);
    doc.text(view.databaseCaveat, MARGIN + 10, doc.y + 1, {
      width: CONTENT_WIDTH - 20,
      lineGap: 1.5,
    });
    doc.y = top + height + 12;
  }

  statRow(ctx, [
    {
      label: "Applications",
      value: fmt(headline.applications),
      note: describeApplicationMovement(view),
    },
    {
      label: "Open findings",
      value: fmt(headline.totalFindings),
      note: view.delta
        ? describeChange(headline.totalFindings - view.delta.findings.previousTotal)
        : "no comparison yet",
      tone: "warn",
    },
    /*
      The split is a headline figure rather than a detail. Base-image findings outnumber
      application dependencies several times over here, so a reader who takes only the total
      away has taken away a number that no team can act on directly.
    */
    {
      label: "In app dependencies",
      value: fmt(headline.appFindings),
      note: `plus ${fmt(headline.baseFindings)} from base images`,
      tone: "warn",
    },
    {
      label: "Critical and high",
      value: fmt(headline.criticalAndHigh),
      note: "of all open findings",
      tone: headline.criticalAndHigh > 0 ? "warn" : "ok",
    },
  ]);

  statRow(ctx, [
    {
      label: "Resolved",
      value: fmt(headline.resolved),
      note: "attributed by cause below",
      tone: headline.resolved > 0 ? "ok" : undefined,
    },
    {
      label: "Introduced",
      value: fmt(headline.introduced),
      note: "attributed by cause below",
      tone: headline.introduced > 0 ? "warn" : undefined,
    },
    {
      label: "Reintroduced",
      value: fmt(headline.reintroduced),
      note: "resolved before, back again",
      tone: headline.reintroduced > 0 ? "warn" : undefined,
    },
  ]);

  ctx.heading("Summary");
  ctx.paragraph(view.summary);
  ctx.gap(10);
}

function describeApplicationMovement(view: MonthlyReportView): string {
  const added = view.applicationsAdded.length;
  const removed = view.applicationsRemoved.length;
  if (added === 0 && removed === 0) return "no change";
  const bits: string[] = [];
  if (added > 0) bits.push(`+${added} added`);
  if (removed > 0) bits.push(`-${removed} removed`);
  return bits.join(", ");
}

// ---------------------------------------------------------------------------
// movement
// ---------------------------------------------------------------------------

const causeColumns: readonly Column<CauseBreakdown>[] = [
  { header: "Cause", width: 0.26, value: (r) => r.label },
  { header: "Count", width: 0.08, align: "right", value: (r) => fmt(r.count) },
  // The widest column in the report. Every row here is a sentence that stops a number from
  // being misread, so it is the last thing that should be truncated to fit.
  { header: "What it means", width: 0.66, value: (r) => r.meaning },
];

function movementSection(ctx: Layout, view: MonthlyReportView): void {
  if (!view.delta) {
    ctx.heading(
      "What changed",
      "Nothing to compare against yet: this is the first report in the series.",
    );
    ctx.emptyNote(
      "Movement will appear from the next report onwards, once there is a previous month to diff against.",
    );
    return;
  }

  ctx.heading(
    "What changed, and why",
    "Findings are matched against the vulnerability database as it stands today. A count that fell can mean the estate improved or that an advisory changed, and those deserve different responses — so each is attributed separately.",
  );

  ctx.paragraph("Findings resolved", { size: 9.5 });
  ctx.gap(4);
  table(ctx, causeColumns, view.resolvedByCause);

  ctx.paragraph("Findings introduced", { size: 9.5 });
  ctx.gap(4);
  table(ctx, causeColumns, view.introducedByCause);

  if (view.headline.reintroduced > 0) {
    ctx.paragraph(
      `${fmt(view.headline.reintroduced)} of the findings introduced this period had been resolved in an earlier period and have returned. These are counted within the introduced figure above, not in addition to it. A recurrence usually means a dependency was pinned back or a base image was rolled back, and is worth a different conversation from a first occurrence.`,
      { color: COLOR.muted },
    );
    ctx.gap(10);
  }
}

// ---------------------------------------------------------------------------
// severity
// ---------------------------------------------------------------------------

function severitySection(ctx: Layout, view: MonthlyReportView): void {
  if (view.severityMovement.length === 0) return;

  ctx.heading(
    "Severity",
    view.comparable
      ? "Open findings by severity, against the same point last month. Severities are as published in the vulnerability database; they describe the flaw, not this organisation's exposure to it."
      : "Open findings by severity. Severities are as published in the vulnerability database; they describe the flaw, not this organisation's exposure to it.",
  );

  const columns: readonly Column<SeverityMovement>[] = view.comparable
    ? [
        {
          header: "Severity",
          width: 0.3,
          value: (r) => SEVERITY_LABELS[r.severity] ?? r.severity,
        },
        { header: "Now", width: 0.18, align: "right", value: (r) => fmt(r.now) },
        { header: "Last report", width: 0.22, align: "right", value: (r) => fmt(r.before ?? 0) },
        { header: "Change", width: 0.3, align: "right", value: (r) => signed(r.change ?? 0) },
      ]
    : [
        {
          header: "Severity",
          width: 0.6,
          value: (r) => SEVERITY_LABELS[r.severity] ?? r.severity,
        },
        { header: "Open findings", width: 0.4, align: "right", value: (r) => fmt(r.now) },
      ];

  table(ctx, columns, view.severityMovement);
}

// ---------------------------------------------------------------------------
// estate
// ---------------------------------------------------------------------------

function estateSection(ctx: Layout, view: MonthlyReportView): void {
  ctx.heading(
    "Applications and dependencies",
    "Movement in what the platform tracks. A dependency is one package in one application, so the same library used by five applications counts five times.",
  );

  const { dependencyMovement: deps } = view;
  statRow(
    ctx,
    view.comparable
      ? [
          {
            label: "Dependencies tracked",
            value: fmt(deps.total),
            note: describeChange(deps.total - (deps.previousTotal ?? 0)),
          },
          { label: "Added", value: fmt(deps.added), note: "new application/package pairs" },
          { label: "Removed", value: fmt(deps.removed), note: "pairs no longer present" },
        ]
      : [
          {
            label: "Dependencies tracked",
            value: fmt(deps.total),
            note: "application/package pairs",
          },
          { label: "Applications", value: fmt(view.headline.applications), note: "tracked" },
          {
            label: "Vulnerable packages",
            value: fmt(view.widestPackages.length),
            note: "distinct name and version",
          },
        ],
  );

  if (view.applicationsAdded.length > 0) {
    ctx.paragraph(
      `Applications added: ${view.applicationsAdded.map((a) => a.name).join(", ")}.`,
    );
    ctx.gap(4);
  }
  if (view.applicationsRemoved.length > 0) {
    ctx.paragraph(
      `Applications no longer tracked: ${view.applicationsRemoved.map((a) => a.name).join(", ")}. Their findings are reported as resolved by removal above rather than as fixes.`,
    );
    ctx.gap(4);
  }
  if (view.applicationsAdded.length === 0 && view.applicationsRemoved.length === 0) {
    ctx.emptyNote("No applications were added or removed this period.");
  }
  ctx.gap(8);
}

// ---------------------------------------------------------------------------
// where the risk is
// ---------------------------------------------------------------------------

function applicationSection(ctx: Layout, view: MonthlyReportView): void {
  ctx.heading(
    "Where the risk sits",
    "Applications ordered by critical and high findings. Base-image findings are shown separately: they are fixed by rebuilding on a newer image, usually once for many applications, rather than by the team that owns the application.",
  );

  if (view.riskiestApplications.length === 0) {
    ctx.emptyNote("No application currently carries an open finding.");
    return;
  }

  const columns: readonly Column<ApplicationRisk>[] = [
    { header: "Application", width: view.comparable ? 0.32 : 0.44, value: (r) => r.name },
    { header: "Critical", width: 0.11, align: "right", value: (r) => fmt(r.critical) },
    { header: "High", width: 0.1, align: "right", value: (r) => fmt(r.high) },
    { header: "Dependencies", width: 0.16, align: "right", value: (r) => fmt(r.appFindings) },
    { header: "Base image", width: 0.16, align: "right", value: (r) => fmt(r.baseFindings) },
    // Only with a baseline. Without one every row would read "new", which says nothing
    // about the application and everything about the report being the first.
    ...(view.comparable
      ? [
          {
            header: "Change",
            width: 0.15,
            align: "right" as const,
            value: (r: ApplicationRisk) => (r.change === null ? "new" : signed(r.change)),
          },
        ]
      : []),
  ];

  table(ctx, columns, view.riskiestApplications.slice(0, 25));
}

function packageSection(ctx: Layout, view: MonthlyReportView): void {
  ctx.heading(
    "Packages affecting the most applications",
    "Ordered by how many applications each package puts at risk at once, because that is what decides which single upgrade is worth the most. A package listed against several applications is usually one fix, not several.",
  );

  if (view.widestPackages.length === 0) {
    ctx.emptyNote("No vulnerable package is currently present in any application.");
    return;
  }

  const columns: readonly Column<PackageExposure>[] = [
    { header: "Package", width: 0.27, value: (r) => r.name },
    { header: "Version", width: 0.19, mono: true, value: (r) => r.version ?? "—" },
    { header: "Source", width: 0.14, value: (r) => (r.scope === "os" ? "Base image" : "Dependency") },
    { header: "Applications", width: 0.14, align: "right", value: (r) => fmt(r.applications) },
    { header: "Findings", width: 0.13, align: "right", value: (r) => fmt(r.findings) },
    {
      header: "Worst",
      width: 0.13,
      align: "right",
      value: (r) => SEVERITY_LABELS[r.worstSeverity] ?? r.worstSeverity,
    },
  ];

  table(ctx, columns, view.widestPackages.slice(0, 25));
}

// ---------------------------------------------------------------------------
// detail
// ---------------------------------------------------------------------------

const NEW_FINDING_LIMIT = 40;

function newFindingsSection(ctx: Layout, view: MonthlyReportView): void {
  if (!view.delta) return;

  ctx.heading(
    "Findings introduced this period",
    "Worst first. This is the list to act on: everything here appeared since the last report.",
  );

  if (view.newFindings.length === 0) {
    ctx.emptyNote("No new findings appeared this period.");
    return;
  }

  const columns: readonly Column<(typeof view.newFindings)[number]>[] = [
    { header: "Severity", width: 0.11, value: (r) => SEVERITY_LABELS[r.severity] ?? r.severity },
    { header: "Application", width: 0.22, value: (r) => r.applicationName },
    { header: "Package", width: 0.24, value: (r) => r.package },
    { header: "Advisory", width: 0.18, mono: true, value: (r) => r.vulnerabilityId },
    { header: "Why it appeared", width: 0.25, value: (r) => r.cause },
  ];

  table(ctx, columns, view.newFindings.slice(0, NEW_FINDING_LIMIT));

  if (view.newFindings.length > NEW_FINDING_LIMIT) {
    // Stated rather than silently truncated: a reader who counts the rows and compares them
    // to the headline figure must not conclude the report contradicts itself.
    ctx.paragraph(
      `Showing the ${NEW_FINDING_LIMIT} most severe of ${fmt(view.newFindings.length)} findings introduced this period. The full list is available in the platform.`,
      { color: COLOR.muted, size: 8 },
    );
    ctx.gap(8);
  }
}

function methodologySection(ctx: Layout, view: MonthlyReportView): void {
  ctx.heading("How to read this report");

  const notes: string[] = [
    "Figures cover every application the platform tracks, using each application's most recent build. An application that was not rebuilt this period still appears, with the findings from the build it last submitted.",
    "A finding is one vulnerability in one package in one application. The same vulnerability in a package shared by five applications counts five times, because it has to be resolved in five places — unless the package comes from a shared base image, in which case one rebuild resolves all five.",
    "Comparison is against the previous monthly report, not against a fixed date. Reports generated on demand between monthly reports do not move that comparison point.",
  ];

  if (view.run.vulnDbBuiltAt) {
    notes.push(
      `Findings were matched against the vulnerability database built ${fmtDate(view.run.vulnDbBuiltAt)}. Advisories published after that date are not reflected here.`,
    );
  } else {
    notes.push(
      "No vulnerability database build date was recorded for this report, which means vulnerability scanning was not active. Treat the finding counts as incomplete.",
    );
  }

  if (view.delta) {
    notes.push(
      `The previous report counted ${fmt(view.delta.findings.previousTotal)} findings against a database built ${fmtDate(view.delta.baselineDbBuiltAt)}.`,
    );
  }

  for (const note of notes) {
    ctx.paragraph(`•  ${note}`, { size: 8, color: COLOR.muted });
    ctx.gap(4);
  }
}
