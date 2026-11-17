import PDFDocument from "pdfkit";
import { PROJECT_STATUS_LABELS, type MyTeamsResponse } from "@sbom/shared";
import { COLOR, CONTENT_WIDTH, Layout, MARGIN, PAGE, fmtDate, stampFooters, statRow, table } from "../reports/pdf-layout.js";

/**
 * My teams as a PDF: per squad the status counts, the projects with their reasons, late actions,
 * accepted risks and the four-week trend. The same numbers as the page, in the same order.
 */
export async function renderTeamsPdf(report: MyTeamsResponse, title = "My teams"): Promise<Buffer> {
  const doc = new PDFDocument({
    size: [PAGE.width, PAGE.height],
    margin: MARGIN,
    info: { Title: title, Author: "SBOM Platform", CreationDate: new Date(report.generatedAt) },
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

  doc.font("Helvetica-Bold").fontSize(18).fillColor(COLOR.text).text(title, MARGIN, MARGIN, { width: CONTENT_WIDTH });
  doc
    .font("Helvetica")
    .fontSize(8.5)
    .fillColor(COLOR.muted)
    .text(
      `${report.viewAs === "lead" ? "The squads you lead" : "Every squad"} · generated ${fmtDate(report.generatedAt)}. ` +
        "Statuses: Fix now = a fix is available and it is used in real attacks, or it is critical and remote; " +
        "Fix soon = other critical or high with a fix. Accepted risks are left out of every number.",
      { width: CONTENT_WIDTH },
    );
  ctx.gap(12);

  if (report.teams.length === 0) ctx.paragraph("You lead no squad.");

  for (const team of report.teams) {
    ctx.heading(`Squad ${team.name}`, `${team.projects.length} projects`);
    statRow(ctx, [
      { label: "Fix now", value: String(team.statusCounts["fix-now"]), tone: team.statusCounts["fix-now"] > 0 ? "warn" : "ok" },
      { label: "Fix soon", value: String(team.statusCounts["fix-soon"]) },
      { label: "No recent build", value: String(team.statusCounts["no-recent-build"]) },
      { label: "Nothing to do", value: String(team.statusCounts["nothing-to-do"]) },
      { label: "Late actions", value: String(team.lateActions.length), tone: team.lateActions.length > 0 ? "warn" : "ok" },
    ]);

    table(
      ctx,
      [
        { header: "Status", width: 0.14, value: (p) => PROJECT_STATUS_LABELS[p.status] },
        { header: "Project", width: 0.22, value: (p) => p.name },
        { header: "Why", width: 0.46, value: (p) => p.reason },
        { header: "Past target", width: 0.1, align: "right", value: (p) => String(p.counts.late) },
        { header: "Last build", width: 0.08, value: (p) => fmtDate(p.lastBuildAt) },
      ],
      team.projects,
    );
    ctx.gap(8);

    if (team.lateActions.length > 0) {
      ctx.heading("Late actions", "Past their target date, earliest due first.");
      table(
        ctx,
        [
          { header: "Project", width: 0.2, value: (a) => a.applicationName },
          { header: "Action", width: 0.46, value: (a) => a.title },
          { header: "Was due", width: 0.12, value: (a) => fmtDate(a.dueAt) },
          { header: "Rule", width: 0.22, value: (a) => a.dueRule },
        ],
        team.lateActions,
      );
      ctx.gap(8);
    }

    ctx.heading("Accepted risks", "Still in force, ending soonest first. * ends within 14 days.");
    if (team.acceptedRisks.length === 0) ctx.paragraph("None.");
    else
      table(
        ctx,
        [
          { header: "Ends", width: 0.12, value: (r) => (r.expiresAt ? `${fmtDate(r.expiresAt)}${r.endingSoon ? " *" : ""}` : "no end date") },
          { header: "Advisory", width: 0.18, value: (r) => r.vulnerabilityId, mono: true },
          { header: "Project", width: 0.18, value: (r) => r.applicationName },
          { header: "Why", width: 0.36, value: (r) => r.reason },
          { header: "By", width: 0.16, value: (r) => r.acceptedBy ?? "" },
        ],
        team.acceptedRisks,
      );
    ctx.gap(8);

    ctx.heading(
      "Last four weeks",
      "Critical and high in the build each project had at the end of each week, as known today. Accepted risks left out.",
    );
    table(
      ctx,
      [
        { header: "Week ending", width: 0.3, value: (t) => fmtDate(t.weekEnding) },
        { header: "Critical", width: 0.2, align: "right", value: (t) => String(t.critical) },
        { header: "High", width: 0.2, align: "right", value: (t) => String(t.high) },
        { header: "Projects with a build", width: 0.3, align: "right", value: (t) => String(t.projectsCounted) },
      ],
      team.trend,
    );
    ctx.gap(14);
  }

  stampFooters(doc, title, report.generatedAt);
  doc.end();
  return finished;
}
