import { Link } from "react-router";
import { PROJECT_STATUS_LABELS, projectStatuses, type MyProject, type MyTeam, type TeamAcceptedRisk, type TeamLateAction } from "@sbom/shared";
import { ProjectStatusBadge } from "../components/ActionPlan.tsx";
import { ExportTableButton, type ExportColumn } from "../components/ExportTable.tsx";
import { Badge, Card, CardHeader, EmptyState, ErrorBanner, LoadingBlock, PageHeader, Table, TableWrap, Td, Th, Tr } from "../components/ui.tsx";
import { withEnvironment } from "../lib/api.ts";
import { formatRelative } from "../lib/format.ts";
import { useMyTeams } from "../lib/queries.ts";

const date = (iso: string | null) =>
  iso ? new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "";

const PROJECT_COLUMNS: ExportColumn<MyProject>[] = [
  { header: "Status", value: (p) => PROJECT_STATUS_LABELS[p.status], width: 16 },
  { header: "Project", value: (p) => p.name, width: 28 },
  { header: "Why", value: (p) => p.reason, width: 70 },
  { header: "Vulnerabilities past target", value: (p) => p.counts.late, width: 14 },
  { header: "Fix now", value: (p) => p.counts.now, width: 8 },
  { header: "Fix soon", value: (p) => p.counts.soon, width: 8 },
  { header: "Vulnerabilities", value: (p) => p.counts.total, width: 12 },
  { header: "Last build", value: (p) => p.lastBuildAt, width: 20 },
];
const LATE_COLUMNS: ExportColumn<TeamLateAction>[] = [
  { header: "Project", value: (a) => a.applicationName, width: 28 },
  { header: "Action", value: (a) => a.title, width: 60 },
  { header: "Was due", value: (a) => a.dueAt, width: 20 },
  { header: "Rule", value: (a) => a.dueRule, width: 40 },
  { header: "Clears", value: (a) => a.clears, width: 8 },
];
const RISK_COLUMNS: ExportColumn<TeamAcceptedRisk>[] = [
  { header: "Ends", value: (r) => r.expiresAt ?? "no end date", width: 20 },
  { header: "Advisory", value: (r) => r.vulnerabilityId, width: 22 },
  { header: "Project", value: (r) => r.applicationName, width: 28 },
  { header: "Package", value: (r) => r.packageLabel ?? "every package", width: 30 },
  { header: "Why", value: (r) => r.reason, width: 60 },
  { header: "Accepted by", value: (r) => r.acceptedBy, width: 30 },
];

/**
 * My teams: the squads a team lead leads, each with its projects by status, late actions,
 * accepted risks (those ending soon first) and the last four weeks. Team leads land here.
 */
export function MyTeamsPage() {
  const { data, isLoading, error, refetch } = useMyTeams();
  return (
    <>
      <PageHeader
        title="My teams"
        subtitle={
          data?.viewAs === "admin"
            ? "Every squad: you lead none, and as an administrator you see them all."
            : "The squads you lead. The numbers are the same as on each project's page."
        }
        actions={
          data && data.teams.length > 0 ? (
            <a href={withEnvironment("/api/v1/my-teams/pdf")} className="rounded-md border border-border-strong bg-bg-raised px-3 py-1.5 text-sm font-medium text-text-base hover:bg-bg-subtle">
              Download PDF
            </a>
          ) : null
        }
      />
      {isLoading ? <LoadingBlock /> : null}
      {error ? <ErrorBanner error={error} onRetry={() => void refetch()} /> : null}
      {data && data.teams.length === 0 ? (
        <Card>
          <EmptyState title="You lead no squad" hint="An administrator marks team leads under Administration → Access → Squads." />
        </Card>
      ) : null}
      <div className="space-y-6">
        {data?.teams.map((team) => <TeamSection key={team.squadId} team={team} />)}
      </div>
    </>
  );
}

function TeamSection({ team }: { team: MyTeam }) {
  const soon = team.acceptedRisks.filter((r) => r.endingSoon).length;
  return (
    <section className="space-y-3">
      <h2 className="text-lg font-semibold text-text-base">Squad {team.name}</h2>
      <div className="grid gap-3 sm:grid-cols-5">
        {projectStatuses.map((s) => (
          <Card key={s} className="p-3">
            <div className="text-[11px] font-semibold tracking-wide text-text-faint uppercase">{PROJECT_STATUS_LABELS[s]}</div>
            <div className="nums mt-1 text-2xl font-semibold text-text-base">{team.statusCounts[s]}</div>
          </Card>
        ))}
        <Card className="p-3">
          <div className="text-[11px] font-semibold tracking-wide text-text-faint uppercase">Late actions</div>
          <div className={`nums mt-1 text-2xl font-semibold ${team.lateActions.length > 0 ? "text-danger" : "text-text-base"}`}>
            {team.lateActions.length}
          </div>
        </Card>
      </div>

      <Card>
        <CardHeader
          title="Projects"
          subtitle="Most urgent first. Open one for its action plan."
          actions={<ExportTableButton title={`Squad ${team.name}: projects`} filename={`squad-${team.name}-projects`} columns={PROJECT_COLUMNS} rows={team.projects} />}
        />
        {team.projects.length === 0 ? (
          <EmptyState title="No projects in this environment" />
        ) : (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th width="140px">Status</Th>
                  <Th width="220px">Project</Th>
                  <Th>Why</Th>
                  <Th width="150px" align="right">Vulnerabilities past target</Th>
                  <Th width="130px">Last build</Th>
                </tr>
              </thead>
              <tbody>
                {team.projects.map((p) => (
                  <Tr key={p.applicationId}>
                    <Td><ProjectStatusBadge status={p.status} /></Td>
                    <Td>
                      <Link to={`/applications/${p.applicationId}`} className="font-medium text-accent hover:underline">{p.name}</Link>
                    </Td>
                    <Td className="text-sm text-text-muted">{p.reason}</Td>
                    <Td align="right" className={`nums ${p.counts.late > 0 ? "font-medium text-danger" : "text-text-muted"}`}>{p.counts.late}</Td>
                    <Td className="text-sm text-text-muted">{p.lastBuildAt ? formatRelative(p.lastBuildAt) : "never"}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader
            title={`Late actions (${team.lateActions.length})`}
            subtitle="Past their target date, earliest due first."
            actions={team.lateActions.length > 0 ? <ExportTableButton title={`Squad ${team.name}: late actions`} filename={`squad-${team.name}-late`} columns={LATE_COLUMNS} rows={team.lateActions} /> : null}
          />
          {team.lateActions.length === 0 ? (
            <EmptyState title="Nothing late" />
          ) : (
            <ul className="divide-y divide-border-base">
              {team.lateActions.map((a, i) => (
                <li key={`${a.applicationId}:${i}`} className="px-4 py-2 text-sm">
                  <Link to={`/applications/${a.applicationId}`} className="font-medium text-accent hover:underline">{a.applicationName}</Link>
                  <span className="text-text-base">: {a.title}</span>
                  <div className="text-xs text-danger">Was due {date(a.dueAt)} ({a.dueRule})</div>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader
            title={`Accepted risks (${team.acceptedRisks.length})`}
            subtitle={soon > 0 ? `${soon} ending within 14 days.` : "In force on these projects, ending soonest first."}
            actions={team.acceptedRisks.length > 0 ? <ExportTableButton title={`Squad ${team.name}: accepted risks`} filename={`squad-${team.name}-accepted-risks`} columns={RISK_COLUMNS} rows={team.acceptedRisks} /> : null}
          />
          {team.acceptedRisks.length === 0 ? (
            <EmptyState title="No accepted risks" />
          ) : (
            <ul className="divide-y divide-border-base">
              {team.acceptedRisks.map((r) => (
                <li key={r.id} className="px-4 py-2 text-sm">
                  <span className="font-mono text-xs">{r.vulnerabilityId}</span> in{" "}
                  <Link to={`/applications/${r.applicationId}`} className="text-accent hover:underline">{r.applicationName}</Link>
                  {r.packageLabel ? <span className="text-text-muted"> ({r.packageLabel})</span> : null}
                  {r.endingSoon ? <span className="ml-2"><Badge tone="warn">ends soon</Badge></span> : null}
                  <div className="text-xs text-text-muted">
                    {r.expiresAt ? `Until ${date(r.expiresAt)}` : "No end date"} · {r.reason}
                    {r.acceptedBy ? ` · ${r.acceptedBy}` : ""}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card>
        <CardHeader
          title="Last four weeks"
          subtitle="Critical and high in the build each project had at the end of each week, as known today. Accepted risks left out."
        />
        <TableWrap>
          <Table>
            <thead>
              <tr>
                <Th>Week ending</Th>
                <Th align="right">Critical</Th>
                <Th align="right">High</Th>
                <Th align="right">Projects with a build</Th>
              </tr>
            </thead>
            <tbody>
              {team.trend.map((t, i) => {
                const prev = team.trend[i - 1];
                const delta = prev ? t.critical + t.high - (prev.critical + prev.high) : null;
                return (
                  <Tr key={t.weekEnding}>
                    <Td>{i === team.trend.length - 1 ? "Now" : date(t.weekEnding)}</Td>
                    <Td align="right" className="nums">{t.critical}</Td>
                    <Td align="right" className="nums">
                      {t.high}
                      {delta !== null && delta !== 0 ? (
                        <span className={`ml-2 text-xs ${delta < 0 ? "text-ok" : "text-danger"}`}>{delta > 0 ? `+${delta}` : delta} total</span>
                      ) : null}
                    </Td>
                    <Td align="right" className="nums text-text-muted">{t.projectsCounted}</Td>
                  </Tr>
                );
              })}
            </tbody>
          </Table>
        </TableWrap>
      </Card>
    </section>
  );
}
