import { Link } from "react-router";
import { Badge, Card, CardHeader, EmptyState, ErrorBanner, LoadingBlock, PageHeader, Table, TableWrap, Td, Th, Tr } from "../components/ui.tsx";
import { ProjectStatusBadge } from "../components/ActionPlan.tsx";
import { formatRelative } from "../lib/format.ts";
import { useMyProjects } from "../lib/queries.ts";

/**
 * My projects: the projects a person reaches through their squads and direct grants, the urgent
 * ones first, each with a status in words and always the reason. Developers land here.
 */
export function MyProjectsPage() {
  const { data, isLoading, error, refetch } = useMyProjects();

  return (
    <>
      <PageHeader
        title="My projects"
        subtitle="The projects of your squads and the ones granted to you, most urgent first. Open one for its action plan."
      />
      {isLoading ? <LoadingBlock /> : null}
      {error ? <ErrorBanner error={error} onRetry={() => void refetch()} /> : null}
      {data && data.projects.length === 0 ? (
        <Card>
          <EmptyState
            title={data.hasMembership ? "No projects in this environment" : "You have no projects yet"}
            hint={
              data.hasMembership ? (
                "Your squads have no projects in the environment selected at the top. Try another environment."
              ) : (
                <>
                  You are not on a squad and no project is granted to you. Ask an administrator to add you to your
                  squad. Meanwhile, <Link to="/applications" className="text-accent hover:underline">all applications</Link>{" "}
                  you may see are listed under Applications.
                </>
              )
            }
          />
        </Card>
      ) : null}
      {data && data.projects.length > 0 ? (
        <Card>
          <CardHeader
            title={`${data.projects.length} ${data.projects.length === 1 ? "project" : "projects"}`}
            subtitle={summaryLine(data.projects.map((p) => p.status))}
          />
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th width="140px">Status</Th>
                  <Th width="240px">Project</Th>
                  <Th>Why</Th>
                  <Th width="140px">Last build</Th>
                  <Th width="200px">Through</Th>
                </tr>
              </thead>
              <tbody>
                {data.projects.map((p) => (
                  <Tr key={p.applicationId}>
                    <Td>
                      <ProjectStatusBadge status={p.status} />
                    </Td>
                    <Td>
                      <Link to={`/applications/${p.applicationId}`} className="font-medium text-accent hover:underline">
                        {p.name}
                      </Link>
                    </Td>
                    <Td className="text-sm text-text-muted">
                      {p.reason}
                      {p.counts.newSinceVisit > 0 ? (
                        <span className="ml-2">
                          <Badge tone="info" title="Vulnerabilities that appeared after your previous visit to this project.">
                            {p.counts.newSinceVisit} new
                          </Badge>
                        </span>
                      ) : null}
                    </Td>
                    <Td className="text-sm text-text-muted">{p.lastBuildAt ? formatRelative(p.lastBuildAt) : "never"}</Td>
                    <Td className="text-xs text-text-muted">{p.via.join(", ")}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        </Card>
      ) : null}
    </>
  );
}

function summaryLine(statuses: string[]): string {
  const n = (s: string) => statuses.filter((x) => x === s).length;
  const parts = [
    [n("fix-now"), "to fix now"],
    [n("fix-soon"), "to fix soon"],
    [n("no-recent-build"), "without a recent build"],
    [n("nothing-to-do"), "with nothing to do"],
  ]
    .filter(([count]) => (count as number) > 0)
    .map(([count, label]) => `${count} ${label}`);
  return parts.join(" · ");
}
