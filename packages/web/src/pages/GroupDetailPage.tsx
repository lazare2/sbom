import { Link, useParams } from "react-router";
import { groupAdvisorySort, sortDirections } from "@sbom/shared";
import type { VulnSeverity } from "@sbom/shared";
import { vulnSeverities } from "@sbom/shared";
import {
  SeverityBadge,
  SeverityCountsInline,
} from "../components/Severity.tsx";
import { useGroup, useGroupAdvisories, useVulnStatus } from "../lib/queries.ts";
import { useServerSort } from "../lib/useSort.ts";
import {
  readEnum,
  readNumber,
  readString,
  useUrlState,
} from "../lib/useUrlState.ts";
import { formatNumber, formatRelative } from "../lib/format.ts";
import {
  Badge,
  Card,
  CardHeader,
  EmptyState,
  ErrorBanner,
  Field,
  LoadingBlock,
  Pagination,
  PageHeader,
  Select,
  StatusBadge,
  Table,
  TableWrap,
  Td,
  Th,
  Tr,
} from "../components/ui.tsx";

const DEFAULTS = {
  severity: "",
  sortBy: groupAdvisorySort.defaultField,
  sortDir: groupAdvisorySort.defaultDirection,
  page: 1,
};

const urlSpec = {
  defaults: DEFAULTS,
  parse: (params: URLSearchParams) => ({
    severity: readString(params, "severity"),
    sortBy: readEnum(
      params,
      "sortBy",
      groupAdvisorySort.fields,
      groupAdvisorySort.defaultField,
    ),
    sortDir: readEnum(
      params,
      "sortDir",
      sortDirections,
      groupAdvisorySort.defaultDirection,
    ),
    page: readNumber(params, "page", 1),
  }),
};

/**
 * One group: what is in it, and what it is exposed to.
 *
 * The page is built around a single question the applications list cannot answer — "is this
 * advisory everywhere in the product, or in one corner of it". A CVE in one of eight images is
 * a rebuild; the same CVE in eight of eight is a base image nobody has updated. Severity does
 * not distinguish those, so the member spread is given its own column rather than being left
 * to be worked out by opening each application.
 */
export function GroupDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { state, setState } = useUrlState(urlSpec);
  const { data: group, isLoading, error, refetch } = useGroup(id);

  const vulnStatus = useVulnStatus();
  const showAdvisories = vulnStatus.data?.enabled === true;

  const advisories = useGroupAdvisories(showAdvisories ? id : undefined, {
    severity: state.severity || undefined,
    sortBy: state.sortBy,
    sortDir: state.sortDir,
    page: state.page,
    pageSize: 50,
  });

  const sort = useServerSort(groupAdvisorySort, state, setState);

  if (error) return <ErrorBanner error={error} onRetry={refetch} />;
  if (isLoading || !group) return <LoadingBlock />;

  const counts = group.vulnerabilities;

  return (
    <>
      <div className="mb-1">
        <Link
          to="/groups"
          className="text-xs text-text-muted hover:text-accent hover:underline"
        >
          ← Groups
        </Link>
      </div>
      <PageHeader
        title={group.name}
        subtitle={group.description ?? undefined}
      />

      <div className="mb-4 grid gap-3 md:grid-cols-2">
        <Card>
          <CardHeader title="Membership" />
          <dl className="grid grid-cols-2 gap-4 p-4">
            <Field label="Applications">
              {formatNumber(group.applicationCount)}
            </Field>
            <Field label="Assessed">
              {counts ? (
                <>
                  {formatNumber(counts.assessedApplicationCount)}
                  <span className="ml-1 text-[11px] text-text-faint">
                    of {formatNumber(group.applicationCount)}
                  </span>
                </>
              ) : (
                <span className="text-text-faint">—</span>
              )}
            </Field>
          </dl>
          <div className="border-t border-border-base px-4 pb-3">
            <Link
              to={`/applications?group=${group.id}`}
              className="text-xs text-accent hover:underline"
            >
              Open these in the applications list →
            </Link>
          </div>
        </Card>

        {showAdvisories ? (
          <Card>
            {/*
              The subtitle is on the card rather than in a tooltip on purpose. This number is
              deliberately not the dashboard's for the same applications, and a reader with
              both open needs the reason on screen, not on hover.
            */}
            <CardHeader
              title="Advisories"
              subtitle="Each advisory counted once, however many members carry it."
            />
            {counts === null ? (
              <p className="p-4 text-sm text-text-faint">
                No member has a build that has been matched against the
                vulnerability database yet. That is not the same as having no
                advisories.
              </p>
            ) : (
              <div className="p-4">
                <p className="nums text-2xl font-semibold text-text-base">
                  {formatNumber(counts.advisories)}
                </p>
                <p className="mt-1 text-xs text-text-muted">
                  affecting {formatNumber(counts.affectedApplicationCount)} of{" "}
                  {formatNumber(counts.assessedApplicationCount)} assessed
                  applications
                </p>
                <div className="mt-3">
                  <SeverityCountsInline counts={counts.bySeverity} />
                </div>
              </div>
            )}
          </Card>
        ) : null}
      </div>

      <Card className="mb-4">
        <CardHeader title="Applications in this group" />
        {group.members.length === 0 ? (
          <EmptyState
            title="No applications yet"
            hint="An admin can add applications to this group under Admin → Groups."
          />
        ) : (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Application</Th>
                  <Th width="140px">Status</Th>
                  {showAdvisories ? (
                    <Th align="right" width="120px">
                      Advisories
                    </Th>
                  ) : null}
                  <Th width="150px">Last scan</Th>
                </tr>
              </thead>
              <tbody>
                {group.members.map((member) => (
                  <Tr key={member.id}>
                    <Td>
                      <Link
                        to={`/applications/${member.id}`}
                        className="font-medium text-accent hover:underline"
                      >
                        {member.name}
                      </Link>
                    </Td>
                    <Td>
                      <StatusBadge status={member.status} />
                    </Td>
                    {showAdvisories ? (
                      <Td align="right" className="nums text-text-muted">
                        {member.advisories === null ? (
                          <span
                            className="text-[11px] text-text-faint"
                            title="This build has not been matched against the vulnerability database yet."
                          >
                            not assessed
                          </span>
                        ) : (
                          formatNumber(member.advisories)
                        )}
                      </Td>
                    ) : null}
                    <Td className="text-text-muted">
                      {member.lastScanAt ? (
                        formatRelative(member.lastScanAt)
                      ) : (
                        <span className="text-text-faint">never</span>
                      )}
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>

      {showAdvisories ? (
        <Card>
          <CardHeader title="Advisories across this group" />
          <div className="border-b border-border-base p-3">
            <div className="max-w-[200px]">
              <label
                htmlFor="g-severity"
                className="mb-1 block text-[11px] font-medium text-text-muted"
              >
                Severity
              </label>
              <Select
                id="g-severity"
                value={state.severity}
                onChange={(value) => setState({ severity: value, page: 1 })}
                options={[
                  { value: "", label: "Any" },
                  ...vulnSeverities.map((s) => ({ value: s, label: s })),
                ]}
              />
            </div>
          </div>
          {advisories.error ? (
            <ErrorBanner
              error={advisories.error}
              onRetry={advisories.refetch}
            />
          ) : advisories.isLoading ? (
            <LoadingBlock />
          ) : !advisories.data || advisories.data.items.length === 0 ? (
            <EmptyState
              title="No advisories"
              hint="Nothing matched for the members of this group."
            />
          ) : (
            <>
              <TableWrap>
                <Table>
                  <thead>
                    <tr>
                      <Th
                        onSort={() => sort.toggle("vulnerabilityId")}
                        sorted={sort.stateOf("vulnerabilityId")}
                      >
                        Advisory
                      </Th>
                      <Th
                        onSort={() => sort.toggle("severity")}
                        sorted={sort.stateOf("severity")}
                        width="110px"
                      >
                        Severity
                      </Th>
                      <Th
                        onSort={() => sort.toggle("affectedMembers")}
                        sorted={sort.stateOf("affectedMembers")}
                        align="right"
                        width="150px"
                      >
                        Members affected
                      </Th>
                      <Th align="right" width="110px">
                        Packages
                      </Th>
                      <Th width="90px">Fixable</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {advisories.data.items.map((advisory) => (
                      <Tr key={advisory.vulnerabilityId}>
                        <Td>
                          <Link
                            to={`/vulnerabilities/${advisory.vulnerabilityId}`}
                            className="font-mono text-xs text-accent hover:underline"
                          >
                            {advisory.vulnerabilityId}
                          </Link>
                        </Td>
                        <Td>
                          <SeverityBadge
                            severity={advisory.severity as VulnSeverity}
                          />
                        </Td>
                        <Td align="right" className="nums">
                          {formatNumber(advisory.affectedMembers)}
                          <span className="ml-1 text-[11px] text-text-faint">
                            of{" "}
                            {formatNumber(
                              counts?.assessedApplicationCount ?? 0,
                            )}
                          </span>
                        </Td>
                        <Td align="right" className="nums text-text-muted">
                          {formatNumber(advisory.affectedPackages)}
                        </Td>
                        <Td>
                          {advisory.fixable ? (
                            <Badge tone="ok">Fix available</Badge>
                          ) : (
                            <span className="text-[11px] text-text-faint">
                              —
                            </span>
                          )}
                        </Td>
                      </Tr>
                    ))}
                  </tbody>
                </Table>
              </TableWrap>
              <Pagination
                page={advisories.data.page}
                pageSize={advisories.data.pageSize}
                total={advisories.data.total}
                totalPages={advisories.data.totalPages}
                onPageChange={(page) => setState({ page })}
                isFetching={advisories.isFetching}
              />
            </>
          )}
        </Card>
      ) : null}
    </>
  );
}
