import { useEffect, useState } from "react";
import { Link } from "react-router";
import { groupSort, sortDirections } from "@sbom/shared";
import { useGroups, useVulnStatus } from "../lib/queries.ts";
import { useServerSort } from "../lib/useSort.ts";
import { useDebounced } from "../lib/useDebounced.ts";
import {
  readEnum,
  readNumber,
  readString,
  useUrlState,
} from "../lib/useUrlState.ts";
import { formatNumber } from "../lib/format.ts";
import { CriticalHighBadges } from "../components/Severity.tsx";
import {
  Card,
  EmptyState,
  ErrorBanner,
  LoadingBlock,
  Pagination,
  PageHeader,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../components/ui.tsx";

const DEFAULTS = {
  search: "",
  sortBy: groupSort.defaultField,
  sortDir: groupSort.defaultDirection,
  page: 1,
};

const urlSpec = {
  defaults: DEFAULTS,
  parse: (params: URLSearchParams) => ({
    search: readString(params, "search"),
    sortBy: readEnum(
      params,
      "sortBy",
      groupSort.fields,
      groupSort.defaultField,
    ),
    sortDir: readEnum(
      params,
      "sortDir",
      sortDirections,
      groupSort.defaultDirection,
    ),
    page: readNumber(params, "page", 1),
  }),
};

/**
 * Named sets of applications, and how exposed each one is.
 *
 * The column reads **advisories**, not findings, and the difference is the reason this page
 * can be compared across rows at all. A group's members almost always share a base image, so
 * summing their findings would count that image once per member — a sixteen-image group would
 * outrank an eight-image one running identical software, and the ranking would be a member
 * count wearing a risk label. Counting each advisory once removes that.
 *
 * It is also why the number here will not match the dashboard's for the same applications.
 * Both are correct: the dashboard counts remediation work, where eight vulnerable images
 * really are eight rebuilds. These two words are kept apart deliberately and must never be
 * shown side by side unlabelled.
 */
export function GroupsPage() {
  const { state, setState } = useUrlState(urlSpec);
  const [searchInput, setSearchInput] = useState(state.search);
  const debouncedSearch = useDebounced(searchInput, 300);

  useEffect(() => {
    if (debouncedSearch !== state.search) setState({ search: debouncedSearch });
  }, [debouncedSearch, state.search, setState]);

  useEffect(() => {
    setSearchInput(state.search);
  }, [state.search]);

  const { data, isLoading, isFetching, error, refetch } = useGroups({
    search: state.search || undefined,
    sortBy: state.sortBy,
    sortDir: state.sortDir,
    page: state.page,
    pageSize: 50,
  });

  /*
    Strict `=== true`, matching the applications list: undefined while the status request is in
    flight would render the column and then remove it, shifting every other column sideways.
  */
  const vulnStatus = useVulnStatus();
  const showAdvisories = vulnStatus.data?.enabled === true;

  const sort = useServerSort(groupSort, state, setState);

  return (
    <>
      <PageHeader
        title="Groups"
        subtitle="Sets of applications that answer a question together — one product built from several images, or a trait that cuts across unrelated services."
      />

      <Card>
        <div className="border-b border-border-base p-3">
          <div className="max-w-[320px]">
            <label
              htmlFor="group-search"
              className="mb-1 block text-[11px] font-medium text-text-muted"
            >
              Search by name
            </label>
            <TextInput
              id="group-search"
              value={searchInput}
              onChange={setSearchInput}
              placeholder="Checkout Platform"
            />
          </div>
        </div>

        {error ? (
          <ErrorBanner error={error} onRetry={refetch} />
        ) : isLoading ? (
          <LoadingBlock />
        ) : !data || data.items.length === 0 ? (
          <EmptyState
            title={
              state.search ? "No groups match that search" : "No groups yet"
            }
            hint={
              state.search
                ? "Try a shorter search term."
                : "An admin can create groups under Admin → Groups, then add applications to them."
            }
          />
        ) : (
          <>
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th
                      onSort={() => sort.toggle("name")}
                      sorted={sort.stateOf("name")}
                    >
                      Group
                    </Th>
                    <Th
                      onSort={() => sort.toggle("applicationCount")}
                      sorted={sort.stateOf("applicationCount")}
                      align="right"
                      width="120px"
                    >
                      Applications
                    </Th>
                    {showAdvisories ? (
                      <Th align="right" width="180px">
                        Advisories
                      </Th>
                    ) : null}
                    <Th
                      onSort={() => sort.toggle("createdAt")}
                      sorted={sort.stateOf("createdAt")}
                      width="140px"
                    >
                      Created
                    </Th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((group) => (
                    <Tr key={group.id}>
                      <Td>
                        <Link
                          to={`/groups/${group.id}`}
                          className="font-medium text-accent hover:underline"
                        >
                          {group.name}
                        </Link>
                        {group.description ? (
                          <p className="mt-0.5 text-[11px] text-text-faint">
                            {group.description}
                          </p>
                        ) : null}
                      </Td>
                      <Td align="right" className="nums text-text-muted">
                        {formatNumber(group.applicationCount)}
                      </Td>
                      {showAdvisories ? (
                        <Td align="right">
                          <AdvisoryCell group={group} />
                        </Td>
                      ) : null}
                      <Td className="text-text-muted">
                        {new Date(group.createdAt).toLocaleDateString()}
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
            <Pagination
              page={data.page}
              pageSize={data.pageSize}
              total={data.total}
              totalPages={data.totalPages}
              onPageChange={(page) => setState({ page })}
              isFetching={isFetching}
            />
          </>
        )}
      </Card>
    </>
  );
}

/**
 * Distinct advisories, with the share of the group they were measured over.
 *
 * The denominator is shown rather than implied. A group of twenty reporting three advisories
 * looks healthy right up until you learn that seventeen of its members have never been
 * scanned, and "3 · across 3 of 20" is the only rendering that makes that visible without
 * opening the group.
 */
function AdvisoryCell({
  group,
}: {
  group: {
    applicationCount: number;
    vulnerabilities: import("@sbom/shared").GroupVulnCounts | null;
  };
}) {
  const counts = group.vulnerabilities;

  if (counts === null) {
    return (
      <span
        className="text-xs text-text-faint"
        title="No member of this group has a build that has been matched against the vulnerability database. This is not the same as having no advisories."
      >
        not assessed
      </span>
    );
  }

  return (
    <div className="flex flex-col items-end gap-0.5">
      <div className="flex items-center gap-1.5">
        <span className="nums font-medium">
          {formatNumber(counts.advisories)}
        </span>
        <CriticalHighBadges
          critical={counts.bySeverity.critical}
          high={counts.bySeverity.high}
        />
      </div>
      <span className="nums text-[11px] text-text-faint">
        {counts.advisories === 0
          ? `clean · ${counts.assessedApplicationCount} of ${group.applicationCount} assessed`
          : `${counts.affectedApplicationCount} of ${counts.assessedApplicationCount} affected`}
      </span>
    </div>
  );
}
