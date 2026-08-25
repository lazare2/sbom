import { useMemo, useState } from "react";
import { Link } from "react-router";
import {
  MALICIOUS_ACK_LABELS,
  maliciousCorroborations,
  maliciousFindingSort,
  type MaliciousAckState,
  type MaliciousFinding,
  type SortDirection,
} from "@sbom/shared";
import { useAuth } from "../auth/AuthProvider.tsx";
import { useMaliciousFindings, useMaliciousStatus } from "../lib/queries.ts";
import { useServerSort } from "../lib/useSort.ts";
import { readEnum, readNumber, readString, useUrlState } from "../lib/useUrlState.ts";
import { CorroborationBadge } from "../components/CorroborationBadge.tsx";
import { useDebounced } from "../lib/useDebounced.ts";
import { formatDateTime, formatNumber, formatRelative } from "../lib/format.ts";
import { AcknowledgeModal, MaliciousDetailModal } from "../components/MaliciousDetail.tsx";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorBanner,
  LoadingBlock,
  Mono,
  PageHeader,
  Pagination,
  Select,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../components/ui.tsx";

/**
 * Malicious packages found in the estate.
 *
 * Its own page rather than a tab on Vulnerabilities, because the action it asks for is not the
 * one that page is built around. A CVE is fixed by upgrading; this is fixed by removing the
 * package and then rotating every credential the installing machine could read. Sitting these
 * rows among severity buckets and fix versions would frame them as a worse version of the same
 * problem, and the credential rotation -- the part that actually limits the damage -- would be
 * the thing nobody did.
 *
 * ## Why two columns of counts, always
 *
 * `In current builds` and `Ever shipped` are both shown on every row and neither is derivable
 * from the other. The first is what can be removed today. The second is the set of pipelines
 * whose secrets are suspect, and it does not shrink when the package is removed -- the payload
 * already ran. A page showing only the first would tell somebody who deleted the package last
 * week that they were clean, which is the worst thing this platform could say.
 */

const PRESENCE = ["all", "current", "historical"] as const;
/** "" means every tier. Kept out of `maliciousCorroborations` so the URL default is empty. */
const CORROBORATION = ["", ...maliciousCorroborations] as const;
const DIRECTIONS = ["asc", "desc"] as const;

const spec = {
  defaults: {
    q: "",
    presence: "all" as (typeof PRESENCE)[number],
    corroboration: "" as (typeof CORROBORATION)[number],
    unacknowledged: "",
    sortBy: maliciousFindingSort.defaultField,
    sortDir: maliciousFindingSort.defaultDirection as SortDirection,
    page: 1,
  },
  parse: (params: URLSearchParams) => ({
    q: readString(params, "q", ""),
    presence: readEnum(params, "presence", PRESENCE, "all"),
    corroboration: readEnum(params, "corroboration", CORROBORATION, ""),
    unacknowledged: readString(params, "unacknowledged", ""),
    sortBy: readEnum(params, "sortBy", maliciousFindingSort.fields, maliciousFindingSort.defaultField),
    sortDir: readEnum(params, "sortDir", DIRECTIONS, maliciousFindingSort.defaultDirection),
    page: readNumber(params, "page", 1),
  }),
};

export function MaliciousPage() {
  const { isAdmin } = useAuth();
  const { state, setState } = useUrlState(spec);
  const [searchInput, setSearchInput] = useState(state.q);
  const debounced = useDebounced(searchInput, 300);
  const [openFinding, setOpenFinding] = useState<string | null>(null);
  const [ackTarget, setAckTarget] = useState<MaliciousFinding | null>(null);

  const status = useMaliciousStatus();
  const enabled = status.data?.enabled === true;

  const params = useMemo(
    () => ({
      search: debounced || undefined,
      presence: state.presence === "all" ? undefined : state.presence,
      corroboration: state.corroboration || undefined,
      unacknowledged: state.unacknowledged === "true" ? "true" : undefined,
      sortBy: state.sortBy,
      sortDir: state.sortDir,
      page: state.page,
      pageSize: 50,
    }),
    [debounced, state],
  );

  const findings = useMaliciousFindings(params, enabled);
  const sort = useServerSort(maliciousFindingSort, state, setState);

  if (status.isLoading) return <LoadingBlock label="Loading malicious package detection" />;

  /*
   * Switched off gets an explanation, never an empty table.
   *
   * An empty findings table is a claim -- "we looked and found nothing" -- and it is the exact
   * claim this state cannot support. The same reasoning the vulnerability pages apply to a
   * disabled scanner.
   */
  if (!enabled) {
    return (
      <>
        <PageHeader
          title="Malicious packages"
          subtitle="Packages published to attack whoever installs them, matched against the OpenSSF malicious-packages feed."
        />
        <Card>
          <EmptyState
            title="Detection is switched off"
            hint={
              isAdmin
                ? "Nothing has been checked, so this page cannot tell you whether the estate is affected. Enable it in Admin → Malicious packages."
                : "Nothing has been checked, so this page cannot tell you whether the estate is affected. An administrator can enable it."
            }
          />
        </Card>
      </>
    );
  }

  /* Enabled but nothing downloaded yet is also not a clean bill of health. */
  if (status.data?.feedBuiltAt === null) {
    return (
      <>
        <PageHeader title="Malicious packages" subtitle="Awaiting the first feed download." />
        <Card>
          <EmptyState
            title="No feed installed yet"
            hint="Detection is on, but the malicious-package feed has not been downloaded, so nothing has been checked. This usually resolves itself within a few minutes; the admin page shows why if it does not."
          />
        </Card>
      </>
    );
  }

  const total = findings.data?.total ?? 0;

  return (
    <>
      <PageHeader
        title="Malicious packages"
        subtitle={
          <>
            Matched against {formatNumber(status.data?.reportCount ?? 0)} reports from the OpenSSF
            malicious-packages feed, built {formatRelative(status.data!.feedBuiltAt!)}.{" "}
            {status.data?.coverage && status.data.coverage.pending > 0 ? (
              <strong className="text-warn">
                {formatNumber(status.data.coverage.pending)} packages still to check.
              </strong>
            ) : null}
          </>
        }
      />

      {findings.error ? (
        <ErrorBanner error={findings.error} onRetry={() => void findings.refetch()} />
      ) : null}

      <Card>
        <CardHeader
          title="Findings"
          subtitle="Removing the package is only half of it. Anything installed on a build machine ran its own code there, so the credentials that machine could read must be treated as compromised."
          actions={
            <div className="flex flex-wrap items-center gap-2">
              <TextInput
                value={searchInput}
                onChange={(q) => {
                  setSearchInput(q);
                  setState({ page: 1 });
                }}
                placeholder="Package or MAL id"
              />
              <Select
                value={state.presence}
                onChange={(presence) =>
                  setState({ presence: presence as (typeof PRESENCE)[number], page: 1 })
                }
                options={[
                  { value: "all", label: "Current and historical" },
                  { value: "current", label: "In a current build" },
                  { value: "historical", label: "Previous builds only" },
                ]}
              />
              <Select
                value={state.corroboration}
                onChange={(corroboration) =>
                  setState({ corroboration: corroboration as (typeof CORROBORATION)[number], page: 1 })
                }
                options={[
                  { value: "", label: "Any evidence" },
                  { value: "corroborated", label: "Corroborated (2+ reporters)" },
                  { value: "single_source", label: "Single source" },
                  { value: "unattributed", label: "Unattributed" },
                ]}
              />
              <Select
                value={state.unacknowledged}
                onChange={(unacknowledged) => setState({ unacknowledged, page: 1 })}
                options={[
                  { value: "", label: "All findings" },
                  { value: "true", label: "Not yet acknowledged" },
                ]}
              />
            </div>
          }
        />

        {findings.isLoading ? (
          <LoadingBlock label="Loading findings" />
        ) : total === 0 ? (
          <EmptyState
            title={
              state.presence === "all" && !debounced
                ? "No known malicious packages"
                : "Nothing matches this filter"
            }
            hint={
              state.presence === "all" && !debounced
                ? `Nothing in the estate matches the ${formatNumber(status.data?.reportCount ?? 0)} reports in the feed as of ${formatDateTime(status.data!.feedBuiltAt!)}. These feeds are reactive, so a package published in the last few hours may not be in them yet.`
                : "Try widening the filter."
            }
          />
        ) : (
          <>
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th onSort={() => sort.toggle("packageName")} sorted={sort.stateOf("packageName")}>
                      Package
                    </Th>
                    <Th width="110px">Ecosystem</Th>
                    <Th
                      onSort={() => sort.toggle("corroboration")}
                      sorted={sort.stateOf("corroboration")}
                      width="150px"
                    >
                      Evidence
                    </Th>
                    <Th
                      onSort={() => sort.toggle("currentApplications")}
                      sorted={sort.stateOf("currentApplications")}
                      align="right"
                      width="140px"
                    >
                      In current builds
                    </Th>
                    <Th
                      onSort={() => sort.toggle("affectedApplications")}
                      sorted={sort.stateOf("affectedApplications")}
                      align="right"
                      width="130px"
                    >
                      Ever shipped
                    </Th>
                    <Th
                      onSort={() => sort.toggle("firstShippedAt")}
                      sorted={sort.stateOf("firstShippedAt")}
                      width="150px"
                    >
                      First shipped
                    </Th>
                    <Th width="150px">Status</Th>
                    {isAdmin ? <Th width="120px" /> : null}
                  </tr>
                </thead>
                <tbody>
                  {findings.data?.items.map((finding) => (
                    <Tr key={finding.id}>
                      <Td>
                        <button
                          type="button"
                          onClick={() => setOpenFinding(finding.id)}
                          className="text-left font-medium text-accent hover:underline"
                        >
                          {finding.packageName}
                        </button>
                        <div className="mt-0.5 flex flex-wrap items-center gap-1.5">
                          <span className="text-xs text-text-faint"><Mono>{finding.id}</Mono></span>
                          {finding.observedVersions.length > 0 ? (
                            <span className="text-xs text-text-faint">
                              {finding.observedVersions.slice(0, 3).join(", ")}
                              {finding.observedVersions.length > 3
                                ? ` +${finding.observedVersions.length - 3}`
                                : ""}
                            </span>
                          ) : null}
                        </div>
                      </Td>
                      <Td className="text-text-muted">{finding.ecosystem}</Td>
                      <Td>
                        <CorroborationBadge
                          corroboration={finding.corroboration}
                          sources={finding.sources}
                          reporterCount={finding.reporterCount}
                        />
                      </Td>
                      <Td align="right">
                        {/*
                          The urgent number, and the only one on this page that can be driven to
                          zero by a rebuild. Zero here is a real zero: the package was matched
                          and is genuinely not in any current build.
                        */}
                        {finding.currentApplications > 0 ? (
                          <Badge tone="danger">{formatNumber(finding.currentApplications)}</Badge>
                        ) : (
                          <span className="nums text-text-faint">0</span>
                        )}
                      </Td>
                      <Td align="right" className="nums text-text-base">
                        {formatNumber(finding.affectedApplications)}
                      </Td>
                      <Td
                        className="text-text-muted"
                        title={finding.firstShippedAt ? formatDateTime(finding.firstShippedAt) : undefined}
                      >
                        {finding.firstShippedAt ? formatRelative(finding.firstShippedAt) : "—"}
                      </Td>
                      <Td>
                        {finding.acknowledgement ? (
                          <AckBadge state={finding.acknowledgement.state} />
                        ) : finding.currentApplications > 0 ? (
                          <Badge tone="danger">Remove now</Badge>
                        ) : (
                          <Badge tone="warn">Rotate credentials</Badge>
                        )}
                      </Td>
                      {isAdmin ? (
                        <Td align="right">
                          <Button size="sm" variant="ghost" onClick={() => setAckTarget(finding)}>
                            {finding.acknowledgement ? "Update" : "Acknowledge"}
                          </Button>
                        </Td>
                      ) : null}
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
            <Pagination
              page={findings.data!.page}
              pageSize={findings.data!.pageSize}
              total={findings.data!.total}
              totalPages={findings.data!.totalPages}
              onPageChange={(page) => setState({ page })}
              isFetching={findings.isFetching}
            />
          </>
        )}
      </Card>

      <p className="mt-3 text-xs text-text-faint">
        Data from the{" "}
        <a
          href="https://github.com/ossf/malicious-packages"
          target="_blank"
          rel="noreferrer"
          className="text-accent hover:underline"
        >
          OpenSSF malicious-packages
        </a>{" "}
        feed (Apache-2.0), pooled from GitHub, Amazon Inspector, Checkmarx and others. Coverage is
        reactive: a package published in the last few hours may not be reported yet, so an empty
        result is not proof of safety.{" "}
        <Link to="/vulnerabilities" className="text-accent hover:underline">
          Vulnerabilities
        </Link>{" "}
        are tracked separately.
      </p>

      <MaliciousDetailModal
        id={openFinding}
        enabled={enabled}
        isAdmin={isAdmin}
        onClose={() => setOpenFinding(null)}
      />

      <AcknowledgeModal
        finding={ackTarget}
        onClose={() => setAckTarget(null)}
      />
    </>
  );
}

/** One vocabulary for acknowledgement states, so no two screens word them differently. */
export function AckBadge({ state }: { state: MaliciousAckState }) {
  const tone =
    state === "remediated" ? "ok" : state === "false_positive" ? "neutral" : state === "not_affected" ? "info" : "warn";
  return <Badge tone={tone}>{MALICIOUS_ACK_LABELS[state]}</Badge>;
}
