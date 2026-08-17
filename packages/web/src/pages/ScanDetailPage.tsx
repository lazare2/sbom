import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { componentListSort } from "@sbom/shared";
import { useServerSort } from "../lib/useSort.ts";
import { useScan, useScanComponents } from "../lib/queries.ts";
import { formatBytes, formatDateTime, formatNumber, formatRelative } from "../lib/format.ts";
import { readEnum, readNumber, readString, useUrlState } from "../lib/useUrlState.ts";
import { useDebounced } from "../lib/useDebounced.ts";
import { PlatformChips } from "../components/Platform.tsx";
import {
  BreakdownTiles,
  DEFAULT_FINDINGS_FILTERS,
  FindingsCard,
  FindingsTable,
  findingsParams,
  useFindingsSort,
  type FindingsFilters,
} from "../components/Findings.tsx";
import { useScanVulnerabilities, useVulnStatus } from "../lib/queries.ts";
import { useAuth } from "../auth/AuthProvider.tsx";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorBanner,
  Field,
  LoadingBlock,
  Mono,
  Pagination,
  PageHeader,
  ScanSourceBadge,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../components/ui.tsx";

const SORTS = componentListSort.fields;
const DIRECTIONS = ["asc", "desc"] as const;

const DEFAULTS = {
  q: "",
  sortBy: componentListSort.defaultField,
  sortDir: "asc" as "asc" | "desc",
  page: 1,
};

const urlSpec = {
  defaults: DEFAULTS,
  parse: (params: URLSearchParams) => ({
    q: readString(params, "q"),
    sortBy: readEnum(params, "sortBy", SORTS, componentListSort.defaultField),
    sortDir: readEnum(params, "sortDir", DIRECTIONS, "asc"),
    page: readNumber(params, "page", 1),
  }),
};

/**
 * A single historical build.
 *
 * This is what makes retained history useful rather than merely stored: the
 * component list of any past scan is viewable, not just the latest one.
 */
export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { state, setState } = useUrlState(urlSpec);

  const { data: scan, isLoading, error, refetch } = useScan(id);

  const [searchInput, setSearchInput] = useState(state.q);
  const debounced = useDebounced(searchInput, 300);

  useEffect(() => {
    if (debounced !== state.q) setState({ q: debounced });
  }, [debounced, state.q, setState]);
  useEffect(() => {
    setSearchInput(state.q);
  }, [state.q]);

  const params = useMemo(
    () => ({
      search: state.q || undefined,
      sortBy: state.sortBy,
      sortDir: state.sortDir,
      page: state.page,
      pageSize: 100,
    }),
    [state],
  );

  const components = useScanComponents(id, params);
  const { data: vulnStatus } = useVulnStatus();
  const vulnEnabled = vulnStatus?.enabled === true;
  /*
    Above the guards below, and it has to be. The plain `function sortBy` this replaced was
    hoisted, so its position after an early return was harmless; a hook in the same place
    is skipped on the loading render and called on the loaded one, which is a hooks-order
    violation React reports as a hook-count mismatch rather than as a missing sort.
  */
  const sort = useServerSort(componentListSort, state, setState);

  if (isLoading) return <LoadingBlock label="Loading scan" />;
  if (error) return <ErrorBanner error={error} onRetry={() => void refetch()} />;
  if (!scan) return null;

  return (
    <>
      <PageHeader
        title={
          <span className="flex flex-wrap items-center gap-2">
            <Link to={`/applications/${scan.applicationId}`} className="text-accent hover:underline">
              {scan.applicationName}
            </Link>
            <span className="text-text-faint">/</span>
            <span>{scan.buildNumber ? `Build ${scan.buildNumber}` : "Scan"}</span>
            {scan.isLatest ? (
              <Badge tone="ok" title="This scan is the application's current state.">
                current
              </Badge>
            ) : (
              <Badge tone="neutral" title="A historical build. The application has newer scans.">
                historical
              </Badge>
            )}
            <ScanSourceBadge source={scan.source} uploadedByEmail={scan.uploadedByEmail} />
          </span>
        }
        subtitle={
          <span title={formatDateTime(scan.createdAt)}>
            Scanned {formatRelative(scan.createdAt)} · {formatNumber(scan.componentCount)} components
          </span>
        }
        actions={
          <>
            {scan.previousScanId ? (
              <Link to={`/scans/${scan.previousScanId}`}>
                <Button size="sm">← Previous build</Button>
              </Link>
            ) : null}
            {scan.nextScanId ? (
              <Link to={`/scans/${scan.nextScanId}`}>
                <Button size="sm">Next build →</Button>
              </Link>
            ) : null}
            {/*
              Only offered when there is an earlier build: the diff endpoint
              needs two scans, and a button that always 400s on the first scan
              of an application is worse than no button.
            */}
            {scan.previousScanId ? (
              <Link
                to={`/applications/${scan.applicationId}/diff?from=${scan.previousScanId}&to=${scan.id}`}
              >
                <Button size="sm">Compare with previous</Button>
              </Link>
            ) : null}
            {/*
              A plain anchor, not a router Link: this is a file download served
              with Content-Disposition, so the browser must handle it natively
              rather than the SPA intercepting the navigation.
            */}
            <a href={`/api/v1/scans/${scan.id}/raw`} download>
              <Button size="sm" variant="secondary">
                Download SBOM
              </Button>
            </a>
          </>
        }
      />

      <Card className="mb-4">
        <CardHeader title="Build provenance" />
        <dl className="grid grid-cols-2 gap-4 p-4 sm:grid-cols-3 lg:grid-cols-4">
          <div className="col-span-2 sm:col-span-3 lg:col-span-4">
            {/*
              Per-build, not per-application: comparing this against an earlier
              scan's value is how a base-image bump becomes visible.
            */}
            <Field label="Runs on">
              <PlatformChips platform={scan.platform} emptyLabel="Not detected" />
            </Field>
          </div>
          <Field label="Scanned at">{formatDateTime(scan.createdAt)}</Field>
          <Field label="Build number">{scan.buildNumber ?? "—"}</Field>
          <Field label="Pipeline">{scan.pipelineId ?? "—"}</Field>
          <Field label="Branch">{scan.branch ?? "—"}</Field>
          <div className="col-span-2">
            <Field label="Commit">
              <Mono title={scan.commitSha ?? undefined}>{scan.commitSha ?? "—"}</Mono>
            </Field>
          </div>
          <div className="col-span-2">
            <Field label="Image">
              <Mono title={scan.imageRef ?? undefined}>{scan.imageRef ?? "—"}</Mono>
            </Field>
          </div>
          <Field label="Generated by">
            {scan.toolName ? `${scan.toolName} ${scan.toolVersion ?? ""}`.trim() : "—"}
          </Field>
          <Field label="CycloneDX">{scan.specVersion ?? "—"}</Field>
          {/*
            One field, two mutually exclusive answers. A scan has either an ingest
            token or an uploader, never both, so showing both slots would leave a
            permanent "—" next to whichever one applies and invite the reader to
            wonder what is missing.
          */}
          {scan.source === "manual" ? (
            <Field label="Uploaded by">{scan.uploadedByEmail ?? "a deleted account"}</Field>
          ) : (
            <Field label="Ingest token">{scan.ingestTokenName ?? "—"}</Field>
          )}
          <Field label="Raw SBOM">{formatBytes(scan.sbomSizeBytes)}</Field>
          <div className="col-span-2 sm:col-span-3 lg:col-span-4">
            <Field label="SBOM SHA-256">
              {/* Lets an auditor verify the download matches what was uploaded. */}
              <Mono>{scan.sbomSha256}</Mono>
            </Field>
          </div>
          {scan.uploadNote ? (
            <div className="col-span-2 sm:col-span-3 lg:col-span-4">
              <Field label="Reason given for the manual upload">
                <span className="whitespace-pre-wrap">{scan.uploadNote}</span>
              </Field>
            </div>
          ) : null}
        </dl>
      </Card>

      {/*
        Only rendered when scanning is on. Absent rather than empty: a findings card
        showing nothing for a build nobody matched would read as a clean result.
      */}
      {vulnEnabled ? (
        <div className="mb-4">
          <ScanFindings scanId={scan.id} />
        </div>
      ) : null}

      {components.error ? (
        <ErrorBanner error={components.error} onRetry={() => void components.refetch()} />
      ) : null}

      <Card>
        <CardHeader
          title="Components in this build"
          subtitle={components.data ? `${formatNumber(components.data.total)} matching` : undefined}
          actions={
            <div className="w-52">
              <TextInput
                value={searchInput}
                onChange={setSearchInput}
                placeholder="Filter packages…"
                ariaLabel="Filter components by name"
              />
            </div>
          }
        />
        {components.isLoading ? (
          <LoadingBlock label="Loading components" />
        ) : !components.data || components.data.items.length === 0 ? (
          <EmptyState
            title="No components"
            hint="This build's SBOM contained no catalogued packages, or no package matches your filter."
          />
        ) : (
          <>
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th onSort={() => sort.toggle("name")} sorted={sort.stateOf("name")}>
                      Package
                    </Th>
                    <Th onSort={() => sort.toggle("version")} sorted={sort.stateOf("version")} width="180px">
                      Version
                    </Th>
                    <Th onSort={() => sort.toggle("ecosystem")} sorted={sort.stateOf("ecosystem")} width="120px">
                      Ecosystem
                    </Th>
                    <Th onSort={() => sort.toggle("purl")} sorted={sort.stateOf("purl")}>
                      Package URL
                    </Th>
                  </tr>
                </thead>
                <tbody>
                  {components.data.items.map((c) => (
                    <Tr key={c.id}>
                      <Td>
                        <Link
                          to={`/search?name=${encodeURIComponent(c.name)}&match=exact`}
                          className="font-medium text-accent hover:underline"
                        >
                          {c.name}
                        </Link>
                      </Td>
                      <Td className="nums font-mono text-xs text-text-muted">
                        {c.version ?? <span className="text-text-faint">unknown</span>}
                      </Td>
                      <Td>
                        <span className="rounded bg-neutral-subtle px-1.5 py-0.5 font-mono text-[11px] text-text-muted">
                          {c.ecosystem}
                        </span>
                      </Td>
                      <Td className="max-w-[520px] truncate" title={c.purl ?? undefined}>
                        {c.purl ? <Mono>{c.purl}</Mono> : <span className="text-text-faint">—</span>}
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
            <Pagination
              page={components.data.page}
              pageSize={components.data.pageSize}
              total={components.data.total}
              totalPages={components.data.totalPages}
              onPageChange={(page) => setState({ page })}
              isFetching={components.isFetching}
            />
          </>
        )}
      </Card>
    </>
  );
}

/**
 * Findings for one specific build, including a historical one.
 *
 * Matched against today's database rather than against what was known when the build was
 * scanned — so opening a release from six months ago answers "was this affected by the CVE
 * announced last week", which is the question people actually bring to an old build.
 */
function ScanFindings({ scanId }: { scanId: string }) {
  const { isAdmin } = useAuth();
  const [filters, setFilters] = useState<FindingsFilters>(DEFAULT_FINDINGS_FILTERS);
  const paramsForFindings = useMemo(() => findingsParams(filters, 25), [filters]);
  const findingsSort = useFindingsSort(filters, (patch) => setFilters((f) => ({ ...f, ...patch })));
  const { data, isLoading, isFetching } = useScanVulnerabilities(scanId, paramsForFindings);

  return (
    <FindingsCard
      title="Vulnerabilities in this build"
      subtitle="Evaluated against the vulnerability database installed now, not the one current when this build was scanned."
      filters={filters}
      onChange={(patch) => setFilters((prev) => ({ ...prev, ...patch }))}
    >
      {data ? <BreakdownTiles breakdown={data.breakdown} /> : null}
      <FindingsTable
        sort={findingsSort}
        data={data}
        isLoading={isLoading}
        isFetching={isFetching}
        onPageChange={(page) => setFilters((prev) => ({ ...prev, page }))}
      />
    </FindingsCard>
  );
}
