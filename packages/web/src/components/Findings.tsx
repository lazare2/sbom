import { useState } from "react";
import { Link } from "react-router";
import type { Paginated, SortDirection, VulnBreakdown, VulnerabilityFinding, VulnSeverity } from "@sbom/shared";
import { findingSort } from "@sbom/shared";
import { useServerSort, type SortControl } from "../lib/useSort.ts";
import { useAuth } from "../auth/AuthProvider.tsx";
import { useCreateSuppression } from "../lib/mutations.ts";
import { formatNumber } from "../lib/format.ts";
import { SEVERITY_ORDER, SeverityBadge, SeverityBar } from "./Severity.tsx";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  Checkbox,
  EcosystemBadge,
  EmptyState,
  FormError,
  FormRow,
  LoadingBlock,
  Modal,
  Mono,
  Pagination,
  Select,
  Table,
  TableWrap,
  Td,
  Textarea,
  Th,
  Tr,
} from "./ui.tsx";

/**
 * Findings presentation, shared by the application view and the per-scan view.
 *
 * Extracted so those two cannot drift: they answer the same question about different
 * scopes, and a finding that rendered differently depending on which page you reached it
 * from would undermine both.
 */

export interface FindingsFilters {
  scope: "app" | "os" | "all";
  severity: VulnSeverity | "";
  fixable: boolean;
  knownExploited: boolean;
  includeSuppressed: boolean;
  sortBy: (typeof findingSort)["fields"][number];
  sortDir: SortDirection;
  page: number;
}

export const DEFAULT_FINDINGS_FILTERS: FindingsFilters = {
  scope: "app",
  sortBy: findingSort.defaultField,
  sortDir: findingSort.defaultDirection,
  severity: "",
  fixable: false,
  knownExploited: false,
  includeSuppressed: false,
  page: 1,
};

/**
 * Severity totals, split app vs base image.
 *
 * The two bars are never added together. On a real container image base-image packages
 * account for roughly 99% of findings, so one combined bar would be a picture of the base
 * image with the application's own dependencies invisible inside it.
 */
export function BreakdownTiles({ breakdown }: { breakdown: VulnBreakdown }) {
  const appTotal = SEVERITY_ORDER.reduce((acc, k) => acc + breakdown.app[k], 0);
  const osTotal = SEVERITY_ORDER.reduce((acc, k) => acc + breakdown.os[k], 0);
  const scale = Math.max(appTotal, osTotal, 1);

  return (
    <div className="grid gap-4 border-b border-border-base p-4 sm:grid-cols-2">
      <div>
        <div className="flex items-baseline justify-between gap-2">
          <p className="text-xs font-medium text-text-muted">Application dependencies</p>
          <p className="nums text-lg font-semibold text-text-base">{formatNumber(appTotal)}</p>
        </div>
        <SeverityBar counts={breakdown.app} total={scale} className="mt-2" />
        <p className="mt-2 text-xs text-text-muted">
          {formatNumber(breakdown.app.critical)} critical · {formatNumber(breakdown.app.high)} high ·{" "}
          {formatNumber(breakdown.appFixable)} with a fix
          {breakdown.appKnownExploited > 0 ? (
            <>
              {" · "}
              <span className="font-medium text-danger">
                {formatNumber(breakdown.appKnownExploited)} known exploited
              </span>
            </>
          ) : null}
        </p>
        <p className="mt-0.5 text-xs text-text-faint">
          across {formatNumber(breakdown.appAffectedPackages)} package
          {breakdown.appAffectedPackages === 1 ? "" : "s"}
        </p>
      </div>

      <div>
        <div className="flex items-baseline justify-between gap-2">
          <p className="text-xs font-medium text-text-muted">Base image and runtimes</p>
          <p className="nums text-lg font-semibold text-text-muted">{formatNumber(osTotal)}</p>
        </div>
        <SeverityBar counts={breakdown.os} total={scale} className="mt-2" />
        <p className="mt-2 text-xs text-text-muted">
          {formatNumber(breakdown.os.critical)} critical · {formatNumber(breakdown.os.high)} high
        </p>
        <p className="mt-0.5 text-xs text-text-faint">
          {/* Says why this is a separate number rather than leaving the reader to wonder. */}
          Fixed by rebuilding on a newer base image, not by changing a dependency.
        </p>
      </div>
    </div>
  );
}

export function FindingsFilterBar({
  filters,
  onChange,
}: {
  filters: FindingsFilters;
  onChange: (patch: Partial<FindingsFilters>) => void;
}) {
  return (
    <>
      <Select
        value={filters.scope}
        onChange={(scope) => onChange({ scope: scope as FindingsFilters["scope"], page: 1 })}
        ariaLabel="Package scope"
        options={[
          { value: "app", label: "Application dependencies" },
          { value: "os", label: "Base image and runtimes" },
          { value: "all", label: "Everything" },
        ]}
      />
      <Select
        value={filters.severity}
        onChange={(severity) => onChange({ severity: severity as VulnSeverity | "", page: 1 })}
        ariaLabel="Minimum severity"
        options={[
          { value: "", label: "Any severity" },
          ...SEVERITY_ORDER.map((s) => ({ value: s, label: s[0]!.toUpperCase() + s.slice(1) })),
        ]}
      />
      <Checkbox
        checked={filters.fixable}
        onChange={(fixable) => onChange({ fixable, page: 1 })}
        label="Fix available"
      />
      <Checkbox
        checked={filters.knownExploited}
        onChange={(knownExploited) => onChange({ knownExploited, page: 1 })}
        label="Known exploited"
      />
      <Checkbox
        checked={filters.includeSuppressed}
        onChange={(includeSuppressed) => onChange({ includeSuppressed, page: 1 })}
        label="Show accepted risks"
      />
    </>
  );
}

/** Turns filter state into the query the API expects, dropping defaults. */
export function findingsParams(filters: FindingsFilters, pageSize = 50): Record<string, unknown> {
  return {
    scope: filters.scope,
    severity: filters.severity || undefined,
    fixable: filters.fixable ? "true" : undefined,
    knownExploited: filters.knownExploited ? "true" : undefined,
    includeSuppressed: filters.includeSuppressed ? "true" : undefined,
    sortBy: filters.sortBy,
    sortDir: filters.sortDir,
    page: filters.page,
    pageSize,
  };
}

export function FindingsTable({
  data,
  isLoading,
  isFetching,
  applicationId,
  onPageChange,
  sort,
}: {
  data: Paginated<VulnerabilityFinding> | undefined;
  isLoading: boolean;
  isFetching?: boolean;
  /** Scopes an "accept risk" action to one application when set. */
  applicationId?: string;
  onPageChange: (page: number) => void;
  /** Omit for a table rendered without sortable headers. */
  sort?: SortControl<(typeof findingSort)["fields"][number]>;
}) {
  const { isAdmin } = useAuth();
  const [accepting, setAccepting] = useState<VulnerabilityFinding | null>(null);
  const on = (field: (typeof findingSort)["fields"][number]) => (sort ? () => sort.toggle(field) : undefined);
  const at = (field: (typeof findingSort)["fields"][number]) => (sort ? sort.stateOf(field) : undefined);

  if (isLoading) return <LoadingBlock label="Matching packages" />;
  if (!data || data.items.length === 0) {
    return (
      <EmptyState
        title="No findings"
        hint="These packages were matched against the vulnerability database and nothing was reported against them. Widen the scope or clear the filters to see more."
      />
    );
  }

  return (
    <>
      <TableWrap>
        <Table>
          <thead>
            <tr>
              <Th onSort={on("severity")} sorted={at("severity")} width="105px">
                Severity
              </Th>
              <Th onSort={on("vulnerability")} sorted={at("vulnerability")} width="190px">
                Advisory
              </Th>
              <Th onSort={on("package")} sorted={at("package")}>
                Package
              </Th>
              {/* Sorts on whether a fix exists — see findingOrderBy for why not the version. */}
              <Th onSort={on("fixVersion")} sorted={at("fixVersion")} width="150px">
                Fixed in
              </Th>
              <Th onSort={on("cvss")} sorted={at("cvss")} width="90px">
                CVSS
              </Th>
              {isAdmin ? <Th width="110px" /> : null}
            </tr>
          </thead>
          <tbody>
            {data.items.map((finding) => (
              <Tr key={`${finding.componentId}-${finding.vulnerabilityId}`}>
                <Td>
                  <span className={finding.suppressed ? "opacity-50" : undefined}>
                    <SeverityBadge severity={finding.severity} />
                  </span>
                </Td>
                <Td>
                  <div className="flex flex-col gap-0.5">
                    <Link
                      to={`/vulnerabilities/${encodeURIComponent(finding.vulnerabilityId)}`}
                      className="font-mono text-xs text-accent hover:underline"
                    >
                      {finding.vulnerabilityId}
                    </Link>
                    {/* The CVE number is what people search for and quote, even when grype's
                        primary id is a GHSA — so it has to be visible, not just indexed. */}
                    {finding.aliases.length > 0 ? (
                      <span className="font-mono text-[11px] text-text-faint">
                        {finding.aliases.slice(0, 2).join(", ")}
                      </span>
                    ) : null}
                    <span className="flex flex-wrap gap-1">
                      {finding.knownExploited ? (
                        <Badge tone="danger" title="On CISA's Known Exploited Vulnerabilities list.">
                          exploited
                        </Badge>
                      ) : null}
                      {finding.suppressed ? (
                        <Badge tone="neutral" title={finding.suppressionReason ?? undefined}>
                          accepted
                        </Badge>
                      ) : null}
                    </span>
                  </div>
                </Td>
                <Td>
                  <div className="flex flex-wrap items-center gap-2">
                    <Link
                      to={`/search?name=${encodeURIComponent(finding.componentName)}&match=exact`}
                      className="font-medium text-accent hover:underline"
                    >
                      {finding.componentName}
                    </Link>
                    <Mono>{finding.componentVersion ?? "unknown"}</Mono>
                    <EcosystemBadge ecosystem={finding.ecosystem} />
                    {finding.kind !== "library" ? (
                      <Badge tone="neutral" title="Part of the base image rather than a chosen dependency.">
                        {finding.kind}
                      </Badge>
                    ) : null}
                  </div>
                </Td>
                <Td>
                  {finding.fixVersions.length > 0 ? (
                    <Mono title={finding.fixVersions.join(", ")}>{finding.fixVersions[0]}</Mono>
                  ) : finding.fixState === "wont-fix" ? (
                    <span className="text-xs text-warn" title="Upstream will not fix this.">
                      won't fix
                    </span>
                  ) : (
                    <span className="text-xs text-text-faint">no fix yet</span>
                  )}
                </Td>
                <Td className="nums text-text-muted">{finding.cvssBaseScore?.toFixed(1) ?? "—"}</Td>
                {isAdmin ? (
                  <Td>
                    {finding.suppressed ? null : (
                      <Button size="sm" variant="ghost" onClick={() => setAccepting(finding)}>
                        Accept risk
                      </Button>
                    )}
                  </Td>
                ) : null}
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
        onPageChange={onPageChange}
        isFetching={isFetching}
      />
      <AcceptRiskModal
        finding={accepting}
        applicationId={applicationId}
        onClose={() => setAccepting(null)}
      />
    </>
  );
}

/**
 * Accepting a risk.
 *
 * A reason is required, and the scope defaults to the narrowest option that makes sense
 * where the dialog was opened from. Both are deliberate: an unexplained suppression is
 * indistinguishable from a mistake six months later, and an estate-wide one entered by
 * accident silently hides a real finding everywhere.
 */
function AcceptRiskModal({
  finding,
  applicationId,
  onClose,
}: {
  finding: VulnerabilityFinding | null;
  applicationId?: string;
  onClose: () => void;
}) {
  const create = useCreateSuppression();
  const [reason, setReason] = useState("");
  const [scope, setScope] = useState<"package" | "application" | "everywhere">("package");

  if (!finding) return null;

  // Captured after the null check so the closure below has a narrowed value.
  const target = finding;

  function submit() {
    create.mutate(
      {
        vulnerabilityId: target.vulnerabilityId,
        ...(scope === "package" ? { componentId: target.componentId } : {}),
        ...(scope === "application" && applicationId ? { applicationId } : {}),
        reason: reason.trim(),
      },
      {
        onSuccess: () => {
          setReason("");
          onClose();
        },
      },
    );
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={`Accept ${finding.vulnerabilityId}`}
      footer={
        <>
          <Button onClick={onClose} disabled={create.isPending}>
            Cancel
          </Button>
          <Button
            variant="primary"
            disabled={reason.trim().length < 3 || create.isPending}
            onClick={submit}
          >
            {create.isPending ? "Saving…" : "Accept risk"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <p className="text-xs text-text-muted">
          This finding will be excluded from every count, ranking and dashboard, and listed under
          Accepted risks in the admin panel with your name against it. It is hidden, not deleted.
        </p>

        <FormRow label="Applies to" htmlFor="accept-scope">
          <Select
            id="accept-scope"
            value={scope}
            onChange={(v) => setScope(v as typeof scope)}
            ariaLabel="Suppression scope"
            options={[
              {
                value: "package",
                label: `Only ${finding.componentName} ${finding.componentVersion ?? ""}`.trim(),
              },
              ...(applicationId ? [{ value: "application", label: "Only this application" }] : []),
              { value: "everywhere", label: "Everywhere in the estate" },
            ]}
          />
        </FormRow>

        <FormRow
          label="Why is this risk accepted?"
          htmlFor="accept-reason"
          hint="Required. This is the record someone reads when they ask why a known CVE was not being reported."
        >
          <Textarea id="accept-reason" rows={3} value={reason} onChange={setReason} />
        </FormRow>

        <FormError error={create.error} />
      </div>
    </Modal>
  );
}

/**
 * Sort control for a findings table whose state lives in `FindingsFilters`.
 *
 * Both callers hold those filters in component state rather than the URL, so the sort rides
 * along in the same object instead of being threaded separately. Resets to page 1 on every
 * change, like the other filters — a re-sort makes the current page number meaningless.
 */
export function useFindingsSort(
  filters: FindingsFilters,
  onChange: (patch: Partial<FindingsFilters>) => void,
): SortControl<(typeof findingSort)["fields"][number]> {
  return useServerSort(findingSort, filters, (patch) => onChange({ ...patch, page: 1 }));
}

/** Wraps a findings list in the standard card, with filters in the header. */
export function FindingsCard({
  title,
  subtitle,
  filters,
  onChange,
  children,
}: {
  title: string;
  subtitle?: string;
  filters: FindingsFilters;
  onChange: (patch: Partial<FindingsFilters>) => void;
  children: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader
        title={title}
        subtitle={subtitle}
        actions={<FindingsFilterBar filters={filters} onChange={onChange} />}
      />
      {children}
    </Card>
  );
}
