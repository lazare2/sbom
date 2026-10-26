import { Fragment, useMemo, useState } from "react";
import { Link } from "react-router";
import type { FixRecommendation, FixRecommendationReport } from "@sbom/shared";
import { useFixRecommendations } from "../lib/queries.ts";
import { formatDate, formatNumber } from "../lib/format.ts";
import { FINDINGS_SCOPE_OPTIONS, type FindingsFilters } from "./Findings.tsx";
import { SeverityBadge, SeverityCountsInline } from "./Severity.tsx";
import {
  Badge,
  Card,
  CardHeader,
  Checkbox,
  EcosystemBadge,
  EmptyState,
  ErrorBanner,
  LoadingBlock,
  Mono,
  Select,
  Spinner,
  Table,
  TableWrap,
  Td,
  Th,
  Tr,
} from "./ui.tsx";

/**
 * One upgrade per vulnerable package, instead of one "fixed in" per advisory.
 *
 * The findings table lists every advisory with its own fix version, so a package with five of
 * them offers five versions and leaves the reader to work out which one clears them all. This
 * view does that sum: the lowest version clearing everything reported, and then that version
 * checked against the vulnerability database and moved forward while it is still affected.
 *
 * Drawn in two passes. The first is answered from stored findings and arrives at once; the
 * second checks the recommended versions with the scanner, which the first time can take a
 * while on a large base image. The table is usable throughout, and says which it is showing.
 */
export function FixRecommendationsCard({
  applicationId,
  scope,
  onScopeChange,
}: {
  applicationId: string;
  scope: FindingsFilters["scope"];
  onScopeChange: (scope: FindingsFilters["scope"]) => void;
}) {
  const report = useFixRecommendations(applicationId, scope);
  /*
    Packages with no fix are hidden by default. On a base image they are routinely the large
    majority, and a list of things nobody can act on pushes the handful that can be off the
    first screen. The count stays visible on the toggle, so hiding them is never silent.
  */
  const [showNoFix, setShowNoFix] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);

  const data = report.data;
  const all = data?.recommendations ?? [];
  const noFix = all.filter((r) => r.status === "no_fix").length;
  const rows = showNoFix ? all : all.filter((r) => r.status !== "no_fix");

  return (
    <Card>
      <CardHeader
        title="Recommended upgrades"
        subtitle="One target version per package: the lowest that clears every advisory reported against it, then checked against the vulnerability database and moved forward if that version is itself affected."
        actions={
          <>
            <Select
              value={scope}
              onChange={(value) => onScopeChange(value)}
              ariaLabel="Package scope"
              options={FINDINGS_SCOPE_OPTIONS}
            />
            <Checkbox
              checked={showNoFix}
              onChange={setShowNoFix}
              label={`Show packages with no fix (${formatNumber(noFix)})`}
            />
          </>
        }
      />

      {report.error ? (
        <div className="p-4">
          <ErrorBanner error={report.error} onRetry={report.refetch} />
        </div>
      ) : report.isLoading || !data ? (
        <LoadingBlock label="Working out upgrades" />
      ) : (
        <>
          <Summary report={data} verifying={report.verifying} verifyError={report.verifyError} />
          {rows.length === 0 ? (
            <EmptyState
              title={all.length === 0 ? "Nothing to upgrade" : "No package has a fix yet"}
              hint={
                all.length === 0
                  ? "No vulnerabilities are reported against the packages in this scope."
                  : "Every advisory in this scope is waiting on an upstream fix. Tick “Show packages with no fix” to see them."
              }
            />
          ) : (
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th>Package</Th>
                    <Th width="200px">Installed</Th>
                    <Th width="190px">Findings</Th>
                    <Th width="220px">Upgrade to</Th>
                    <Th width="200px">Checked</Th>
                    <Th width="80px" />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((rec) => (
                    <Fragment key={rec.key}>
                      <RecommendationRow
                        rec={rec}
                        verifying={report.verifying}
                        open={expanded === rec.key}
                        onToggle={() => setExpanded(expanded === rec.key ? null : rec.key)}
                      />
                      {expanded === rec.key ? (
                        <tr>
                          <td colSpan={6} className="border-b border-border-base bg-bg-subtle px-4 py-3">
                            <RecommendationDetail rec={rec} />
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
          )}
        </>
      )}
    </Card>
  );
}

function Summary({
  report,
  verifying,
  verifyError,
}: {
  report: FixRecommendationReport;
  verifying: boolean;
  verifyError: unknown;
}) {
  const { summary, verification } = report;
  const actionable = report.recommendations.filter((r) => r.status !== "no_fix").length;

  return (
    <div className="space-y-1.5 border-b border-border-base px-4 py-3 text-xs text-text-muted">
      <p>
        Upgrading <strong className="text-text-base">{formatNumber(actionable)}</strong>{" "}
        {actionable === 1 ? "package" : "packages"} clears{" "}
        <strong className="text-text-base">{formatNumber(summary.resolvable)}</strong> of{" "}
        {formatNumber(summary.findings)} {summary.findings === 1 ? "finding" : "findings"}.
        {summary.withoutFix > 0 ? (
          <>
            {" "}
            <span className="text-warn">
              {formatNumber(summary.withoutFix)} have no fix available yet, and stay until upstream
              publishes one.
            </span>
          </>
        ) : null}
      </p>
      {/*
        Which pass is on screen, always. An unverified recommendation clears what is reported
        today but may itself be affected, and a reader has to be able to tell the two apart
        before acting on a version.
      */}
      {verifying ? (
        <Spinner label="Checking the recommended versions against the vulnerability database…" />
      ) : verifyError ? (
        <p className="text-warn">
          The recommended versions could not be checked just now, so they are shown unverified.
        </p>
      ) : verification.status === "verified" ? (
        <p>
          Recommended versions were checked against the vulnerability database
          {verification.databaseBuiltAt ? ` built ${formatDate(verification.databaseBuiltAt)}` : ""}.
        </p>
      ) : verification.message ? (
        <p className="text-warn">{verification.message}</p>
      ) : null}
    </div>
  );
}

function RecommendationRow({
  rec,
  verifying,
  open,
  onToggle,
}: {
  rec: FixRecommendation;
  verifying: boolean;
  open: boolean;
  onToggle: () => void;
}) {
  const moved =
    rec.recommendedVersion !== null &&
    rec.minimumVersion !== null &&
    rec.recommendedVersion !== rec.minimumVersion;

  return (
    <Tr>
      <Td>
        <div className="flex flex-wrap items-center gap-2">
          <Link
            to={`/search?name=${encodeURIComponent(rec.name)}&match=exact`}
            className="font-medium text-accent hover:underline"
            title={`Find every application using ${rec.name}`}
          >
            {rec.name}
          </Link>
          <EcosystemBadge ecosystem={rec.ecosystem} />
          {rec.origin === "os" ? (
            <Badge
              tone="neutral"
              title="Part of the base image: fixed by rebuilding on a newer image, not by changing a dependency."
            >
              base image
            </Badge>
          ) : null}
        </div>
      </Td>
      <Td>
        <div className="flex flex-col gap-0.5">
          {rec.installedVersions.map((v) => (
            <Mono key={v}>{v}</Mono>
          ))}
        </div>
      </Td>
      <Td>
        <div className="flex flex-col gap-1">
          <span className="flex items-center gap-1.5">
            <SeverityBadge severity={rec.highestSeverity} />
            <span className="nums text-xs text-text-muted">{formatNumber(rec.findings)}</span>
          </span>
          <SeverityCountsInline counts={rec.counts} />
        </div>
      </Td>
      <Td>
        {rec.recommendedVersion === null ? (
          <span className="text-xs text-text-faint">no fix available</span>
        ) : (
          <div className="flex flex-col gap-0.5">
            <Mono>{rec.recommendedVersion}</Mono>
            {/*
              The case this view exists for: the version that clears today's findings is
              itself affected, so the answer is a later one. Said on the row, because a
              reader who stops at the minimum is the one this protects.
            */}
            {moved ? (
              <span className="text-[11px] text-warn">
                not {rec.minimumVersion} — it is affected too
              </span>
            ) : null}
            {rec.resolvedByMinimum < rec.findings ? (
              <span className="text-[11px] text-text-faint">
                clears {rec.resolvedByMinimum} of {rec.findings}
              </span>
            ) : null}
          </div>
        )}
      </Td>
      <Td>
        <StatusBadge rec={rec} verifying={verifying} />
      </Td>
      <Td align="right">
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={open}
          className="text-xs text-accent hover:underline"
        >
          {open ? "Hide" : "Why"}
        </button>
      </Td>
    </Tr>
  );
}

function StatusBadge({ rec, verifying }: { rec: FixRecommendation; verifying: boolean }) {
  switch (rec.status) {
    case "clean":
      return (
        <Badge tone="ok" title="The scanner reports nothing against this version.">
          no known vulnerabilities
        </Badge>
      );
    case "residual": {
      const remaining = rec.checks[rec.checks.length - 1]?.advisories.length ?? 0;
      return (
        <Badge
          tone="warn"
          title="The best available version still carries advisories that have no fix yet."
        >
          {remaining} unfixed remain
        </Badge>
      );
    }
    case "no_fix":
      return <Badge tone="neutral">no fix published</Badge>;
    case "unverified":
    default:
      return verifying ? (
        <span className="text-xs text-text-faint">checking…</span>
      ) : (
        <Badge tone="neutral" title="This version clears what is reported today, but was not itself checked.">
          not checked
        </Badge>
      );
  }
}

/** How many advisories the detail lists before offering the rest. */
const ADVISORY_LIST_CAP = 25;

/** The reasoning behind one row: what each advisory needs, and what each checked version had. */
function RecommendationDetail({ rec }: { rec: FixRecommendation }) {
  const [showAll, setShowAll] = useState(false);

  /*
    One line per advisory, not per advisory per installed version. A package shipped at two
    versions reports most advisories twice, and listing both doubled a ninety-line list for no
    information beyond "on both" -- which the line now says itself.
  */
  const merged = useMemo(() => {
    const byId = new Map<
      string,
      FixRecommendation["advisories"][number] & { on: string[]; fixes: string[] }
    >();
    for (const advisory of rec.advisories) {
      const existing = byId.get(advisory.vulnerabilityId);
      if (!existing) {
        byId.set(advisory.vulnerabilityId, {
          ...advisory,
          on: advisory.installedVersion ? [advisory.installedVersion] : [],
          fixes: advisory.fixedIn ? [advisory.fixedIn] : [],
        });
        continue;
      }
      if (advisory.installedVersion) existing.on.push(advisory.installedVersion);
      // Listed rather than reduced to one: ordering versions is the server's job, and the
      // two installed versions can sit on different release lines with different fixes.
      if (advisory.fixedIn && !existing.fixes.includes(advisory.fixedIn)) {
        existing.fixes.push(advisory.fixedIn);
      }
    }
    return [...byId.values()];
  }, [rec.advisories]);
  const visible = showAll ? merged : merged.slice(0, ADVISORY_LIST_CAP);

  return (
    <div className="grid gap-4 text-xs lg:grid-cols-2">
      <div>
        <h4 className="mb-1.5 font-medium text-text-muted">
          {merged.length} {merged.length === 1 ? "advisory" : "advisories"} reported against the
          installed {rec.installedVersions.length === 1 ? "version" : "versions"}
        </h4>
        <ul className="divide-y divide-border-base rounded-md border border-border-base bg-bg-raised">
          {visible.map((advisory) => (
            <li
              key={advisory.vulnerabilityId}
              className="flex flex-wrap items-center justify-between gap-2 px-2.5 py-1.5"
            >
              <span className="flex items-center gap-2">
                <SeverityBadge severity={advisory.severity} />
                <Link
                  to={`/vulnerabilities/${encodeURIComponent(advisory.vulnerabilityId)}`}
                  className="font-mono text-accent hover:underline"
                >
                  {advisory.vulnerabilityId}
                </Link>
                {advisory.knownExploited ? <Badge tone="danger">exploited</Badge> : null}
                {rec.installedVersions.length > 1 && advisory.on.length > 0 ? (
                  <span className="text-text-faint">
                    {advisory.on.length === rec.installedVersions.length
                      ? rec.installedVersions.length === 2
                        ? "on both"
                        : "on all"
                      : `on ${advisory.on.join(", ")}`}
                  </span>
                ) : null}
              </span>
              <span className="text-text-muted">
                {advisory.fixes.length > 0 ? (
                  <>
                    fixed in <Mono>{advisory.fixes.join(" / ")}</Mono>
                  </>
                ) : advisory.fixState === "wont-fix" ? (
                  <span className="text-warn">won't fix</span>
                ) : (
                  <span className="text-text-faint">no fix yet</span>
                )}
              </span>
            </li>
          ))}
        </ul>
        {merged.length > ADVISORY_LIST_CAP ? (
          <button
            type="button"
            onClick={() => setShowAll(!showAll)}
            className="mt-1.5 text-accent hover:underline"
          >
            {showAll ? "Show fewer" : `Show all ${merged.length}`}
          </button>
        ) : null}
      </div>

      <div>
        <h4 className="mb-1.5 font-medium text-text-muted">How the target was chosen</h4>
        <ol className="space-y-2">
          {rec.minimumVersion !== null ? (
            <li className="text-text-muted">
              <Mono>{rec.minimumVersion}</Mono> is the lowest version that clears every advisory
              above that has a fix
              {rec.resolvedByMinimum < rec.findings
                ? ` (${rec.resolvedByMinimum} of ${rec.findings}; the rest have none)`
                : ""}
              .
            </li>
          ) : (
            <li className="text-text-muted">
              None of the advisories above has a published fix, so there is no version to move to
              yet.
            </li>
          )}
          {rec.checks.map((check) => (
            <li key={check.version} className="text-text-muted">
              Checked <Mono>{check.version}</Mono>:{" "}
              {check.advisories.length === 0 ? (
                <span className="font-medium text-ok">no known vulnerabilities.</span>
              ) : (
                <>
                  still affected by {check.advisories.length}{" "}
                  {check.advisories.length === 1 ? "advisory" : "advisories"}
                  <ul className="mt-1 ml-4 list-disc space-y-0.5">
                    {check.advisories.slice(0, 8).map((advisory) => (
                      <li key={advisory.vulnerabilityId}>
                        <span className="font-mono">{advisory.vulnerabilityId}</span> (
                        {advisory.severity}) —{" "}
                        {advisory.fixedIn ? (
                          <>
                            fixed in <Mono>{advisory.fixedIn}</Mono>
                          </>
                        ) : (
                          "no fix yet"
                        )}
                      </li>
                    ))}
                    {check.advisories.length > 8 ? (
                      <li className="text-text-faint">and {check.advisories.length - 8} more</li>
                    ) : null}
                  </ul>
                </>
              )}
            </li>
          ))}
          {rec.status === "unverified" && rec.minimumVersion !== null ? (
            <li className="text-text-faint">
              Not checked against the database on this load. It clears what is reported today,
              but may itself be affected.
            </li>
          ) : null}
        </ol>
      </div>
    </div>
  );
}
