import { useState } from "react";
import type { ApiErrorEntry } from "@sbom/shared";
import { apiErrorSort, sortDirections } from "@sbom/shared";
import { useServerSort } from "../../lib/useSort.ts";
import { formatDateTime, formatRelative } from "../../lib/format.ts";
import { useApiErrors, useApiErrorSummary } from "../../lib/queries.ts";
import { useClearApiErrors } from "../../lib/mutations.ts";
import { readEnum, readNumber, readString, useUrlState } from "../../lib/useUrlState.ts";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorBanner,
  FormError,
  LoadingBlock,
  Pagination,
  Select,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../../components/ui.tsx";

const SCOPES = ["", "server"] as const;

const spec = {
  defaults: {
    scope: "" as (typeof SCOPES)[number],
    path: "",
    sortBy: apiErrorSort.defaultField,
    sortDir: apiErrorSort.defaultDirection,
    page: 1,
  },
  parse: (p: URLSearchParams) => ({
    scope: readEnum(p, "scope", SCOPES, ""),
    path: readString(p, "path"),
    sortBy: readEnum(p, "sortBy", apiErrorSort.fields, apiErrorSort.defaultField),
    sortDir: readEnum(p, "sortDir", sortDirections, apiErrorSort.defaultDirection),
    page: readNumber(p, "page", 1),
  }),
};

/**
 * How alarming a status should look.
 *
 * A 4xx is the platform refusing a request, which is usually correct behaviour and often the
 * reader's own doing — it is information, not a fault. A 5xx is the platform failing, which
 * is always worth attention. Rendering both in the same red teaches an administrator to
 * ignore the colour.
 */
function toneFor(status: number): "warn" | "danger" | "neutral" {
  if (status >= 500) return "danger";
  if (status >= 400) return "warn";
  return "neutral";
}

/**
 * What failed, and why — readable on a machine with no developer tools.
 *
 * This page exists because of a specific failure. A rejected form said "Body validation
 * failed" and nothing else; the API had named the offending field, sent it, and every layer
 * above dropped it. On a locked-down server there was no network tab to fall back on and the
 * server log recorded only a status code, so a one-word configuration mistake was
 * undiagnosable. Both halves are fixed — the form now shows its field errors — and this is
 * the record for everything that is not in front of you when it happens.
 */
export function AdminErrorsPage() {
  const { state, setState } = useUrlState(spec);
  const [confirmingClear, setConfirmingClear] = useState(false);

  const summary = useApiErrorSummary();
  const clear = useClearApiErrors();
  const entries = useApiErrors({
    serverOnly: state.scope === "server" ? true : undefined,
    path: state.path || undefined,
    sortBy: state.sortBy,
    sortDir: state.sortDir,
    page: state.page,
    pageSize: 50,
  });
  const sort = useServerSort(apiErrorSort, state, setState);

  const retentionDays = summary.data?.retentionDays;

  return (
    <Card>
      <CardHeader
        title="Error log"
        subtitle={
          retentionDays
            ? `Requests this platform refused or failed, kept for ${retentionDays} days. Separate from the audit log, which records changes that succeeded.`
            : "Requests this platform refused or failed. Separate from the audit log, which records changes that succeeded."
        }
      />

      {summary.data ? (
        <div className="flex flex-wrap items-center gap-4 border-b border-border-base px-4 py-2.5 text-xs">
          <span className="text-text-muted">
            <span className="font-medium text-text-base">{summary.data.total}</span> recorded
          </span>
          <span className="text-text-muted">
            <span className={summary.data.serverErrors > 0 ? "font-medium text-danger" : "font-medium text-text-base"}>
              {summary.data.serverErrors}
            </span>{" "}
            server failures
          </span>
          {/*
            Distinguishes "nothing has failed" from "nothing is being recorded". Without it an
            empty table is ambiguous in exactly the way this whole page exists to prevent.
          */}
          {summary.data.oldestOccurredAt ? (
            <span className="text-text-muted">
              oldest {formatRelative(summary.data.oldestOccurredAt)}
            </span>
          ) : (
            <span className="text-text-muted">nothing recorded yet</span>
          )}
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-2 border-b border-border-base px-4 py-2.5">
        <Select
          value={state.scope}
          ariaLabel="Filter by kind of failure"
          onChange={(v) => setState({ scope: v as (typeof SCOPES)[number], page: 1 })}
          options={[
            { value: "", label: "Everything" },
            { value: "server", label: "Server failures only (5xx)" },
          ]}
        />
        <div className="w-64">
          <TextInput
            value={state.path}
            onChange={(v) => setState({ path: v, page: 1 })}
            placeholder="Part of a path, e.g. /vuln"
            ariaLabel="Filter by path"
          />
        </div>

        <div className="ml-auto flex items-center gap-2">
          {confirmingClear ? (
            <>
              <span className="text-xs text-text-muted">Discard every recorded failure?</span>
              <Button
                size="sm"
                variant="danger"
                disabled={clear.isPending}
                onClick={() => {
                  clear.mutate(undefined, { onSuccess: () => setConfirmingClear(false) });
                }}
              >
                {clear.isPending ? "Clearing…" : "Clear"}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setConfirmingClear(false)}>
                Cancel
              </Button>
            </>
          ) : (
            <Button
              size="sm"
              variant="ghost"
              disabled={!summary.data || summary.data.total === 0}
              onClick={() => setConfirmingClear(true)}
              title="Once a problem is fixed, its rows only hide the next one. Recorded in the audit log."
            >
              Clear log
            </Button>
          )}
        </div>
      </div>

      <div className="px-4 pt-3 empty:hidden">
        <FormError error={clear.error} />
      </div>

      {entries.isLoading ? (
        <LoadingBlock label="Loading error log" />
      ) : entries.error ? (
        <div className="p-4">
          <ErrorBanner error={entries.error} onRetry={() => void entries.refetch()} />
        </div>
      ) : !entries.data || entries.data.items.length === 0 ? (
        <EmptyState
          title={state.scope || state.path ? "Nothing matches" : "No failures recorded"}
          hint={
            state.scope || state.path
              ? "Widen the filters to see the rest of the log."
              : "Requests that are refused or fail are recorded here. An empty list is good news."
          }
        />
      ) : (
        <>
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th onSort={() => sort.toggle("occurredAt")} sorted={sort.stateOf("occurredAt")}>
                    When
                  </Th>
                  <Th onSort={() => sort.toggle("statusCode")} sorted={sort.stateOf("statusCode")}>
                    Status
                  </Th>
                  <Th onSort={() => sort.toggle("path")} sorted={sort.stateOf("path")}>
                    Request
                  </Th>
                  <Th onSort={() => sort.toggle("code")} sorted={sort.stateOf("code")}>
                    Code
                  </Th>
                  {/* The reason. Not sortable — it is the free text the row exists to carry. */}
                  <Th>What went wrong</Th>
                  <Th>Who</Th>
                </tr>
              </thead>
              <tbody>
                {entries.data.items.map((entry) => (
                  <ErrorRow key={entry.id} entry={entry} />
                ))}
              </tbody>
            </Table>
          </TableWrap>

          <Pagination
            page={entries.data.page}
            pageSize={entries.data.pageSize}
            total={entries.data.total}
            totalPages={entries.data.totalPages}
            onPageChange={(p) => setState({ page: p })}
            isFetching={entries.isFetching}
          />
        </>
      )}
    </Card>
  );
}

function ErrorRow({ entry }: { entry: ApiErrorEntry }) {
  const fields = entry.details ? Object.entries(entry.details) : [];

  return (
    <Tr>
      <Td title={formatDateTime(entry.occurredAt)}>{formatRelative(entry.occurredAt)}</Td>
      <Td>
        <Badge tone={toneFor(entry.statusCode)}>{entry.statusCode}</Badge>
      </Td>
      <Td>
        <span className="font-mono text-[11px] break-all">
          <span className="text-text-muted">{entry.method}</span> {entry.path}
        </span>
      </Td>
      <Td>
        <span className="font-mono text-[11px]">{entry.code}</span>
      </Td>
      <Td>
        <div className="space-y-1">
          <p>{entry.message}</p>
          {fields.length > 0 ? (
            /*
              The field-level reasons — the half that was previously produced and then thrown
              away. `_` is the API's key for an issue about the request as a whole, which has
              no field to name.
            */
            <ul className="space-y-0.5 text-[11px] text-text-muted">
              {fields.map(([field, messages]) => (
                <li key={field}>
                  {field === "_" ? null : <span className="font-mono">{field}: </span>}
                  {messages.join(" ")}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      </Td>
      {/* Null is not missing data: an unauthenticated or CI request genuinely has no actor,
          and that is itself worth being able to see. */}
      <Td>{entry.actorEmail ?? <span className="text-text-muted">—</span>}</Td>
    </Tr>
  );
}
