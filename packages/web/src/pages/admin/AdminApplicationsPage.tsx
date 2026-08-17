import { useState } from "react";
import { Link } from "react-router";
import type { ApplicationSummary } from "@sbom/shared";
import { formatNumber, formatRelative, humanizeKey } from "../../lib/format.ts";
import { useDeleteApplication } from "../../lib/mutations.ts";
import { useApplications, useAttributeDefinitions } from "../../lib/queries.ts";
import { readEnum, readNumber, readString, useUrlState } from "../../lib/useUrlState.ts";
import { useDebounced } from "../../lib/useDebounced.ts";
import {
  Button,
  Card,
  CardHeader,
  ConfirmDeleteModal,
  EmptyState,
  ErrorBanner,
  FormError,
  LoadingBlock,
  Pagination,
  Select,
  StatusBadge,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../../components/ui.tsx";
import { ApplicationFormModal } from "./ApplicationFormModal.tsx";

const STATUSES = ["", "active", "inactive", "pending_confirmation"] as const;

const spec = {
  defaults: { search: "", status: "" as (typeof STATUSES)[number], page: 1 },
  parse: (p: URLSearchParams) => ({
    search: readString(p, "search"),
    status: readEnum(p, "status", STATUSES, ""),
    page: readNumber(p, "page", 1),
  }),
};

export function AdminApplicationsPage() {
  const { state, setState } = useUrlState(spec);
  const debouncedSearch = useDebounced(state.search, 250);
  const definitions = useAttributeDefinitions();

  const [editing, setEditing] = useState<ApplicationSummary | null>(null);
  const [creating, setCreating] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<ApplicationSummary | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);

  const deleteApp = useDeleteApplication();

  const applications = useApplications({
    search: debouncedSearch || undefined,
    // Unlike the read-only list, the admin view defaults to every status: this
    // is where inactive records are managed, so hiding them by default would
    // make them unreachable from the one screen meant to manage them.
    status: state.status ? [state.status] : ["active", "inactive", "pending_confirmation"],
    page: state.page,
    pageSize: 25,
    sortBy: "name",
  });

  const attributeColumns = (definitions.data ?? []).filter((d) => d.isActive).slice(0, 2);

  return (
    <>
      <Card>
        <CardHeader
          title="Applications"
          subtitle="Register an application before its first scan to have CI land on a confirmed record with its attributes already set."
          actions={
            <Button variant="primary" size="sm" onClick={() => setCreating(true)}>
              Register application
            </Button>
          }
        />

        <div className="flex flex-wrap items-center gap-2 border-b border-border-base px-4 py-2.5">
          <div className="w-64">
            <TextInput
              value={state.search}
              onChange={(v) => setState({ search: v })}
              placeholder="Search by name…"
              ariaLabel="Search applications"
            />
          </div>
          <Select
            value={state.status}
            ariaLabel="Filter by status"
            onChange={(v) => setState({ status: v })}
            options={[
              { value: "", label: "All statuses" },
              { value: "active", label: "Active" },
              { value: "inactive", label: "Inactive" },
              { value: "pending_confirmation", label: "Unconfirmed" },
            ]}
          />
        </div>

        {actionError ? (
          <div className="px-4 pt-3">
            <FormError error={actionError} />
          </div>
        ) : null}

        {applications.isLoading ? (
          <LoadingBlock label="Loading applications" />
        ) : applications.error ? (
          <div className="p-4">
            <ErrorBanner error={applications.error} onRetry={() => void applications.refetch()} />
          </div>
        ) : !applications.data || applications.data.items.length === 0 ? (
          <EmptyState
            title="No applications match"
            hint="Register one, or wait for a CI pipeline to post its first SBOM."
          />
        ) : (
          <>
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th>Name</Th>
                    <Th>Status</Th>
                    {attributeColumns.map((d) => (
                      <Th key={d.key}>{d.label || humanizeKey(d.key)}</Th>
                    ))}
                    <Th align="right">Scans</Th>
                    <Th>Last scan</Th>
                    <Th />
                  </tr>
                </thead>
                <tbody>
                  {applications.data.items.map((app) => (
                    <Tr key={app.id}>
                      <Td>
                        <Link
                          to={`/applications/${app.id}`}
                          className="font-medium text-accent hover:underline"
                        >
                          {app.name}
                        </Link>
                      </Td>
                      <Td>
                        <StatusBadge status={app.status} />
                      </Td>
                      {attributeColumns.map((d) => (
                        <Td key={d.key} className="text-text-muted">
                          {app.attributes[d.key] === undefined || app.attributes[d.key] === null
                            ? "—"
                            : String(app.attributes[d.key])}
                        </Td>
                      ))}
                      <Td align="right" className="nums">
                        {formatNumber(app.scanCount)}
                      </Td>
                      <Td title={app.lastScanAt ?? ""}>{formatRelative(app.lastScanAt)}</Td>
                      <Td align="right">
                        <div className="flex justify-end gap-1.5">
                          {app.status === "pending_confirmation" ? (
                            <Link
                              to="/admin/pending"
                              className="inline-flex items-center rounded-md border border-border-strong bg-bg-raised px-2 py-1 text-xs font-medium text-text-base hover:bg-bg-subtle"
                            >
                              Resolve
                            </Link>
                          ) : (
                            <Button size="sm" onClick={() => setEditing(app)}>
                              Edit
                            </Button>
                          )}
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => {
                              setActionError(null);
                              setDeleteTarget(app);
                            }}
                          >
                            Delete
                          </Button>
                        </div>
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>

            <Pagination
              page={applications.data.page}
              pageSize={applications.data.pageSize}
              total={applications.data.total}
              totalPages={applications.data.totalPages}
              onPageChange={(p) => setState({ page: p })}
              isFetching={applications.isFetching}
            />
          </>
        )}
      </Card>

      <ApplicationFormModal open={creating} onClose={() => setCreating(false)} />
      <ApplicationFormModal
        open={editing !== null}
        existing={editing}
        onClose={() => setEditing(null)}
      />

      <ConfirmDeleteModal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        confirmWord={deleteTarget?.name ?? ""}
        title="Delete application"
        busy={deleteApp.isPending}
        onConfirm={() => {
          if (!deleteTarget) return;
          setActionError(null);
          deleteApp.mutate(deleteTarget.id, {
            onSuccess: () => setDeleteTarget(null),
            onError: (err) => setActionError(err),
          });
        }}
      >
        <FormError error={actionError} />
        <p>
          This permanently deletes{" "}
          <strong className="text-text-base">{deleteTarget?.name}</strong> and all{" "}
          <strong className="text-text-base">{formatNumber(deleteTarget?.scanCount ?? 0)}</strong> of its
          scans. There is no undo, and the history cannot be reconstructed.
        </p>
        <p>
          If the application is simply no longer built, mark it{" "}
          <strong className="text-text-base">inactive</strong> instead — it disappears from the default
          list while keeping the history that answers "did we ever ship this package".
        </p>
      </ConfirmDeleteModal>
    </>
  );
}
