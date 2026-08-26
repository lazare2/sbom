import { useState } from "react";
import type { Environment, EnvironmentComparisonRow } from "@sbom/shared";
import { useEnvironmentComparison, useEnvironments } from "../../lib/queries.ts";
import {
  useCreateEnvironment,
  useDeleteEnvironment,
  useUpdateEnvironment,
} from "../../lib/mutations.ts";
import { useEnvironment } from "../../environments/EnvironmentProvider.tsx";
import { formatNumber, formatRelative } from "../../lib/format.ts";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  ConfirmDeleteModal,
  EmptyState,
  ErrorBanner,
  FormError,
  LoadingBlock,
  Modal,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../../components/ui.tsx";

/**
 * Environment administration, and the one screen that shows more than one estate at once.
 *
 * Two halves, in this order on purpose. The comparison comes first because it is the reason
 * an administrator opens this page — "are the numbers actually separate" is the question the
 * whole feature has to answer, and it is answered by seeing the estates side by side. The
 * table below it is where they are created, renamed and destroyed, which is rare.
 *
 * The comparison never totals a column. There is no row of sums and no field in the payload
 * that could become one: adding a test estate's package count to production's produces a
 * number describing neither, and a figure like that is worse than no figure because it looks
 * authoritative.
 */
export function AdminEnvironmentsPage() {
  const environments = useEnvironments();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Environment | null>(null);
  const [deleting, setDeleting] = useState<Environment | null>(null);

  return (
    <>
      <ComparisonCard />

      <div className="mt-5">
        <Card>
          <CardHeader
            title="Environments"
            subtitle="Isolated estates. Applications never move between them, and no figure on this platform is ever computed across two."
          />

          {environments.error ? (
            <ErrorBanner error={environments.error} onRetry={environments.refetch} />
          ) : environments.isLoading ? (
            <LoadingBlock />
          ) : !environments.data || environments.data.environments.length === 0 ? (
            <EmptyState title="No environments" hint="Create one to start receiving SBOMs." />
          ) : (
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th>Environment</Th>
                    <Th align="right">Applications</Th>
                    <Th align="right">Builds</Th>
                    <Th>Created</Th>
                    <Th width="200px">Actions</Th>
                  </tr>
                </thead>
                <tbody>
                  {environments.data.environments.map((environment) => (
                    <EnvironmentRow
                      key={environment.id}
                      environment={environment}
                      onEdit={() => setEditing(environment)}
                      onDelete={() => setDeleting(environment)}
                    />
                  ))}
                </tbody>
              </Table>
            </TableWrap>
          )}

          <div className="border-t border-border-base p-3">
            <Button size="sm" variant="primary" onClick={() => setCreating(true)}>
              New environment
            </Button>
          </div>
        </Card>
      </div>

      {creating ? <EnvironmentModal onClose={() => setCreating(false)} /> : null}
      {editing ? (
        <EnvironmentModal environment={editing} onClose={() => setEditing(null)} />
      ) : null}
      {deleting ? (
        <DeleteEnvironmentModal environment={deleting} onClose={() => setDeleting(null)} />
      ) : null}
    </>
  );
}

function EnvironmentRow({
  environment,
  onEdit,
  onDelete,
}: {
  environment: Environment;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const { current } = useEnvironment();
  const isCurrent = current.id === environment.id;

  return (
    <Tr>
      <Td>
        <div className="flex items-center gap-2">
          <span className="font-medium text-text-base">{environment.name}</span>
          {/*
            Marking the selected estate matters more here than anywhere else: this is the
            one page where several are on screen, and the actions below act on a row rather
            than on the header's selection.
          */}
          {isCurrent ? <Badge tone="accent">Selected</Badge> : null}
        </div>
        {environment.description ? (
          <p className="mt-0.5 text-[11px] text-text-faint">{environment.description}</p>
        ) : null}
      </Td>
      <Td align="right" className="nums">
        {formatNumber(environment.applicationCount)}
      </Td>
      <Td align="right" className="nums">
        {formatNumber(environment.scanCount)}
      </Td>
      <Td>
        <span className="text-xs text-text-muted">{formatRelative(environment.createdAt)}</span>
      </Td>
      <Td>
        <div className="flex flex-wrap items-center gap-1">
          <Button size="sm" variant="ghost" onClick={onEdit}>
            Edit
          </Button>
          <Button size="sm" variant="ghost" onClick={onDelete}>
            Delete
          </Button>
        </div>
      </Td>
    </Tr>
  );
}

/** Create when `environment` is absent, edit when present. */
function EnvironmentModal({
  environment,
  onClose,
}: {
  environment?: Environment;
  onClose: () => void;
}) {
  const [name, setName] = useState(environment?.name ?? "");
  const [description, setDescription] = useState(environment?.description ?? "");
  const create = useCreateEnvironment();
  const update = useUpdateEnvironment();
  const pending = create.isPending || update.isPending;
  const error = create.error ?? update.error;
  const renaming = environment !== undefined && name.trim() !== environment.name;

  function submit() {
    const trimmed = name.trim();
    if (trimmed === "") return;
    if (environment) {
      update.mutate(
        { id: environment.id, body: { name: trimmed, description: description.trim() } },
        { onSuccess: onClose },
      );
    } else {
      create.mutate({ name: trimmed, description: description.trim() }, { onSuccess: onClose });
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={environment ? `Edit ${environment.name}` : "New environment"}
      footer={
        <>
          <Button onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <Button variant="primary" onClick={submit} disabled={pending || name.trim() === ""}>
            {environment ? "Save" : "Create environment"}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3">
        <div>
          <label htmlFor="env-name" className="mb-1 block text-[11px] font-medium text-text-muted">
            Name
          </label>
          <TextInput
            id="env-name"
            value={name}
            onChange={setName}
            placeholder="Production"
            autoFocus
          />
          <p className="mt-1 text-[11px] text-text-faint">
            Letters, digits, spaces, dots, hyphens and underscores. Pipelines name this string,
            so keep it short and typeable.
          </p>
        </div>

        {/*
          A rename is a change to a published interface, not a relabel. The name appears in CI
          configuration this platform cannot see or update, so the warning is shown at the
          moment of typing rather than buried in documentation nobody opens.
        */}
        {renaming ? (
          <div className="rounded-md border border-warn/40 bg-warn-subtle p-2.5 text-[11px] text-warn">
            Pipelines that name <strong>{environment.name}</strong> in their upload will start
            failing when this is saved. Update their configuration to{" "}
            <strong>{name.trim()}</strong> at the same time. Tokens bound to this environment
            are unaffected — they carry the estate, not its name.
          </div>
        ) : null}

        <div>
          <label htmlFor="env-desc" className="mb-1 block text-[11px] font-medium text-text-muted">
            Description <span className="text-text-faint">(optional)</span>
          </label>
          <TextInput
            id="env-desc"
            value={description}
            onChange={setDescription}
            placeholder="Customer-facing production estate"
          />
        </div>

        <FormError error={error} />
      </div>
    </Modal>
  );
}

function DeleteEnvironmentModal({
  environment,
  onClose,
}: {
  environment: Environment;
  onClose: () => void;
}) {
  const remove = useDeleteEnvironment();

  return (
    <ConfirmDeleteModal
      open
      onClose={onClose}
      onConfirm={() =>
        remove.mutate({ id: environment.id, confirmName: environment.name }, { onSuccess: onClose })
      }
      title={`Delete ${environment.name}`}
      confirmWord={environment.name}
      busy={remove.isPending}
    >
      <p>
        This destroys{" "}
        <strong className="text-text-base">
          {formatNumber(environment.applicationCount)} application
          {environment.applicationCount === 1 ? "" : "s"}
        </strong>{" "}
        and{" "}
        <strong className="text-text-base">
          {formatNumber(environment.scanCount)} build{environment.scanCount === 1 ? "" : "s"}
        </strong>{" "}
        along with their SBOMs, groups, suppressions and reports.
      </p>
      {/*
        Stated rather than implied. "Delete" in most tables means a row disappears; here it
        means years of build history do, and there is no tombstone to restore from.
      */}
      <p>There is no undo, and nothing is kept to recover from.</p>
      <FormError error={remove.error} />
    </ConfirmDeleteModal>
  );
}

/**
 * Every estate's figures, side by side.
 *
 * Columns are estates and rows are measures, rather than the other way round. With two to
 * five environments that keeps the comparison horizontal — the eye moves along a row to
 * compare the same measure — and it means adding an estate widens the table instead of
 * changing what every row means.
 */
function ComparisonCard() {
  const comparison = useEnvironmentComparison();
  const rows = comparison.data?.environments ?? [];
  const scanningEnabled = comparison.data?.vulnerabilityScanningEnabled ?? false;

  if (comparison.error) {
    return (
      <Card>
        <CardHeader title="Side by side" />
        <ErrorBanner error={comparison.error} onRetry={comparison.refetch} />
      </Card>
    );
  }
  if (comparison.isLoading) {
    return (
      <Card>
        <CardHeader title="Side by side" />
        <LoadingBlock />
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader
        title="Side by side"
        subtitle="Each column is one estate, complete in itself. Nothing here is added across environments — a combined total would describe none of them."
      />
      <TableWrap>
        <Table>
          <thead>
            <tr>
              <Th>Measure</Th>
              {rows.map((row) => (
                <Th key={row.id} align="right">
                  {row.name}
                </Th>
              ))}
            </tr>
          </thead>
          <tbody>
            <MeasureRow label="Applications" rows={rows} value={(r) => r.applications.total} />
            <MeasureRow label="Active" rows={rows} value={(r) => r.applications.active} />
            <MeasureRow label="Stale" rows={rows} value={(r) => r.applications.stale} />
            <MeasureRow
              label="Never scanned"
              rows={rows}
              value={(r) => r.applications.neverScanned}
            />
            <MeasureRow label="Builds" rows={rows} value={(r) => r.scans.total} />
            <MeasureRow label="Builds, last 7 days" rows={rows} value={(r) => r.scans.last7d} />
            <MeasureRow label="Packages in use" rows={rows} value={(r) => r.packagesInUse} />
            <Tr>
              <Td>Last build</Td>
              {rows.map((row) => (
                <Td key={row.id} align="right">
                  <span className="text-xs text-text-muted">
                    {row.scans.latestAt ? formatRelative(row.scans.latestAt) : "Never"}
                  </span>
                </Td>
              ))}
            </Tr>

            {/*
              Vulnerability rows render an em dash rather than a zero whenever the block is
              null — scanning switched off, or on but nothing in that estate assessed yet. A
              zero beside another estate's real numbers would read as a clean bill of health,
              which is a stronger claim than the truth and the one nobody questions.
            */}
            <VulnRow
              label="Critical"
              rows={rows}
              enabled={scanningEnabled}
              value={(v) => v.critical}
            />
            <VulnRow label="High" rows={rows} enabled={scanningEnabled} value={(v) => v.high} />
            <VulnRow
              label="Findings, own dependencies"
              rows={rows}
              enabled={scanningEnabled}
              value={(v) => v.appFindings}
            />
            <VulnRow
              label="Findings, base image"
              rows={rows}
              enabled={scanningEnabled}
              value={(v) => v.baseImageFindings}
            />
          </tbody>
        </Table>
      </TableWrap>

      {!scanningEnabled ? (
        <p className="border-t border-border-base px-3 py-2 text-[11px] text-text-faint">
          Vulnerability scanning is switched off, so no estate has been assessed. Those rows are
          blank rather than zero.
        </p>
      ) : null}
    </Card>
  );
}

function MeasureRow({
  label,
  rows,
  value,
}: {
  label: string;
  rows: EnvironmentComparisonRow[];
  value: (row: EnvironmentComparisonRow) => number;
}) {
  return (
    <Tr>
      <Td>{label}</Td>
      {rows.map((row) => (
        <Td key={row.id} align="right" className="nums">
          {formatNumber(value(row))}
        </Td>
      ))}
    </Tr>
  );
}

function VulnRow({
  label,
  rows,
  enabled,
  value,
}: {
  label: string;
  rows: EnvironmentComparisonRow[];
  enabled: boolean;
  value: (vulnerabilities: NonNullable<EnvironmentComparisonRow["vulnerabilities"]>) => number;
}) {
  return (
    <Tr>
      <Td>
        {label}
        {!enabled ? <span className="ml-1 text-[11px] text-text-faint">(not assessed)</span> : null}
      </Td>
      {rows.map((row) => (
        <Td key={row.id} align="right" className="nums">
          {row.vulnerabilities === null ? (
            <span className="text-text-faint" title="Not assessed — this is not a count of zero.">
              —
            </span>
          ) : (
            formatNumber(value(row.vulnerabilities))
          )}
        </Td>
      ))}
    </Tr>
  );
}
