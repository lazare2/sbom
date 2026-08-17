import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import type { ApplicationSummary, Attributes } from "@sbom/shared";
import { AttributeFields } from "../../components/AttributeFields.tsx";
import { formatNumber, formatRelative } from "../../lib/format.ts";
import {
  useConfirmApplication,
  useDeleteApplication,
  useMergeApplication,
} from "../../lib/mutations.ts";
import { useApplications, useAttributeDefinitions } from "../../lib/queries.ts";
import { useDebounced } from "../../lib/useDebounced.ts";
import {
  Button,
  Card,
  CardHeader,
  ConfirmDeleteModal,
  EmptyState,
  ErrorBanner,
  FormError,
  FormRow,
  LoadingBlock,
  Modal,
  Select,
  Table,
  TableWrap,
  Td,
  TextInput,
  Th,
  Tr,
} from "../../components/ui.tsx";

/**
 * Triage for applications the ingest endpoint created on its own.
 *
 * These exist because a scan arrived under an `app_name` matching nothing. The
 * platform never rejects that upload — losing a build's SBOM because nobody
 * pre-registered the repo would be the worse failure — so the cost is this
 * queue, and the four resolutions below are how it gets drained.
 */
export function AdminPendingPage() {
  const [confirmTarget, setConfirmTarget] = useState<ApplicationSummary | null>(null);
  const [mergeTarget, setMergeTarget] = useState<ApplicationSummary | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ApplicationSummary | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);

  const deleteApp = useDeleteApplication();

  const pending = useApplications({
    status: ["pending_confirmation"],
    sortBy: "lastScanAt",
    sortDir: "desc",
    pageSize: 100,
  });

  return (
    <>
      <Card>
        <CardHeader
          title="Applications awaiting confirmation"
          subtitle="Created automatically when a scan arrived under a name that matched no application or alias."
        />

        {actionError ? (
          <div className="px-4 pt-3">
            <FormError error={actionError} />
          </div>
        ) : null}

        {pending.isLoading ? (
          <LoadingBlock label="Loading queue" />
        ) : pending.error ? (
          <div className="p-4">
            <ErrorBanner error={pending.error} onRetry={() => void pending.refetch()} />
          </div>
        ) : !pending.data || pending.data.items.length === 0 ? (
          <EmptyState
            title="Nothing to confirm"
            hint="Every application that has reported a scan is a recognised one. New unconfirmed records appear here automatically."
          />
        ) : (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>Name reported by CI</Th>
                  <Th align="right">Scans</Th>
                  <Th align="right">Packages</Th>
                  <Th>First seen</Th>
                  <Th>Last scan</Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {pending.data.items.map((app) => (
                  <Tr key={app.id}>
                    <Td>
                      <Link
                        to={`/applications/${app.id}`}
                        className="font-mono text-xs font-medium text-accent hover:underline"
                      >
                        {app.name}
                      </Link>
                    </Td>
                    <Td align="right" className="nums">
                      {formatNumber(app.scanCount)}
                    </Td>
                    <Td align="right" className="nums">
                      {formatNumber(app.latestComponentCount)}
                    </Td>
                    <Td title={app.createdAt}>{formatRelative(app.createdAt)}</Td>
                    <Td title={app.lastScanAt ?? ""}>{formatRelative(app.lastScanAt)}</Td>
                    <Td align="right">
                      <div className="flex flex-wrap justify-end gap-1.5">
                        <Button
                          size="sm"
                          variant="primary"
                          onClick={() => {
                            setActionError(null);
                            setConfirmTarget(app);
                          }}
                          title="This is a real application under its own name"
                        >
                          Confirm
                        </Button>
                        <Button
                          size="sm"
                          onClick={() => {
                            setActionError(null);
                            setMergeTarget(app);
                          }}
                          title="These scans belong to an application that already exists"
                        >
                          Merge
                        </Button>
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
        )}
      </Card>

      <ConfirmModal target={confirmTarget} onClose={() => setConfirmTarget(null)} />
      <MergeModal target={mergeTarget} onClose={() => setMergeTarget(null)} />

      <ConfirmDeleteModal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        confirmWord={deleteTarget?.name ?? ""}
        title="Delete unconfirmed application"
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
          Deletes <strong className="text-text-base">{deleteTarget?.name}</strong> and its{" "}
          {formatNumber(deleteTarget?.scanCount ?? 0)} scan
          {deleteTarget?.scanCount === 1 ? "" : "s"}.
        </p>
        <p>
          If the pipeline that produced these is still running, it will recreate this record on its next
          build. Merging with an alias is the way to stop that permanently.
        </p>
      </ConfirmDeleteModal>
    </>
  );
}

// ---------------------------------------------------------------------------

function ConfirmModal({ target, onClose }: { target: ApplicationSummary | null; onClose: () => void }) {
  const definitions = useAttributeDefinitions();
  const confirmApp = useConfirmApplication();
  const [name, setName] = useState("");
  const [attributes, setAttributes] = useState<Attributes>({});

  useEffect(() => {
    if (!target) return;
    setName(target.name);
    setAttributes(target.attributes ?? {});
    confirmApp.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- mutation object is new each render
  }, [target?.id]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!target) return;
    try {
      await confirmApp.mutateAsync({
        id: target.id,
        body: { ...(name !== target.name ? { name } : {}), attributes },
      });
      onClose();
    } catch {
      // Rendered from the mutation error state.
    }
  }

  return (
    <Modal
      open={target !== null}
      onClose={onClose}
      title="Confirm application"
      footer={
        <>
          <Button onClick={onClose} disabled={confirmApp.isPending}>
            Cancel
          </Button>
          <Button
            variant="primary"
            type="submit"
            form="confirm-app-form"
            disabled={!name.trim() || confirmApp.isPending}
          >
            {confirmApp.isPending ? "Confirming…" : "Confirm and activate"}
          </Button>
        </>
      }
    >
      <form id="confirm-app-form" onSubmit={submit} className="space-y-3" noValidate>
        <FormError error={confirmApp.error} />

        <p className="text-sm text-text-muted">
          Marks this as a real application and makes it active. Its{" "}
          {formatNumber(target?.scanCount ?? 0)} existing scan
          {target?.scanCount === 1 ? "" : "s"} are kept.
        </p>

        <FormRow
          label="Name"
          htmlFor="confirm-name"
          hint={
            name !== target?.name
              ? "Renaming means future scans under the old CI name will create a new unconfirmed record. Merge with an alias instead if the CI name is not going to change."
              : "Leave as-is unless the CI name is wrong; this is the name CI posts."
          }
        >
          <TextInput id="confirm-name" value={name} onChange={setName} autoFocus />
        </FormRow>

        <div className="border-t border-border-base pt-3">
          <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-text-faint">Attributes</p>
          <AttributeFields
            definitions={definitions.data ?? []}
            values={attributes}
            onChange={setAttributes}
            idPrefix="confirm"
          />
        </div>
      </form>
    </Modal>
  );
}

function MergeModal({ target, onClose }: { target: ApplicationSummary | null; onClose: () => void }) {
  const mergeApp = useMergeApplication();
  const [search, setSearch] = useState("");
  const [targetId, setTargetId] = useState("");
  const [always, setAlways] = useState(true);
  const debounced = useDebounced(search, 250);

  // Merge destinations must already be confirmed — merging one unconfirmed
  // record into another just moves the problem.
  const candidates = useApplications({
    search: debounced || undefined,
    status: ["active", "inactive"],
    pageSize: 50,
    sortBy: "name",
  });

  useEffect(() => {
    if (!target) return;
    setSearch("");
    setTargetId("");
    setAlways(true);
    mergeApp.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- mutation object is new each render
  }, [target?.id]);

  const options = useMemo(
    () => [
      { value: "", label: "— choose an application —" },
      ...(candidates.data?.items ?? []).map((a) => ({ value: a.id, label: a.name })),
    ],
    [candidates.data],
  );

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!target || !targetId) return;
    try {
      await mergeApp.mutateAsync({ id: target.id, body: { targetApplicationId: targetId, always } });
      onClose();
    } catch {
      // Rendered from the mutation error state.
    }
  }

  return (
    <Modal
      open={target !== null}
      onClose={onClose}
      title={`Merge ${target?.name ?? ""}`}
      footer={
        <>
          <Button onClick={onClose} disabled={mergeApp.isPending}>
            Cancel
          </Button>
          <Button
            variant="primary"
            type="submit"
            form="merge-app-form"
            disabled={!targetId || mergeApp.isPending}
          >
            {mergeApp.isPending ? "Merging…" : "Merge"}
          </Button>
        </>
      }
    >
      <form id="merge-app-form" onSubmit={submit} className="space-y-3" noValidate>
        <FormError error={mergeApp.error} />

        <p className="text-sm text-text-muted">
          Moves all {formatNumber(target?.scanCount ?? 0)} scan
          {target?.scanCount === 1 ? "" : "s"} from{" "}
          <code className="font-mono text-xs text-text-base">{target?.name}</code> into the application
          you choose, then deletes this record. No SBOM data is lost.
        </p>

        <FormRow label="Search" htmlFor="merge-search">
          <TextInput
            id="merge-search"
            value={search}
            onChange={setSearch}
            placeholder="Filter the list below…"
            autoFocus
          />
        </FormRow>

        <FormRow label="Merge into" htmlFor="merge-target">
          <Select id="merge-target" value={targetId} onChange={setTargetId} options={options} />
        </FormRow>

        <fieldset className="space-y-2 rounded-md border border-border-base p-3">
          <legend className="px-1 text-[11px] font-medium uppercase tracking-wide text-text-faint">
            Future scans under this name
          </legend>

          <label className="flex cursor-pointer items-start gap-2 text-sm select-none">
            <input
              type="radio"
              name="merge-mode"
              checked={always}
              onChange={() => setAlways(true)}
              className="mt-0.5 accent-[var(--accent)]"
            />
            <span>
              <span className="font-medium text-text-base">Always merge</span>
              <span className="block text-xs text-text-muted">
                Records a permanent alias, so every future build posting{" "}
                <code className="font-mono">{target?.name}</code> lands on the target automatically. Choose
                this when the CI job name is not going to change.
              </span>
            </span>
          </label>

          <label className="flex cursor-pointer items-start gap-2 text-sm select-none">
            <input
              type="radio"
              name="merge-mode"
              checked={!always}
              onChange={() => setAlways(false)}
              className="mt-0.5 accent-[var(--accent)]"
            />
            <span>
              <span className="font-medium text-text-base">Just this once</span>
              <span className="block text-xs text-text-muted">
                Moves the existing scans only. If the same name arrives again it will create a new
                unconfirmed record. Choose this when the pipeline has already been fixed.
              </span>
            </span>
          </label>
        </fieldset>
      </form>
    </Modal>
  );
}
