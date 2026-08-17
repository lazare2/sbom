import { useEffect, useState } from "react";
import type { ApplicationDetail, ApplicationSummary, Attributes } from "@sbom/shared";
import { AttributeFields } from "../../components/AttributeFields.tsx";
import { useCreateApplication, useUpdateApplication } from "../../lib/mutations.ts";
import { useAttributeDefinitions } from "../../lib/queries.ts";
import { Button, FormError, FormRow, Modal, Select, TextInput } from "../../components/ui.tsx";

/**
 * Create or edit an application.
 *
 * One component for both, because the fields are identical and the only real
 * difference is which mutation fires. Reached from the admin applications table
 * and from the application detail page.
 */
export function ApplicationFormModal({
  open,
  onClose,
  existing,
  onSaved,
}: {
  open: boolean;
  onClose: () => void;
  /** Omit to create. */
  existing?: ApplicationSummary | ApplicationDetail | null;
  onSaved?: (app: ApplicationDetail) => void;
}) {
  const definitions = useAttributeDefinitions();
  const createApp = useCreateApplication();
  const updateApp = useUpdateApplication();

  const [name, setName] = useState("");
  const [status, setStatus] = useState<"active" | "inactive">("active");
  const [attributes, setAttributes] = useState<Attributes>({});

  const isEdit = Boolean(existing);

  // Reseed whenever the modal opens on a different record, so an edit never
  // shows the previous application's values for a moment.
  useEffect(() => {
    if (!open) return;
    setName(existing?.name ?? "");
    setStatus(existing && existing.status !== "pending_confirmation" ? existing.status : "active");
    setAttributes(existing?.attributes ?? {});
    createApp.reset();
    updateApp.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- mutation objects are new every render
  }, [open, existing?.id]);

  const pending = createApp.isPending || updateApp.isPending;
  const error = createApp.error ?? updateApp.error;
  const renaming = isEdit && existing !== undefined && existing !== null && name !== existing.name;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    try {
      if (existing) {
        const result = await updateApp.mutateAsync({
          id: existing.id,
          body: {
            name,
            attributes,
            // A pending application's status is resolved through confirm/merge,
            // not edited here, so it is omitted rather than sent unchanged.
            ...(existing.status === "pending_confirmation" ? {} : { status }),
          },
        });
        onSaved?.(result.application);
      } else {
        const result = await createApp.mutateAsync({ name, status, attributes });
        onSaved?.(result.application);
      }
      onClose();
    } catch {
      // Rendered from the mutation error state.
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isEdit ? `Edit ${existing?.name}` : "Register an application"}
      footer={
        <>
          <Button onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="application-form" disabled={!name.trim() || pending}>
            {pending ? "Saving…" : isEdit ? "Save changes" : "Create application"}
          </Button>
        </>
      }
    >
      <form id="application-form" onSubmit={submit} className="space-y-3" noValidate>
        <FormError error={error} />

        <FormRow
          label="Name"
          htmlFor="app-name"
          hint={
            isEdit
              ? undefined
              : "Must match the app_name your CI pipeline posts, or the first scan will create a second, unconfirmed record."
          }
        >
          <TextInput id="app-name" value={name} onChange={setName} autoFocus required />
        </FormRow>

        {renaming ? (
          <div className="rounded-md border border-warn bg-warn-subtle px-3 py-2 text-xs text-warn">
            Renaming frees the old name. If CI still posts{" "}
            <code className="font-mono">{existing?.name}</code>, the next build will create a new
            unconfirmed application instead of landing here — add it as an alias afterwards to avoid that.
          </div>
        ) : null}

        {existing?.status === "pending_confirmation" ? null : (
          <FormRow
            label="Status"
            htmlFor="app-status"
            hint="Inactive applications are hidden from the default list but keep their full scan history."
          >
            <Select
              id="app-status"
              value={status}
              onChange={(v) => setStatus(v as "active" | "inactive")}
              options={[
                { value: "active", label: "Active" },
                { value: "inactive", label: "Inactive" },
              ]}
            />
          </FormRow>
        )}

        <div className="border-t border-border-base pt-3">
          <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-text-faint">Attributes</p>
          <AttributeFields
            definitions={definitions.data ?? []}
            values={attributes}
            onChange={setAttributes}
          />
        </div>
      </form>
    </Modal>
  );
}
