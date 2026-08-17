import { useEffect, useState } from "react";
import { useClientSort } from "../../lib/useSort.ts";
import type { AttributeDefinition, AttributeType } from "@sbom/shared";
import {
  useCreateAttributeDefinition,
  useDeleteAttributeDefinition,
  useUpdateAttributeDefinition,
} from "../../lib/mutations.ts";
import { useAttributeDefinitions } from "../../lib/queries.ts";
import { ApiError } from "../../lib/api.ts";
import {
  Badge,
  Button,
  Card,
  CardHeader,
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
  Textarea,
  TextInput,
  Th,
  Tr,
} from "../../components/ui.tsx";

const TYPE_LABELS: Record<AttributeType, string> = {
  string: "Text (single line)",
  text: "Text (multi-line)",
  select: "Choice from a list",
  number: "Number",
  boolean: "Yes / no",
};

/**
 * Sortable columns of the attribute-definition table. Client-side: the endpoint returns
 * every definition at once, since there are only ever a handful.
 */
const ATTRIBUTE_COLUMNS = {
  label: "text",
  key: "text",
  type: "text",
  sortOrder: "number",
  status: "text",
} as const;

/**
 * Manage the attribute definitions that drive per-application metadata.
 *
 * These are rows rather than columns so that adding "tier" or "cost centre" is
 * an admin action instead of a schema migration and a deploy. Values live in a
 * jsonb column on `application`, validated against these definitions on write.
 */
export function AdminAttributesPage() {
  // Includes deactivated ones: this is the screen where they get reactivated.
  const definitions = useAttributeDefinitions(true);
  const updateDef = useUpdateAttributeDefinition();
  const deleteDef = useDeleteAttributeDefinition();

  const [editing, setEditing] = useState<AttributeDefinition | null>(null);
  const [creating, setCreating] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<AttributeDefinition | null>(null);

  /*
    Defaults to `sortOrder`, which is the order the fields are presented in on every
    application form. Opening this screen and seeing a different order than the forms use
    would make the Order column look like it does nothing.
  */
  const sort = useClientSort(
    definitions.data,
    ATTRIBUTE_COLUMNS,
    { sortBy: "sortOrder", sortDir: "asc" },
    (def, field) => {
      switch (field) {
        case "key":
          return def.key;
        case "type":
          return def.type;
        case "sortOrder":
          return def.sortOrder;
        case "status":
          return def.isActive ? "active" : "inactive";
        case "label":
        default:
          return def.label;
      }
    },
    (def) => def.key,
  );
  const [actionError, setActionError] = useState<unknown>(null);

  async function toggleActive(def: AttributeDefinition) {
    setActionError(null);
    try {
      await updateDef.mutateAsync({ id: def.id, body: { isActive: !def.isActive } });
    } catch (err) {
      setActionError(err);
    }
  }

  return (
    <>
      <Card>
        <CardHeader
          title="Application attributes"
          subtitle="Squad, owner and severity are seeded. Anything added here appears on every application's edit form and as a filter on the applications list."
          actions={
            <Button variant="primary" size="sm" onClick={() => setCreating(true)}>
              New attribute
            </Button>
          }
        />

        {actionError ? (
          <div className="px-4 pt-3">
            <FormError error={actionError} />
          </div>
        ) : null}

        {definitions.isLoading ? (
          <LoadingBlock label="Loading attributes" />
        ) : definitions.error ? (
          <div className="p-4">
            <ErrorBanner error={definitions.error} onRetry={() => void definitions.refetch()} />
          </div>
        ) : !definitions.data || definitions.data.length === 0 ? (
          <EmptyState
            title="No attributes defined"
            hint="Without any, applications can still be tracked but cannot be grouped by squad or owner."
          />
        ) : (
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th onSort={() => sort.toggle("label")} sorted={sort.stateOf("label")}>
                    Label
                  </Th>
                  <Th onSort={() => sort.toggle("key")} sorted={sort.stateOf("key")}>
                    Key
                  </Th>
                  <Th onSort={() => sort.toggle("type")} sorted={sort.stateOf("type")}>
                    Type
                  </Th>
                  {/* A list of choices; there is no single value to order it by. */}
                  <Th>Options</Th>
                  <Th onSort={() => sort.toggle("sortOrder")} sorted={sort.stateOf("sortOrder")} align="right">
                    Order
                  </Th>
                  <Th onSort={() => sort.toggle("status")} sorted={sort.stateOf("status")}>
                    Status
                  </Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {sort.rows.map((def) => (
                  <Tr key={def.id}>
                    <Td className="font-medium text-text-base">{def.label}</Td>
                    <Td>
                      <code className="font-mono text-xs text-text-muted">{def.key}</code>
                    </Td>
                    <Td className="text-text-muted">{TYPE_LABELS[def.type]}</Td>
                    <Td className="text-text-muted">
                      {def.options && def.options.length > 0 ? def.options.join(", ") : "—"}
                    </Td>
                    <Td align="right" className="nums">
                      {def.sortOrder}
                    </Td>
                    <Td>
                      {def.isActive ? (
                        <Badge tone="ok">Active</Badge>
                      ) : (
                        <Badge
                          tone="neutral"
                          title="Hidden from edit forms and filters. Existing values are kept and still searchable."
                        >
                          Hidden
                        </Badge>
                      )}
                    </Td>
                    <Td align="right">
                      <div className="flex justify-end gap-1.5">
                        <Button size="sm" onClick={() => setEditing(def)}>
                          Edit
                        </Button>
                        <Button size="sm" onClick={() => void toggleActive(def)} disabled={updateDef.isPending}>
                          {def.isActive ? "Hide" : "Show"}
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            setActionError(null);
                            deleteDef.reset();
                            setDeleteTarget(def);
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

      <AttributeFormModal open={creating} onClose={() => setCreating(false)} />
      <AttributeFormModal open={editing !== null} existing={editing} onClose={() => setEditing(null)} />

      <DeleteAttributeModal
        target={deleteTarget}
        onClose={() => setDeleteTarget(null)}
        mutation={deleteDef}
      />
    </>
  );
}

// ---------------------------------------------------------------------------

function AttributeFormModal({
  open,
  onClose,
  existing,
}: {
  open: boolean;
  onClose: () => void;
  existing?: AttributeDefinition | null;
}) {
  const createDef = useCreateAttributeDefinition();
  const updateDef = useUpdateAttributeDefinition();

  const [key, setKey] = useState("");
  const [label, setLabel] = useState("");
  const [type, setType] = useState<AttributeType>("string");
  const [optionsText, setOptionsText] = useState("");
  const [sortOrder, setSortOrder] = useState("0");

  const isEdit = Boolean(existing);

  useEffect(() => {
    if (!open) return;
    setKey(existing?.key ?? "");
    setLabel(existing?.label ?? "");
    setType(existing?.type ?? "string");
    setOptionsText((existing?.options ?? []).join("\n"));
    setSortOrder(String(existing?.sortOrder ?? 0));
    createDef.reset();
    updateDef.reset();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- mutation objects are new every render
  }, [open, existing?.id]);

  /**
   * Auto-derives the key from the label while creating.
   *
   * The key is immutable once created — it is the property name inside every
   * application's jsonb document — so getting it right the first time matters,
   * and making the admin invent `lower_snake_case` by hand is how typos happen.
   */
  function onLabelChange(next: string) {
    setLabel(next);
    if (!isEdit) {
      setKey(
        next
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "_")
          .replace(/^_+|_+$/g, "")
          .replace(/^([0-9])/, "attr_$1"),
      );
    }
  }

  const options = optionsText
    .split("\n")
    .map((o) => o.trim())
    .filter(Boolean);

  const pending = createDef.isPending || updateDef.isPending;
  const error = createDef.error ?? updateDef.error;
  const keyValid = /^[a-z][a-z0-9_]*$/.test(key);
  const canSubmit =
    label.trim().length > 0 && (isEdit || keyValid) && (type !== "select" || options.length > 0) && !pending;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    const body = {
      label: label.trim(),
      type,
      options: type === "select" ? options : null,
      sortOrder: Number(sortOrder) || 0,
      isActive: existing?.isActive ?? true,
    };
    try {
      if (existing) {
        await updateDef.mutateAsync({ id: existing.id, body });
      } else {
        await createDef.mutateAsync({ key, ...body });
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
      title={isEdit ? `Edit ${existing?.label}` : "New attribute"}
      footer={
        <>
          <Button onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="attribute-form" disabled={!canSubmit}>
            {pending ? "Saving…" : isEdit ? "Save changes" : "Create attribute"}
          </Button>
        </>
      }
    >
      <form id="attribute-form" onSubmit={submit} className="space-y-3" noValidate>
        <FormError error={error} />

        <FormRow label="Label" htmlFor="attr-label" hint="What people see on the form and in filters.">
          <TextInput id="attr-label" value={label} onChange={onLabelChange} autoFocus required />
        </FormRow>

        <FormRow
          label="Key"
          htmlFor="attr-key"
          error={!isEdit && key.length > 0 && !keyValid ? "Must be lower_snake_case, starting with a letter" : undefined}
          hint={
            isEdit
              ? "The key cannot be changed — it is the field name stored on every application that uses it."
              : "Generated from the label. Stored on each application; cannot be changed later."
          }
        >
          <TextInput id="attr-key" value={key} onChange={setKey} required />
        </FormRow>

        <FormRow label="Type" htmlFor="attr-type">
          <Select
            id="attr-type"
            value={type}
            onChange={(v) => setType(v as AttributeType)}
            options={(Object.keys(TYPE_LABELS) as AttributeType[]).map((t) => ({
              value: t,
              label: TYPE_LABELS[t],
            }))}
          />
        </FormRow>

        {type === "select" ? (
          <FormRow
            label="Options"
            htmlFor="attr-options"
            hint="One per line. Values outside this list are rejected when an application is saved."
          >
            <Textarea
              id="attr-options"
              value={optionsText}
              onChange={setOptionsText}
              rows={5}
              placeholder={"critical\nhigh\nmedium\nlow"}
            />
          </FormRow>
        ) : null}

        <FormRow
          label="Sort order"
          htmlFor="attr-sort"
          hint="Lower numbers appear first on forms and filter bars."
        >
          <TextInput id="attr-sort" type="number" value={sortOrder} onChange={setSortOrder} />
        </FormRow>
      </form>
    </Modal>
  );
}

/**
 * Deletion needs its own modal rather than the generic confirm.
 *
 * The API refuses to delete a definition that applications still carry values
 * for, returning a 409 with the count. That refusal is the useful part — it
 * turns "delete this" into an informed choice between hiding the attribute and
 * destroying data — so the modal surfaces the count and offers purge as a
 * separate, deliberate second step.
 */
function DeleteAttributeModal({
  target,
  onClose,
  mutation,
}: {
  target: AttributeDefinition | null;
  onClose: () => void;
  mutation: ReturnType<typeof useDeleteAttributeDefinition>;
}) {
  const [inUse, setInUse] = useState<number | null>(null);

  useEffect(() => {
    if (target) setInUse(null);
  }, [target?.id]);

  function run(purge: boolean) {
    if (!target) return;
    mutation.mutate(
      { id: target.id, purge },
      {
        onSuccess: () => {
          setInUse(null);
          onClose();
        },
        onError: (err) => {
          // The 409's details carry how many applications are affected, which
          // is what turns the retry into an informed decision.
          if (err instanceof ApiError && err.status === 409) {
            const details = err.details as { applicationsAffected?: number } | undefined;
            setInUse(details?.applicationsAffected ?? 0);
          }
        },
      },
    );
  }

  return (
    <Modal
      open={target !== null}
      onClose={() => {
        mutation.reset();
        onClose();
      }}
      title={`Delete ${target?.label ?? "attribute"}`}
      footer={
        <>
          <Button
            onClick={() => {
              mutation.reset();
              onClose();
            }}
            disabled={mutation.isPending}
          >
            Cancel
          </Button>
          <Button variant="danger" onClick={() => run(inUse !== null)} disabled={mutation.isPending}>
            {mutation.isPending
              ? "Deleting…"
              : inUse !== null
                ? `Delete and clear ${inUse} value${inUse === 1 ? "" : "s"}`
                : "Delete"}
          </Button>
        </>
      }
    >
      <div className="space-y-3 text-sm text-text-muted">
        {inUse === null ? <FormError error={mutation.error} /> : null}

        {inUse !== null ? (
          <div className="rounded-md border border-warn bg-warn-subtle px-3 py-2 text-xs text-warn">
            <strong>{inUse}</strong> application{inUse === 1 ? " carries" : "s carry"} a value for{" "}
            <code className="font-mono">{target?.key}</code>. Deleting now also removes{" "}
            {inUse === 1 ? "that value" : "those values"} permanently.
          </div>
        ) : null}

        <p>
          Removes the <code className="font-mono text-text-base">{target?.key}</code> attribute from the
          edit form and from the applications list filters.
        </p>
        <p>
          Hiding it instead keeps every stored value searchable while taking it off the forms — usually the
          better choice for an attribute that is simply no longer collected.
        </p>
      </div>
    </Modal>
  );
}
