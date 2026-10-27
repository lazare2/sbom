import { useState } from "react";
import type { SquadDetail, SquadSummary, TeamRef, TribeDetail, TribeSummary } from "@sbom/shared";
import { useCreateSquad, useCreateTribe, useUpdateSquad, useUpdateTribe } from "../lib/mutations.ts";
import { useSquadSettings, useTribes } from "../lib/queries.ts";
import { Button, Checkbox, FormError, FormRow, LoadingBlock, Modal, Textarea, TextInput } from "./ui.tsx";

/**
 * The squad and tribe forms, shared by the Access pages and by the attribute field that offers
 * "Create squad" when a project names one that does not exist yet.
 */

/** A searchable checklist of squads or tribes, for choosing several by name. */
export function TeamChecklist({
  items,
  selected,
  onChange,
  noun,
  loading = false,
}: {
  items: TeamRef[];
  selected: string[];
  onChange: (next: string[]) => void;
  /** "tribe" or "squad", for the search placeholder and the empty state. */
  noun: string;
  loading?: boolean;
}) {
  const [search, setSearch] = useState("");
  const needle = search.trim().toLowerCase();
  // Chosen ones first, so what is selected never depends on scrolling to find it.
  const shown = items
    .filter((t) => needle === "" || t.name.toLowerCase().includes(needle))
    .sort((a, b) => Number(selected.includes(b.id)) - Number(selected.includes(a.id)));

  return (
    <div className="space-y-1.5">
      {items.length > 8 ? (
        <TextInput value={search} onChange={setSearch} placeholder={`Search ${noun}s…`} ariaLabel={`Search ${noun}s`} />
      ) : null}
      <div className="max-h-48 overflow-y-auto rounded-md border border-border-base p-2">
        {loading ? (
          <LoadingBlock label={`Loading ${noun}s`} />
        ) : items.length === 0 ? (
          <p className="text-[11px] text-text-faint">No {noun}s exist yet.</p>
        ) : shown.length === 0 ? (
          <p className="text-[11px] text-text-faint">No {noun} matches that search.</p>
        ) : (
          <div className="flex flex-col gap-1">
            {shown.map((t) => (
              <Checkbox
                key={t.id}
                label={t.name}
                checked={selected.includes(t.id)}
                onChange={(on) => onChange(on ? [...selected, t.id] : selected.filter((id) => id !== t.id))}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * Create or edit a squad: name, address, description and the tribes it sits under.
 *
 * `initialName` pre-fills a new squad's name, for the attribute field's "Create squad".
 */
export function SquadFormModal({
  target,
  initialName = "",
  onClose,
  onSaved,
}: {
  target: SquadSummary | "new" | null;
  initialName?: string;
  onClose: () => void;
  onSaved?: (squad: SquadDetail, created: boolean) => void;
}) {
  const existing = target !== null && target !== "new" ? target : null;
  const create = useCreateSquad();
  const update = useUpdateSquad();
  const tribes = useTribes();
  const settings = useSquadSettings();
  const requireTribe = settings.data?.settings.requireTribe === true;

  const [name, setName] = useState(existing?.name ?? initialName);
  const [email, setEmail] = useState(existing?.email ?? "");
  const [description, setDescription] = useState(existing?.description ?? "");
  const [tribeIds, setTribeIds] = useState<string[]>(existing?.tribes.map((t) => t.id) ?? []);
  const error = create.error ?? update.error;
  const busy = create.isPending || update.isPending;
  const missingTribe = requireTribe && tribeIds.length === 0;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    // Opened from inside a project's form, this one's submit must not reach that form too:
    // React carries the event up the component tree even across a portal.
    e.stopPropagation();
    const body = { name: name.trim(), email: email.trim(), description: description.trim(), tribeIds };
    try {
      if (existing) {
        const saved = await update.mutateAsync({ id: existing.id, body });
        onClose();
        onSaved?.(saved.squad, false);
      } else {
        const created = await create.mutateAsync(body);
        onClose();
        onSaved?.(created.squad, true);
      }
    } catch {
      // Rendered from the mutation's error state.
    }
  }

  return (
    <Modal
      open={target !== null}
      onClose={onClose}
      title={existing ? `Edit ${existing.name}` : "New squad"}
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="primary"
            type="submit"
            form="squad-form"
            disabled={busy || name.trim() === "" || missingTribe}
          >
            {busy ? "Saving…" : existing ? "Save" : "Create squad"}
          </Button>
        </>
      }
    >
      <form id="squad-form" onSubmit={submit} className="space-y-3" noValidate>
        <FormError error={error} />
        <FormRow label="Name" htmlFor="squad-name" hint="Commas are not allowed: a project's squad attribute lists squads separated by commas.">
          <TextInput id="squad-name" value={name} onChange={setName} placeholder="Payments" autoFocus />
        </FormRow>
        <FormRow
          label={requireTribe ? "Tribes" : "Tribes (optional)"}
          hint={
            missingTribe
              ? "Choose at least one: every squad must belong to a tribe."
              : "A squad can sit under several tribes. Its members see the projects assigned to each."
          }
        >
          <TeamChecklist
            items={tribes.data?.tribes ?? []}
            selected={tribeIds}
            onChange={setTribeIds}
            noun="tribe"
            loading={tribes.isLoading}
          />
        </FormRow>
        <FormRow
          label="Team email (optional)"
          htmlFor="squad-email"
          hint="The squad's shared mailbox, kept for reports about its applications. Nothing is sent to it yet."
        >
          <TextInput id="squad-email" value={email} onChange={setEmail} placeholder="payments-team@example.com" />
        </FormRow>
        <FormRow label="Description (optional)" htmlFor="squad-description">
          <Textarea id="squad-description" rows={2} value={description} onChange={setDescription} />
        </FormRow>
      </form>
    </Modal>
  );
}

/** Create or edit a tribe's name, address and description. Squads and projects are set elsewhere. */
export function TribeFormModal({
  target,
  initialName = "",
  onClose,
  onSaved,
}: {
  target: TribeSummary | "new" | null;
  initialName?: string;
  onClose: () => void;
  onSaved?: (tribe: TribeDetail, created: boolean) => void;
}) {
  const existing = target !== null && target !== "new" ? target : null;
  const create = useCreateTribe();
  const update = useUpdateTribe();
  const [name, setName] = useState(existing?.name ?? initialName);
  const [email, setEmail] = useState(existing?.email ?? "");
  const [description, setDescription] = useState(existing?.description ?? "");
  const error = create.error ?? update.error;
  const busy = create.isPending || update.isPending;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    e.stopPropagation(); // See SquadFormModal: never submit the project form around it.
    const body = { name: name.trim(), email: email.trim(), description: description.trim() };
    try {
      if (existing) {
        const saved = await update.mutateAsync({ id: existing.id, body });
        onClose();
        onSaved?.(saved.tribe, false);
      } else {
        const created = await create.mutateAsync(body);
        onClose();
        onSaved?.(created.tribe, true);
      }
    } catch {
      // Rendered from the mutation's error state.
    }
  }

  return (
    <Modal
      open={target !== null}
      onClose={onClose}
      title={existing ? `Edit ${existing.name}` : "New tribe"}
      footer={
        <>
          <Button onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" form="tribe-form" disabled={busy || name.trim() === ""}>
            {busy ? "Saving…" : existing ? "Save" : "Create tribe"}
          </Button>
        </>
      }
    >
      <form id="tribe-form" onSubmit={submit} className="space-y-3" noValidate>
        <FormError error={error} />
        <FormRow label="Name" htmlFor="tribe-name" hint="Commas are not allowed: a project's tribe attribute lists tribes separated by commas.">
          <TextInput id="tribe-name" value={name} onChange={setName} placeholder="Retail Banking" autoFocus />
        </FormRow>
        <FormRow
          label="Tribe email (optional)"
          htmlFor="tribe-email"
          hint="Kept for reports about the tribe's projects. Nothing is sent to it yet."
        >
          <TextInput id="tribe-email" value={email} onChange={setEmail} placeholder="retail-tribe@example.com" />
        </FormRow>
        <FormRow label="Description (optional)" htmlFor="tribe-description">
          <Textarea id="tribe-description" rows={2} value={description} onChange={setDescription} />
        </FormRow>
      </form>
    </Modal>
  );
}
