import { Link } from "react-router";
import type { AuditLogEntry } from "@sbom/shared";
import { formatDateTime, formatRelative } from "../../lib/format.ts";
import { useAuditLog } from "../../lib/queries.ts";
import { readEnum, readNumber, readString, useUrlState } from "../../lib/useUrlState.ts";
import {
  Badge,
  Card,
  CardHeader,
  EmptyState,
  ErrorBanner,
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

const TARGET_TYPES = ["", "application", "user", "attribute_definition", "ingest_token"] as const;

/** Human wording for each recorded action, and how alarming it should look. */
const ACTIONS: Record<string, { label: string; tone: "neutral" | "ok" | "warn" | "danger" | "info" }> = {
  "application.create": { label: "Registered application", tone: "ok" },
  "application.update": { label: "Edited application", tone: "neutral" },
  "application.delete": { label: "Deleted application", tone: "danger" },
  "application.confirm": { label: "Confirmed application", tone: "ok" },
  "application.merge_once": { label: "Merged (once)", tone: "warn" },
  "application.merge_always": { label: "Merged (permanent alias)", tone: "warn" },
  "application.alias_add": { label: "Added alias", tone: "neutral" },
  "application.alias_remove": { label: "Removed alias", tone: "warn" },
  "user.create": { label: "Created account", tone: "ok" },
  "user.update": { label: "Changed account", tone: "neutral" },
  "user.reset_password": { label: "Reset password", tone: "warn" },
  "user.delete": { label: "Deleted account", tone: "danger" },
  "attribute_definition.create": { label: "Created attribute", tone: "ok" },
  "attribute_definition.update": { label: "Edited attribute", tone: "neutral" },
  "attribute_definition.delete": { label: "Deleted attribute", tone: "danger" },
  "ingest_token.create": { label: "Created CI token", tone: "ok" },
  "ingest_token.revoke": { label: "Revoked CI token", tone: "warn" },
};

const spec = {
  defaults: { targetType: "" as (typeof TARGET_TYPES)[number], action: "", page: 1 },
  parse: (p: URLSearchParams) => ({
    targetType: readEnum(p, "targetType", TARGET_TYPES, ""),
    action: readString(p, "action"),
    page: readNumber(p, "page", 1),
  }),
};

/**
 * Append-only record of every admin write.
 *
 * The motivating case is a merge: it moves scan history between applications
 * and then deletes the source record, so without this "why does payments-api
 * suddenly have forty more scans, and where did payments_api go" is
 * unanswerable six months later.
 */
export function AdminAuditPage() {
  const { state, setState } = useUrlState(spec);

  const entries = useAuditLog({
    targetType: state.targetType || undefined,
    action: state.action || undefined,
    page: state.page,
    pageSize: 50,
  });

  return (
    <Card>
      <CardHeader
        title="Audit log"
        subtitle="Every administrative change, oldest entries retained indefinitely. Ingest activity is not recorded here — scans are their own history."
      />

      <div className="flex flex-wrap items-center gap-2 border-b border-border-base px-4 py-2.5">
        <Select
          value={state.targetType}
          ariaLabel="Filter by object type"
          onChange={(v) => setState({ targetType: v })}
          options={[
            { value: "", label: "All objects" },
            { value: "application", label: "Applications" },
            { value: "user", label: "Accounts" },
            { value: "attribute_definition", label: "Attributes" },
            { value: "ingest_token", label: "CI tokens" },
          ]}
        />
        <div className="w-56">
          <TextInput
            value={state.action}
            onChange={(v) => setState({ action: v })}
            placeholder="Exact action, e.g. user.delete"
            ariaLabel="Filter by action"
          />
        </div>
      </div>

      {entries.isLoading ? (
        <LoadingBlock label="Loading audit log" />
      ) : entries.error ? (
        <div className="p-4">
          <ErrorBanner error={entries.error} onRetry={() => void entries.refetch()} />
        </div>
      ) : !entries.data || entries.data.items.length === 0 ? (
        <EmptyState
          title="No entries"
          hint="Administrative changes are recorded here as they happen."
        />
      ) : (
        <>
          <TableWrap>
            <Table>
              <thead>
                <tr>
                  <Th>When</Th>
                  <Th>Who</Th>
                  <Th>Action</Th>
                  <Th>Target</Th>
                  <Th>Detail</Th>
                </tr>
              </thead>
              <tbody>
                {entries.data.items.map((entry) => {
                  const meta = ACTIONS[entry.action];
                  return (
                    <Tr key={entry.id}>
                      <Td title={formatDateTime(entry.createdAt)} className="whitespace-nowrap">
                        {formatRelative(entry.createdAt)}
                      </Td>
                      <Td className="text-text-muted">
                        {/* Denormalised at write time, so it survives the actor's
                            account being deleted. */}
                        {entry.actorEmail ?? <span className="text-text-faint">system</span>}
                      </Td>
                      <Td>
                        <Badge tone={meta?.tone ?? "neutral"}>{meta?.label ?? entry.action}</Badge>
                      </Td>
                      <Td>
                        <AuditTarget entry={entry} />
                      </Td>
                      <Td className="text-text-muted">
                        <AuditDetail entry={entry} />
                      </Td>
                    </Tr>
                  );
                })}
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

function str(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function AuditTarget({ entry }: { entry: AuditLogEntry }) {
  const name = str(entry.metadata.name) ?? str(entry.metadata.email) ?? str(entry.metadata.key);

  // Deleted applications keep their id in the row but have no page to link to;
  // rendering a dead link would be worse than plain text.
  if (entry.targetType === "application" && entry.targetId && entry.action !== "application.delete") {
    return (
      <Link to={`/applications/${entry.targetId}`} className="text-accent hover:underline">
        {name ?? entry.targetId.slice(0, 8)}
      </Link>
    );
  }

  return <span className="text-text-base">{name ?? entry.targetId?.slice(0, 8) ?? "—"}</span>;
}

/** One line of the most useful field for each action type. */
function AuditDetail({ entry }: { entry: AuditLogEntry }) {
  const m = entry.metadata;

  if (entry.action.startsWith("application.merge")) {
    const alias = str(m.aliasCreated);
    return (
      <>
        <code className="font-mono text-xs">{str(m.sourceName) ?? "?"}</code> →{" "}
        <code className="font-mono text-xs">{str(m.targetName) ?? "?"}</code>, {String(m.scansMoved ?? 0)}{" "}
        scans moved
        {alias ? <>, alias created</> : null}
      </>
    );
  }

  if (entry.action === "user.update" && m.before && m.after) {
    const before = m.before as { role?: string; isActive?: boolean };
    const after = m.after as { role?: string; isActive?: boolean };
    const parts: string[] = [];
    if (before.role !== after.role) parts.push(`role ${before.role} → ${after.role}`);
    if (before.isActive !== after.isActive) parts.push(after.isActive ? "reactivated" : "deactivated");
    return <>{parts.join(", ") || "no visible change"}</>;
  }

  if (entry.action === "user.create") {
    return <>role {str(m.role) ?? "user"}</>;
  }

  if (entry.action === "user.reset_password") {
    return <>{String(m.sessionsRevoked ?? 0)} session(s) signed out</>;
  }

  if (entry.action === "application.delete") {
    return <>{String(m.scanCount ?? 0)} scans destroyed</>;
  }

  if (entry.action === "application.update" && m.renamed === true) {
    const before = m.before as { name?: string } | undefined;
    return (
      <>
        renamed from <code className="font-mono text-xs">{before?.name ?? "?"}</code>
      </>
    );
  }

  if (entry.action === "attribute_definition.delete") {
    return <>{String(m.valuesPurged ?? 0)} value(s) purged</>;
  }

  if (entry.action.startsWith("application.alias")) {
    return <code className="font-mono text-xs">{str(m.aliasName) ?? "—"}</code>;
  }

  return <span className="text-text-faint">—</span>;
}
