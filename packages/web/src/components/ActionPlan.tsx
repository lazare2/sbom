import { useState } from "react";
import {
  PROJECT_STATUS_LABELS,
  type ActionPlanResponse,
  type ModuleActionPlanItem,
  type ProjectStatus,
  type Urgency,
} from "@sbom/shared";
import { useActionPlan } from "../lib/queries.ts";
import { formatRelative } from "../lib/format.ts";
import { Badge, Button, Card, CardHeader, EmptyState, ErrorBanner, LoadingBlock, type BadgeTone } from "./ui.tsx";

const STATUS_TONE: Record<ProjectStatus, BadgeTone> = {
  "fix-now": "danger",
  "fix-soon": "warn",
  "no-recent-build": "neutral",
  "nothing-to-do": "ok",
};

export function ProjectStatusBadge({ status }: { status: ProjectStatus }) {
  return <Badge tone={STATUS_TONE[status]}>{PROJECT_STATUS_LABELS[status]}</Badge>;
}

const URGENCY_LABEL: Record<Urgency, string> = {
  now: "Fix now",
  soon: "Fix soon",
  later: "When convenient",
  none: "Waiting for a fix",
};
const URGENCY_TONE: Record<Urgency, BadgeTone> = { now: "danger", soon: "warn", later: "info", none: "neutral" };

const SIZE_LABEL: Record<NonNullable<ModuleActionPlanItem["size"]>, string> = {
  patch: "Small step: a patch release",
  minor: "Small step: a minor release",
  major: "Bigger step: a major release, may need code changes",
  rebuild: "Rebuild the image, no code change",
  unknown: "Version change of unknown size",
};

/** The whole plan as plain text, for a ticket or a chat message. */
export function planAsText(plan: ActionPlanResponse): string {
  const lines = [`Action plan for ${plan.name}: ${PROJECT_STATUS_LABELS[plan.status]}`, plan.reason, ""];
  plan.items.forEach((item, i) => {
    lines.push(`${i + 1}. [${URGENCY_LABEL[item.urgency]}] ${item.title}`);
    lines.push(`   ${item.reason}`);
    if (item.size) lines.push(`   ${SIZE_LABEL[item.size]}`);
    if (item.where) lines.push(`   Where: ${item.where}`);
    if (item.copyLine) lines.push(`   ${item.copyLine}`);
    lines.push("");
  });
  return lines.join("\n").trimEnd() + "\n";
}

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      size="sm"
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
    >
      {copied ? "Copied" : label}
    </Button>
  );
}

/**
 * A project's action plan: one line per thing to do, most urgent first. The full vulnerability
 * list stays one click away.
 */
export function ActionPlanPanel({ applicationId, onShowAll }: { applicationId: string; onShowAll: () => void }) {
  const { data, isLoading, error, refetch } = useActionPlan(applicationId);
  if (isLoading) return <LoadingBlock label="Loading the action plan" />;
  if (error) return <ErrorBanner error={error} onRetry={() => void refetch()} />;
  if (!data) return null;

  const todo = data.items.filter((i) => i.kind !== "no-fix");
  return (
    <Card>
      <CardHeader
        title={
          <span className="flex flex-wrap items-center gap-2">
            Action plan <ProjectStatusBadge status={data.status} />
          </span>
        }
        subtitle={
          <>
            {data.reason}
            {data.lastBuildAt ? ` Last build ${formatRelative(data.lastBuildAt)}.` : ""}
          </>
        }
        actions={
          <>
            {data.items.length > 0 ? <CopyButton text={planAsText(data)} label="Copy plan as text" /> : null}
            <Button size="sm" variant="ghost" onClick={onShowAll}>
              See all {data.counts.total} vulnerabilities →
            </Button>
          </>
        }
      />
      {data.items.length === 0 ? (
        <EmptyState title="Nothing to do" hint={data.reason} />
      ) : (
        <ol className="divide-y divide-border-base">
          {data.items.map((item, index) => (
            <li key={`${item.moduleId}:${item.key}`} className={`px-4 py-3 ${item.kind === "no-fix" ? "bg-bg-subtle" : ""}`}>
              <div className="flex flex-wrap items-center gap-2">
                <span className="nums w-5 text-sm text-text-faint">{item.kind === "no-fix" ? "" : `${index + 1}.`}</span>
                <Badge tone={URGENCY_TONE[item.urgency]}>{URGENCY_LABEL[item.urgency]}</Badge>
                <span className="text-sm font-medium text-text-base">{item.title}</span>
                {item.size && item.size !== "unknown" ? (
                  <span className="text-xs text-text-muted">· {SIZE_LABEL[item.size]}</span>
                ) : null}
              </div>
              <div className="mt-1 pl-7 text-sm text-text-muted">{item.reason}</div>
              {item.where ? <div className="mt-1 pl-7 text-xs text-text-muted">Where: {item.where}</div> : null}
              {item.copyLine ? (
                <div className="mt-2 flex items-center gap-2 pl-7">
                  <code className="min-w-0 flex-1 overflow-x-auto rounded bg-bg-subtle px-2 py-1 font-mono text-xs text-text-base">
                    {item.copyLine}
                  </code>
                  <CopyButton text={item.copyLine} />
                </div>
              ) : null}
            </li>
          ))}
        </ol>
      )}
      {todo.length > 0 ? (
        <p className="border-t border-border-base px-4 py-2 text-xs text-text-faint">
          {todo.length} {todo.length === 1 ? "step clears" : "steps clear"}{" "}
          {todo.reduce((n, i) => n + i.clears, 0)} of the {data.counts.total} vulnerabilities in the current build.
          Accepted risks are left out.
        </p>
      ) : null}
    </Card>
  );
}
