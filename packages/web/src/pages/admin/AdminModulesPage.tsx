import { useState } from "react";
import { Link } from "react-router";
import type { ModuleState } from "@sbom/shared";
import { Badge, Button, Card, CardHeader, ErrorBanner, FormError, LoadingBlock, Modal } from "../../components/ui.tsx";
import { useSetModuleEnabled } from "../../lib/mutations.ts";
import { useModules } from "../../lib/queries.ts";

/**
 * Administration -> Modules: one switch per part of the platform.
 *
 * The same switch as on each module's own settings page, with the same audit entry and the same
 * first update when it goes on. Switching off hides the module's menu entry and pauses its jobs;
 * its data is kept and is back as soon as it is switched on again.
 */
export function AdminModulesPage() {
  const modules = useModules();
  const setEnabled = useSetModuleEnabled();
  const [confirmOff, setConfirmOff] = useState<ModuleState | null>(null);

  if (modules.isLoading) return <LoadingBlock />;
  if (modules.error) return <ErrorBanner error={modules.error} onRetry={() => void modules.refetch()} />;

  function switchModule(module: ModuleState, enabled: boolean) {
    setEnabled.mutate(
      { id: module.id, enabled },
      { onSuccess: () => setConfirmOff(null) },
    );
  }

  return (
    <Card>
      <CardHeader
        title="Modules"
        subtitle="Switch parts of the platform on or off. Switching a module off keeps all its data; switching it on again shows it as it was."
      />
      <ul className="divide-y divide-border-base">
        {(modules.data?.modules ?? []).map((module) => (
          <li key={module.id} className="flex flex-wrap items-center gap-4 px-4 py-3">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-text-base">{module.name}</span>
                {module.enabled ? <Badge tone="ok">On</Badge> : <Badge tone="neutral">Off</Badge>}
              </div>
              <p className="mt-0.5 text-xs text-text-muted">{module.description}</p>
            </div>
            <div className="flex items-center gap-2">
              {module.settingsPath ? (
                <Link to={module.settingsPath} className="text-xs text-accent hover:underline">
                  Settings
                </Link>
              ) : null}
              {module.switchable ? (
                module.enabled ? (
                  <Button size="sm" onClick={() => setConfirmOff(module)} disabled={setEnabled.isPending}>
                    Switch off
                  </Button>
                ) : (
                  <Button
                    size="sm"
                    variant="primary"
                    onClick={() => switchModule(module, true)}
                    disabled={setEnabled.isPending}
                  >
                    Switch on
                  </Button>
                )
              ) : (
                <span className="text-xs text-text-muted">Always on</span>
              )}
            </div>
          </li>
        ))}
      </ul>
      {setEnabled.error && !confirmOff ? (
        <div className="px-4 pb-3">
          <FormError error={setEnabled.error} />
        </div>
      ) : null}

      {confirmOff ? (
        <Modal
          open
          onClose={() => setConfirmOff(null)}
          title={`Switch off ${confirmOff.name}?`}
          footer={
            <>
              <Button variant="ghost" onClick={() => setConfirmOff(null)}>
                Cancel
              </Button>
              <Button variant="primary" onClick={() => switchModule(confirmOff, false)} disabled={setEnabled.isPending}>
                Switch off
              </Button>
            </>
          }
        >
          <p className="text-sm text-text-base">
            Its menu entry disappears and its background work pauses. Its pages say it is not enabled.
          </p>
          <p className="mt-2 text-sm text-text-base">
            <strong>All its data is kept.</strong> Switch it on again here at any time.
          </p>
          {setEnabled.error ? (
            <div className="mt-3">
              <FormError error={setEnabled.error} />
            </div>
          ) : null}
        </Modal>
      ) : null}
    </Card>
  );
}
