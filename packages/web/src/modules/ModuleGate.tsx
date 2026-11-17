import type { ReactNode } from "react";
import { Link } from "react-router";
import { useAuth } from "../auth/AuthProvider.tsx";
import { Card, EmptyState, LoadingBlock } from "../components/ui.tsx";
import { useModules } from "../lib/queries.ts";

/**
 * Shows a module's page only while the module is on; otherwise says so in plain words.
 *
 * Used for modules whose pages do not explain the switched-off state themselves. The data is
 * still there: switching the module back on shows it again.
 */
export function ModuleGate({ id, children }: { id: string; children: ReactNode }) {
  const { isAdmin } = useAuth();
  const modules = useModules();
  if (modules.isLoading) return <LoadingBlock />;
  const state = modules.data?.modules.find((m) => m.id === id);
  // Unknown to the server, or the list could not be read: show the page and let it answer.
  if (!state || state.enabled) return <>{children}</>;
  return (
    <Card>
      <EmptyState
        title={`${state.name} is not enabled`}
        hint={
          isAdmin ? (
            <>
              Switch it on under <Link to="/admin/modules" className="text-accent hover:underline">Administration → Modules</Link>.
              Its data was kept.
            </>
          ) : (
            "An administrator can switch it on. Its data was kept."
          )
        }
      />
    </Card>
  );
}

/** The ids of every switched-on module. Empty while the list is loading. */
export function useEnabledModuleIds(): Set<string> {
  const modules = useModules();
  return new Set((modules.data?.modules ?? []).filter((m) => m.enabled).map((m) => m.id));
}
