import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { Environment } from "@sbom/shared";
import { api, setRequestEnvironment } from "../lib/api.ts";
import { Card, EmptyState, LoadingBlock, ErrorBanner } from "../components/ui.tsx";

/**
 * Which estate the whole application is currently reading.
 *
 * The selection is deliberately *not* in the router. It is not a property of the page
 * you are on -- it applies to every page at once, survives navigation, and is what the
 * user thinks of as "where I am working". Putting it in each page's query string would
 * mean every internal link had to carry it, and the first link that forgot would move
 * the user to another estate without saying so.
 *
 * The cost of that choice is that a pasted URL does not carry the estate. The switcher
 * is visible in the header on every page, and a link that lands on an application in
 * another estate still opens it -- single entities are fetched by the caller's whole
 * readable set, not the current selection -- so the page a link points at is the page
 * that opens.
 */

const STORAGE_KEY = "sbom.environment";

interface EnvironmentContextValue {
  environments: Environment[];
  current: Environment;
  select: (id: string) => void;
}

const EnvironmentContext = createContext<EnvironmentContextValue | null>(null);

export function useEnvironment(): EnvironmentContextValue {
  const value = useContext(EnvironmentContext);
  if (!value) throw new Error("useEnvironment must be used inside EnvironmentProvider");
  return value;
}

function readStored(): string | null {
  try {
    return window.localStorage.getItem(STORAGE_KEY);
  } catch {
    // Private mode, or storage disabled by policy. Falls back to the default estate.
    return null;
  }
}

function writeStored(id: string): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, id);
  } catch {
    // Not being able to remember the choice is survivable; failing the switch is not.
  }
}

/**
 * Loads the estates this account may read and settles on one before anything else renders.
 *
 * Children do not mount until a selection exists, and that is the point rather than a
 * loading nicety: `setRequestEnvironment` has to be in place before the first scoped
 * request leaves the browser. A page that mounted first would fetch with no environment,
 * be answered from the caller's default estate, and render numbers for an estate the
 * switcher is not pointing at.
 */
export function EnvironmentProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [selectedId, setSelectedId] = useState<string | null>(readStored);

  const query = useQuery({
    queryKey: ["environments"],
    queryFn: () => api.get<{ environments: Environment[] }>("/environments"),
    // Estates are created a handful of times in a deployment's life.
    staleTime: 5 * 60 * 1000,
  });

  const environments = query.data?.environments ?? [];

  /*
    A stored id that is no longer granted -- the environment was deleted, or access was
    withdrawn -- falls back to the first estate rather than erroring. The alternative is a
    user who cannot use the platform at all until somebody tells them to clear their
    browser storage.
  */
  const current = environments.find((e) => e.id === selectedId) ?? environments[0] ?? null;

  /*
    Set during render, before children exist. An effect would run after the first child
    render, which is exactly when the first scoped request goes out.
  */
  if (current) setRequestEnvironment(current.id);

  const select = useCallback(
    (id: string) => {
      writeStored(id);
      setSelectedId(id);

      /*
        Every cached answer belonged to the estate that was selected when it was fetched,
        and none of it is true of this one. Dropping it is not an optimisation in reverse:
        without this, switching estates shows the previous one's applications, counts and
        charts until each query happens to refetch, and the header would be naming an
        environment the page is not showing.

        Removed rather than invalidated, so nothing is briefly rendered from stale data
        while the refetch is in flight. The two exempt keys are the session and the
        environment list itself -- neither belongs to an estate, and clearing them would
        make every switch flash the whole application through a loading state.
      */
      queryClient.removeQueries({
        predicate: (query) => {
          const root = query.queryKey[0];
          return root !== "auth" && root !== "environments";
        },
      });
    },
    [queryClient],
  );

  const value = useMemo<EnvironmentContextValue | null>(
    () => (current ? { environments, current, select } : null),
    [environments, current, select],
  );

  if (query.isPending) return <LoadingBlock label="Loading environments" />;
  if (query.error) {
    return (
      <div className="mx-auto max-w-[1600px] px-5 py-6">
        <ErrorBanner error={query.error} onRetry={() => void query.refetch()} />
      </div>
    );
  }

  /*
    A signed-in account with no environments. Legitimate and recoverable, but every data
    route will refuse, so say so plainly here rather than letting eleven pages each render
    their own permission error.
  */
  if (!value) {
    return (
      <div className="mx-auto max-w-[1600px] px-5 py-6">
        <Card>
          <EmptyState
            title="No environments"
            hint="This account has not been granted access to any environment yet. An administrator can grant one from Admin → Users."
          />
        </Card>
      </div>
    );
  }

  return <EnvironmentContext.Provider value={value}>{children}</EnvironmentContext.Provider>;
}
