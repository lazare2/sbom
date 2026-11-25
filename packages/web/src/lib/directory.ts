import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type {
  DirectoryConnectionInput,
  DirectoryDiagnosis,
  DirectoryGroup,
  DirectorySettings,
  DirectorySyncPlan,
  DirectorySyncRun,
  DirectorySyncSettings,
  DirectorySyncState,
} from "@sbom/shared";
import { api } from "./api.ts";

/** The directory (Active Directory) connection, for Administration > Directory. Admin only. */

const SETTINGS_KEY = ["admin", "directory"] as const;

/** The connection and switch, never the password. */
export function useDirectorySettings() {
  return useQuery({
    queryKey: SETTINGS_KEY,
    queryFn: async () => (await api.get<{ settings: DirectorySettings }>("/admin/directory")).settings,
  });
}

export function useSaveDirectoryConnection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: DirectoryConnectionInput) =>
      (await api.put<{ settings: DirectorySettings }>("/admin/directory", body)).settings,
    onSuccess: (settings) => qc.setQueryData(SETTINGS_KEY, settings),
  });
}

/** Resolves with the diagnosis even when the connection fails: the diagnosis is the answer. */
export function useTestDirectoryConnection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => (await api.post<{ diagnosis: DirectoryDiagnosis }>("/admin/directory/test", {})).diagnosis,
    onSuccess: () => void qc.invalidateQueries({ queryKey: SETTINGS_KEY }),
  });
}

/** Groups whose name contains `q` (two characters or more). */
export function useDirectoryGroups(q: string) {
  const term = q.trim();
  return useQuery({
    queryKey: ["admin", "directory", "groups", term],
    queryFn: async () =>
      (await api.get<{ groups: DirectoryGroup[] }>(`/admin/directory/groups?q=${encodeURIComponent(term)}`)).groups,
    enabled: term.length >= 2,
    retry: false,
  });
}

/** Links a squad to a group, or moves its link. The squad lists change too. */
export function useLinkSquad() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ squadId, groupId }: { squadId: string; groupId: string }) =>
      api.put(`/admin/directory/squad-links/${squadId}`, { groupId }),
    onSuccess: () => void qc.invalidateQueries(),
  });
}

/** Unlinks a squad; its members stay. */
export function useUnlinkSquad() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (squadId: string) => api.delete(`/admin/directory/squad-links/${squadId}`),
    onSuccess: () => void qc.invalidateQueries(),
  });
}

const SYNC_KEY = ["admin", "directory", "sync"] as const;

/** The sync's settings and last run. Polled while a run is going on. */
export function useDirectorySync() {
  return useQuery({
    queryKey: SYNC_KEY,
    queryFn: async () => (await api.get<{ sync: DirectorySyncState }>("/admin/directory/sync")).sync,
    refetchInterval: (q) => (q.state.data?.running ? 2000 : false),
  });
}

/** What a sync would do now; changes nothing. */
export function usePreviewSync() {
  return useMutation({
    mutationFn: async () => (await api.post<{ plan: DirectorySyncPlan }>("/admin/directory/sync/preview", {})).plan,
  });
}

/** Sync now; `approve` applies a plan that would otherwise wait. */
export function useRunSync() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (approve: boolean) => (await api.post<{ run: DirectorySyncRun }>("/admin/directory/sync", { approve })).run,
    onSuccess: () => void qc.invalidateQueries(),
  });
}

export function useSaveSyncSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (settings: DirectorySyncSettings) =>
      (await api.put<{ sync: DirectorySyncState }>("/admin/directory/sync/settings", settings)).sync,
    onSuccess: (sync) => qc.setQueryData(SYNC_KEY, sync),
  });
}
