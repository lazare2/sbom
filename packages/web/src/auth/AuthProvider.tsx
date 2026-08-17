import { createContext, useCallback, useContext, useMemo, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { SessionUser } from "@sbom/shared";
import { api, UnauthenticatedError } from "../lib/api.ts";
import { queryKeys, type MeResponse } from "../lib/queries.ts";

interface AuthContextValue {
  user: SessionUser | null;
  isLoading: boolean;
  isAdmin: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  loginError: unknown;
  isLoggingIn: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/**
 * Session state, derived from `GET /auth/me` rather than kept in the client.
 *
 * There is no token in localStorage and no decoded JWT: the httpOnly session
 * cookie is the only credential, and the server is the only authority on whether
 * it is still valid. That means an admin deactivating a user takes effect on this
 * client's next request, which is the property the session design was chosen for.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();

  const meQuery = useQuery({
    queryKey: queryKeys.me,
    queryFn: () => api.get<MeResponse>("/auth/me"),
    retry: false,
    // A 401 here is the normal "not signed in" answer, not an error worth
    // retrying or surfacing.
    throwOnError: false,
    staleTime: 60 * 1000,
    refetchOnWindowFocus: true,
  });

  const loginMutation = useMutation({
    mutationFn: (vars: { email: string; password: string }) =>
      api.post<MeResponse>("/auth/login", vars),
    onSuccess: (data) => {
      queryClient.setQueryData(queryKeys.me, data);
    },
  });

  const logoutMutation = useMutation({
    mutationFn: () => api.post<void>("/auth/logout"),
    onSettled: () => {
      // Clear everything, not just the session: cached application and component
      // data belongs to the session that fetched it and must not be visible to
      // whoever signs in next on this browser.
      queryClient.clear();
    },
  });

  const login = useCallback(
    async (email: string, password: string) => {
      await loginMutation.mutateAsync({ email, password });
    },
    [loginMutation],
  );

  const logout = useCallback(async () => {
    await logoutMutation.mutateAsync();
  }, [logoutMutation]);

  const isUnauthenticated = meQuery.error instanceof UnauthenticatedError;
  const user = isUnauthenticated ? null : (meQuery.data?.user ?? null);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      isLoading: meQuery.isLoading,
      isAdmin: user?.role === "admin",
      login,
      logout,
      loginError: loginMutation.error,
      isLoggingIn: loginMutation.isPending,
    }),
    [user, meQuery.isLoading, login, logout, loginMutation.error, loginMutation.isPending],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
