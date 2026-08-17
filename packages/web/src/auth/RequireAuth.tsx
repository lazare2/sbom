import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router";
import { useAuth } from "./AuthProvider.tsx";
import { LoadingBlock } from "../components/ui.tsx";

/**
 * Gate for authenticated routes.
 *
 * This is a UX guard, not a security boundary — every protected endpoint
 * enforces its own auth server-side. Its job is to avoid rendering a shell full
 * of failed requests, and to send the user back where they were headed after
 * signing in.
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <LoadingBlock label="Checking your session" />
      </div>
    );
  }

  if (!user) {
    // Round-trips the intended destination so a deep link survives the login.
    const from = `${location.pathname}${location.search}`;
    return <Navigate to={`/login?from=${encodeURIComponent(from)}`} replace />;
  }

  /**
   * An admin-issued password has been seen by someone other than its owner, so
   * the session is pinned to the change-password screen until it is replaced.
   *
   * Redirecting here is a courtesy, not the enforcement: the API rejects every
   * route except whoami, change-password and logout with a
   * `password_change_required` 403 while the flag is set, so bypassing this
   * component yields an empty shell rather than data.
   */
  if (user.mustChangePassword && location.pathname !== "/change-password") {
    return <Navigate to="/change-password" replace />;
  }

  return <>{children}</>;
}

/**
 * Gate for admin-only routes.
 *
 * Non-admins are sent to the dashboard rather than shown a "forbidden" page:
 * they did not do anything wrong, they followed a link that does not apply to
 * them, and the admin nav is not rendered for them in the first place.
 */
export function RequireAdmin({ children }: { children: ReactNode }) {
  const { user, isAdmin, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <LoadingBlock label="Checking your session" />
      </div>
    );
  }

  if (!user) return <Navigate to="/login" replace />;
  if (!isAdmin) return <Navigate to="/" replace />;

  return <>{children}</>;
}
