import { NavLink, Outlet, useNavigate } from "react-router";
import { useAuth } from "../auth/AuthProvider.tsx";
import { useVulnStatus } from "../lib/queries.ts";
import { Badge, Button } from "./ui.tsx";

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/applications", label: "Applications", end: false },
  { to: "/groups", label: "Groups", end: false },
  { to: "/search", label: "Package search", end: false },
  { to: "/analytics", label: "Analytics", end: false },
];

/**
 * Shown only when vulnerability scanning is enabled.
 *
 * A permanently visible nav item leading to a page that explains it has nothing to show
 * is clutter on every deployment that does not use the feature. The pages themselves stay
 * routable either way, so a pasted link still works and explains itself.
 */
const VULN_NAV = { to: "/vulnerabilities", label: "Vulnerabilities", end: false };

export function Layout() {
  const { user, logout, isAdmin } = useAuth();
  const navigate = useNavigate();
  // Cached for a minute by the query, so this does not add a request per navigation.
  const { data: vulnStatus } = useVulnStatus();
  const navItems = vulnStatus?.enabled ? [...NAV, VULN_NAV] : NAV;

  async function handleLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `rounded-md px-2.5 py-1.5 text-sm transition-colors ${
      isActive
        ? "bg-accent-subtle font-medium text-accent"
        : "text-text-muted hover:bg-bg-subtle hover:text-text-base"
    }`;

  return (
    <div className="min-h-screen bg-bg">
      <header className="sticky top-0 z-20 border-b border-border-base bg-bg-raised/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-x-6 gap-y-2 px-5 py-2.5">
          <NavLink to="/" className="flex items-center gap-2 text-sm font-semibold text-text-base">
            <span aria-hidden="true" className="grid size-6 place-items-center rounded bg-accent text-[13px] text-white">
              S
            </span>
            SBOM Platform
          </NavLink>

          <nav aria-label="Main" className="flex items-center gap-1">
            {navItems.map((item) => (
              // `end` on the overview link only: without it, "/" matches every
              // route and the whole nav renders as active.
              <NavLink key={item.to} to={item.to} end={item.end} className={linkClass}>
                {item.label}
              </NavLink>
            ))}
            {isAdmin ? (
              <NavLink to="/admin" className={linkClass}>
                Admin
              </NavLink>
            ) : null}
          </nav>

          <div className="ml-auto flex items-center gap-3">
            {user ? (
              <>
                <span className="hidden items-center gap-2 sm:flex">
                  <NavLink
                    to="/change-password"
                    className="text-xs text-text-muted hover:text-text-base hover:underline"
                    title="Change your password"
                  >
                    {user.email}
                  </NavLink>
                  {isAdmin ? <Badge tone="accent">Admin</Badge> : null}
                </span>
                <Button size="sm" variant="ghost" onClick={handleLogout}>
                  Sign out
                </Button>
              </>
            ) : null}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1600px] px-5 py-6">
        <Outlet />
      </main>
    </div>
  );
}
