import { NavLink, Outlet, useNavigate } from "react-router";
import { useAuth } from "../auth/AuthProvider.tsx";
import { EnvironmentSwitcher } from "../environments/EnvironmentSwitcher.tsx";
import { WEB_MODULES } from "../modules/index.tsx";
import { useEnabledModuleIds } from "../modules/ModuleGate.tsx";
import { Badge, Button } from "./ui.tsx";
import type { NavSection } from "../modules/types.ts";

type NavItem = { to: string; label: string; end: boolean; section: NavSection };

/** The core pages. Modules add their own entries (modules/index.tsx). */
const CORE_NAV: NavItem[] = [
  { to: "/", label: "Overview", end: true, section: "estate" },
  { to: "/applications", label: "Applications", end: false, section: "estate" },
  { to: "/search", label: "Package search", end: false, section: "estate" },
];

const SECTION_TITLES: Record<NavSection, string> = {
  you: "Your work",
  estate: "Estate",
  reports: "Reports",
};

/**
 * Each module's menu entries, shown only while the module is on and to the people they are for
 * (My teams to team leads and administrators).
 *
 * A permanently visible entry leading to a page that explains it has nothing to show is clutter
 * on every installation that does not use the module. The pages themselves stay routable
 * either way, so a pasted link still works and explains itself.
 */
function moduleNav(enabled: Set<string>, user: { role: string; isTeamLead?: boolean | undefined } | null): NavItem[] {
  return WEB_MODULES.filter((m) => enabled.has(m.id)).flatMap((m) =>
    (m.nav ?? [])
      .filter((item) => !item.visibleTo || (user !== null && item.visibleTo(user)))
      .map((item) => ({ to: item.to, label: item.label, end: item.end ?? false, section: item.section })),
  );
}

export function Layout() {
  const { user, logout, isAdmin } = useAuth();
  const navigate = useNavigate();
  // Cached for a minute by the query, so this does not add a request per navigation.
  const enabledModules = useEnabledModuleIds();
  const items = [...CORE_NAV, ...moduleNav(enabledModules, user)];
  // Your work first, then the estate, then reports: the order a person's day goes in.
  const sections = (["you", "estate", "reports"] as const)
    .map((section) => ({ section, items: items.filter((i) => i.section === section) }))
    .filter((g) => g.items.length > 0);

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

          {/* Narrow screens: the same entries in one scrolling row, since there is no room for the side menu. */}
          <nav aria-label="Main (compact)" className="flex w-full items-center gap-1 overflow-x-auto md:hidden">
            {sections.flatMap((g) => g.items).map((item) => (
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
            {/* One box for a project, a package or a CVE. */}
            <form
              role="search"
              onSubmit={(e) => {
                e.preventDefault();
                const q = String(new FormData(e.currentTarget).get("q") ?? "").trim();
                if (q) navigate(`/find?q=${encodeURIComponent(q)}`);
              }}
            >
              <input
                name="q"
                type="search"
                placeholder="Project, package or CVE…"
                aria-label="Search projects, packages and vulnerabilities"
                className="h-[30px] w-56 rounded-md border border-border-strong bg-bg-raised px-2 text-sm text-text-base"
              />
            </form>
            {/*
              Beside the account rather than in the navigation, because it is not a place to
              go -- it changes what every other item in the navigation means.
            */}
            <EnvironmentSwitcher />
            {/*
              Beside the account too, and for the same reason: the API is not a page of the
              estate, it is a property of the account looking at it. Deliberately visible to
              every signed-in user rather than gated to administrators -- developers reading
              the inventory from a script is the case this exists for, and a credential they
              have to queue for is one four of them will end up sharing.
            */}
            {user ? (
              <NavLink
                to="/api-access"
                className={({ isActive }) =>
                  `rounded-md px-2.5 py-1.5 text-xs transition-colors ${
                    isActive
                      ? "bg-accent-subtle font-medium text-accent"
                      : "text-text-muted hover:bg-bg-subtle hover:text-text-base"
                  }`
                }
                title="The API address, and your personal tokens"
              >
                API
              </NavLink>
            ) : null}
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

      <div className="mx-auto flex max-w-[1600px] gap-6 px-5">
        {/*
          The side menu, by role: your own work first (My teams for team leads, My projects), then
          the estate, then reports, then Administration for administrators.
        */}
        <nav aria-label="Main" className="sticky top-[57px] hidden w-48 shrink-0 self-start py-6 md:block">
          {sections.map((g) => (
            <div key={g.section} className="mb-5">
              <div className="mb-1 px-2.5 text-[11px] font-semibold tracking-wide text-text-faint uppercase">
                {SECTION_TITLES[g.section]}
              </div>
              <div className="flex flex-col gap-0.5">
                {g.items.map((item) => (
                  // `end` on the overview link only: without it, "/" matches every route.
                  <NavLink key={item.to} to={item.to} end={item.end} className={linkClass}>
                    {item.label}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
          {isAdmin ? (
            <div className="mb-5">
              <div className="mb-1 px-2.5 text-[11px] font-semibold tracking-wide text-text-faint uppercase">
                Administration
              </div>
              <div className="flex flex-col gap-0.5">
                <NavLink to="/admin" className={linkClass}>
                  Admin
                </NavLink>
              </div>
            </div>
          ) : null}
        </nav>

        <main className="min-w-0 flex-1 py-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
