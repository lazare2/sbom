import { NavLink, Navigate, Outlet, useLocation } from "react-router";
import { useAccessRequests } from "../../lib/queries.ts";

/**
 * Admin tabs that hold several pages: Access (who can see what) and Scanners (what checks the
 * packages). Each renders its own row of sub-tabs above the page, so the main admin bar stays
 * short and related screens sit together.
 */

interface SubTab {
  to: string;
  label: string;
  badge?: number;
}

function SubTabs({ label, tabs }: { label: string; tabs: SubTab[] }) {
  return (
    <>
      <nav aria-label={label} className="mb-4 flex flex-wrap gap-1 rounded-md bg-bg-subtle p-1">
        {tabs.map((tab) => (
          <NavLink
            key={tab.to}
            to={tab.to}
            className={({ isActive }) =>
              `inline-flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-medium transition-colors ${
                isActive ? "bg-bg-raised text-text-base shadow-sm" : "text-text-muted hover:text-text-base"
              }`
            }
          >
            {tab.label}
            {tab.badge ? (
              <span className="nums rounded-full bg-accent-subtle px-1.5 py-0.5 text-[10px] font-semibold text-accent">
                {tab.badge}
              </span>
            ) : null}
          </NavLink>
        ))}
      </nav>
      <Outlet />
    </>
  );
}

/** Users, tribes, squads and groups: everything that decides who sees which project. */
export function AdminAccessLayout() {
  const accessRequests = useAccessRequests("pending");
  return (
    <SubTabs
      label="Access sections"
      tabs={[
        { to: "/admin/access/users", label: "Users", badge: accessRequests.data?.pendingCount ?? 0 },
        { to: "/admin/access/tribes", label: "Tribes" },
        { to: "/admin/access/squads", label: "Squads" },
        { to: "/admin/access/groups", label: "Groups" },
      ]}
    />
  );
}

/** Vulnerability scanning and malicious-package detection. */
export function AdminScannersLayout() {
  return (
    <SubTabs
      label="Scanner sections"
      tabs={[
        { to: "/admin/scanners/vulnerabilities", label: "Vulnerabilities" },
        { to: "/admin/scanners/malicious", label: "Malicious packages" },
      ]}
    />
  );
}

/**
 * Sends a page's old address to its new one, keeping the query string, so a bookmark or a link
 * in an email from before the reorganisation still lands on the same screen with its filters.
 */
export function MovedTo({ to }: { to: string }) {
  const { search, hash } = useLocation();
  return <Navigate to={`${to}${search}${hash}`} replace />;
}
