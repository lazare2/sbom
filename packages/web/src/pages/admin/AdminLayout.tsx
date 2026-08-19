import { NavLink, Outlet } from "react-router";
import { useDashboardStats } from "../../lib/queries.ts";
import { PageHeader } from "../../components/ui.tsx";

const TABS = [
  { to: "/admin/applications", label: "Applications" },
  { to: "/admin/pending", label: "Awaiting confirmation", badge: "pending" as const },
  { to: "/admin/groups", label: "Groups" },
  { to: "/admin/users", label: "Users" },
  { to: "/admin/attributes", label: "Attributes" },
  { to: "/admin/tokens", label: "CI tokens" },
  { to: "/admin/vulnerabilities", label: "Vulnerability scanning" },
  { to: "/admin/reports", label: "Monthly report" },
  { to: "/admin/configuration", label: "Configuration" },
  { to: "/admin/audit", label: "Audit log" },
];

export function AdminLayout() {
  // Only used for the pending count on the tab. A triage queue nobody can see
  // the size of is a triage queue nobody opens.
  const stats = useDashboardStats();
  const pending = stats.data?.applications.pendingConfirmation ?? 0;

  return (
    <>
      <PageHeader
        title="Administration"
        subtitle="Manage applications, accounts, attributes, vulnerability scanning, the monthly report, and the CI credentials that submit SBOMs."
      />

      <nav
        aria-label="Admin sections"
        className="mb-5 flex flex-wrap gap-1 border-b border-border-base pb-2"
      >
        {TABS.map((tab) => (
          <NavLink
            key={tab.to}
            to={tab.to}
            className={({ isActive }) =>
              `inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-sm transition-colors ${
                isActive
                  ? "bg-accent-subtle font-medium text-accent"
                  : "text-text-muted hover:bg-bg-subtle hover:text-text-base"
              }`
            }
          >
            {tab.label}
            {tab.badge === "pending" && pending > 0 ? (
              <span className="nums rounded-full bg-warn-subtle px-1.5 py-0.5 text-[10px] font-semibold text-warn">
                {pending}
              </span>
            ) : null}
          </NavLink>
        ))}
      </nav>

      <Outlet />
    </>
  );
}
