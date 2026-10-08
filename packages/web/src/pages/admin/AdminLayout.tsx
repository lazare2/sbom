import { NavLink, Outlet } from "react-router";
import { useAccessRequests, useDashboardStats } from "../../lib/queries.ts";
import { PageHeader } from "../../components/ui.tsx";

const TABS = [
  { to: "/admin/applications", label: "Applications" },
  { to: "/admin/pending", label: "Awaiting confirmation", badge: "pending" as const },
  { to: "/admin/groups", label: "Groups" },
  { to: "/admin/users", label: "Users", badge: "accessRequests" as const },
  { to: "/admin/authentication", label: "Authentication" },
  { to: "/admin/environments", label: "Environments" },
  { to: "/admin/attributes", label: "Attributes" },
  { to: "/admin/tokens", label: "CI tokens" },
  { to: "/admin/vulnerabilities", label: "Vulnerability scanning" },
  { to: "/admin/malicious", label: "Malicious packages" },
  { to: "/admin/reports", label: "Monthly report" },
  { to: "/admin/configuration", label: "Configuration" },
  { to: "/admin/audit", label: "Audit log" },
  { to: "/admin/errors", label: "Error log" },
];

export function AdminLayout() {
  // Only used for the pending count on the tab. A triage queue nobody can see
  // the size of is a triage queue nobody opens.
  const stats = useDashboardStats();
  const pending = stats.data?.applications.pendingConfirmation ?? 0;

  /*
    People the directory authenticated who have no account yet.

    On the nav for the same reason as the pending-application count: the queue is only useful
    if its size is visible from somewhere other than the page it lives on. Somebody locked out
    of the platform is waiting on an administrator noticing, and nobody opens the Users page
    speculatively.
  */
  const accessRequests = useAccessRequests("pending");
  const waiting = accessRequests.data?.pendingCount ?? 0;

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
            {tab.badge === "accessRequests" && waiting > 0 ? (
              <span
                /* Accent rather than the warning tone used for unconfirmed applications.
                   An unconfirmed application is untidy data; this is a colleague who cannot
                   get in, and the two should not read as the same kind of backlog. */
                className="nums rounded-full bg-accent-subtle px-1.5 py-0.5 text-[10px] font-semibold text-accent"
                title={`${waiting} ${waiting === 1 ? "person is" : "people are"} waiting for an account`}
              >
                {waiting}
              </span>
            ) : null}
          </NavLink>
        ))}
      </nav>

      <Outlet />
    </>
  );
}
