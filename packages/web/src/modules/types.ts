import type { ReactElement } from "react";

/**
 * One module, as the web interface sees it: its menu entries, its pages and its admin pages.
 *
 * The id is the server's (packages/api/src/modules/platform/index.ts); whether the module is on
 * comes from `GET /modules`. The list in `index.tsx` is the only place a module is named -
 * Layout.tsx, main.tsx and the admin layouts read it.
 */
export interface WebModule {
  readonly id: string;
  /** Entries in the main menu. Shown only while the module is on. */
  readonly nav?: readonly ModuleNavItem[];
  /**
   * Pages. Mounted whether or not the module is on, so a pasted link explains itself rather
   * than 404ing. While the module is off the frame shows a "not enabled" page instead, unless
   * `pagesExplainDisabled` says the pages do that themselves.
   */
  readonly routes?: readonly ModuleRoute[];
  readonly pagesExplainDisabled?: boolean;
  /** Settings pages under Administration. Always reachable, so the module can be set up. */
  readonly adminPages?: readonly ModuleAdminPage[];
  /** Old admin addresses that now live elsewhere, kept working for bookmarks. */
  readonly adminRedirects?: readonly { from: string; to: string }[];
}

export interface ModuleNavItem {
  readonly to: string;
  readonly label: string;
  /** Exact match for the active state. */
  readonly end?: boolean;
  /** Which part of the side menu it belongs to. */
  readonly section: NavSection;
  /** Shown only to these people; everybody when absent. */
  readonly visibleTo?: (user: { role: string; isTeamLead?: boolean | undefined }) => boolean;
}

export interface ModuleRoute {
  readonly path: string;
  readonly element: ReactElement;
}

export interface ModuleAdminPage {
  /** Path below /admin, or below /admin/scanners for a scanner. */
  readonly path: string;
  readonly label: string;
  readonly element: ReactElement;
  /** Grouped under Administration -> Scanners; otherwise its own admin tab. */
  readonly section?: "scanners";
}

/** The side menu's parts, top to bottom: the person's own work, the estate, reports. */
export type NavSection = "you" | "estate" | "reports";
