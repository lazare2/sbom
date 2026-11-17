import { groupRoutes } from "../groups/groups.routes.js";
import type { PlatformModule } from "../platform/module.js";
import { settingToggle } from "../platform/toggles.js";

/**
 * Organisation: the Groups pages - named sets of applications to read together.
 *
 * Off: the Groups menu entry and pages say "not enabled". Deliberately NOT affected: squads,
 * tribes and every grant, including grants made through a group. Those decide who may see what,
 * and switching a page off must never quietly change access. Group definitions stay.
 */
export const organisationModule: PlatformModule = {
  id: "organisation",
  name: "Organisation",
  description: "The Groups pages: named sets of applications, with their combined vulnerabilities. Access granted through groups is not affected by this switch.",

  toggle: settingToggle("organisation", "/admin/access/groups"),

  routes: [{ prefix: "/groups", access: "user", plugin: groupRoutes, gated: true }],
};
