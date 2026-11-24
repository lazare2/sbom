import {
  directoryConnectionInputSchema,
  directorySyncRequestSchema,
  directorySyncSettingsSchema,
  linkSquadToDirectorySchema,
} from "@sbom/shared";
import type { PlatformModule } from "../platform/module.js";
import { directoryAdminRoutes } from "./directory-admin.routes.js";

/**
 * Directory: squad membership read from the organisation's directory (Active Directory first).
 *
 * Off on a fresh install, unlike most modules: it reaches another system with a service account,
 * which nobody should get without deciding to. Switching it on needs a saved connection. Off,
 * nothing reads the directory; squads and every grant stay exactly as they are.
 */
export const directoryModule: PlatformModule = {
  id: "directory",
  name: "Directory",
  description:
    "Reads squad membership from your organisation's directory (Active Directory), so access follows people's teams.",

  toggle: {
    enabled: (ctx) => ctx.directory.enabled(),
    setEnabled: (ctx, enabled, actor) => ctx.directory.setEnabled(enabled, actor),
    settingsPath: "/admin/directory",
  },

  routes: [{ prefix: "/admin/directory", access: "admin", plugin: directoryAdminRoutes }],

  jobs: [
    {
      name: "directory nightly sync",
      // Checks once a minute whether tonight's run is due; does nothing while the module is off.
      start: (ctx) => ctx.directorySync.start(),
      stop: (ctx) => ctx.directorySync.stop(),
    },
  ],

  routeDocs: {
    "GET /api/v1/admin/directory": {
      summary: "The directory connection and whether the module is on. Never the password, only whether one is stored.",
      tag: "Directory",
      auth: "admin",
      notes: "Includes the result of the last connection test, which any change to the connection clears.",
    },
    "PUT /api/v1/admin/directory": {
      summary: "Saves the directory connection (Active Directory over LDAPS).",
      tag: "Directory",
      auth: "admin",
      body: directoryConnectionInputSchema,
      notes:
        "An omitted bindPassword keeps the stored one. The password is sealed with SECRETS_KEY and never " +
        "returned. Saving does not switch the module on. Audited as directory.connection_update.",
    },
    "POST /api/v1/admin/directory/test": {
      summary: "Connects, signs in with the service account, checks the base DN and runs one sample group search.",
      tag: "Directory",
      auth: "admin",
      notes:
        "Always 200: the result's code says which step failed (unreachable, tls_untrusted, bind_rejected, " +
        "base_dn_not_found ...) with a hint. The result is kept for the admin screen.",
    },
    "GET /api/v1/admin/directory/groups": {
      summary: "Searches the directory's groups by name (q, at least two characters), for linking squads.",
      tag: "Directory",
      auth: "admin",
      notes: "Each group has its permanent id (AD objectGUID). 502 with code directory_<step> when the directory cannot answer.",
    },
    "GET /api/v1/admin/directory/squad-links": {
      summary: "Every squad that takes its members from a directory group, with the group as last seen.",
      tag: "Directory",
      auth: "admin",
    },
    "PUT /api/v1/admin/directory/squad-links/:id": {
      summary: "Links a squad to a directory group (or moves its link): its members then come from the group.",
      tag: "Directory",
      auth: "admin",
      body: linkSquadToDirectorySchema,
      notes:
        "The group is checked in the directory now. One group feeds one squad (409 otherwise). Needs the " +
        "module on (409 module_disabled). Linked, the squad's members cannot be changed by hand; the " +
        "team-lead mark can. Audited as squad.directory_link.",
    },
    "DELETE /api/v1/admin/directory/squad-links/:id": {
      summary: "Unlinks a squad. Its members stay as they are, hand-managed again.",
      tag: "Directory",
      auth: "admin",
      notes: "Allowed while the module is off. Audited as squad.directory_unlink.",
    },
    "GET /api/v1/admin/directory/sync": {
      summary: "The sync's settings (nightly hour, removal limits), the server's time zone, and the last run with its plan.",
      tag: "Directory",
      auth: "admin",
    },
    "PUT /api/v1/admin/directory/sync/settings": {
      summary: "Sets the nightly hour and the limits above which a sync waits for approval.",
      tag: "Directory",
      auth: "admin",
      body: directorySyncSettingsSchema,
      notes: "Audited as directory.sync_settings.",
    },
    "POST /api/v1/admin/directory/sync/preview": {
      summary: "What a sync would do now - per squad who joins and who leaves, accounts deactivated, people not matched. Changes nothing.",
      tag: "Directory",
      auth: "admin",
      notes: "502 with code directory_<step> when the directory cannot be read.",
    },
    "POST /api/v1/admin/directory/sync": {
      summary: "Sync now: linked squads' members made equal to their directory groups.",
      tag: "Directory",
      auth: "admin",
      body: directorySyncRequestSchema,
      notes:
        "Returns the run: applied, nothing_to_do, held (the first sync, or one removing more than the limits " +
        "allow, waits; send approve: true after checking the plan) or failed (nothing changed). People are " +
        "matched by their directory id, else by email; a disabled person leaves linked squads and, if their " +
        "account came from single sign-on, is deactivated. 409 module_disabled or sync_running. Audited.",
    },
  },
};
