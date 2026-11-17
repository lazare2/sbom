import type { FastifyInstance } from "fastify";
import type { AppContext } from "../../context.js";
import type { Actor } from "../admin/audit.service.js";
import type { ReadAccess } from "../environments/environment.service.js";
import type { RouteMeta } from "../openapi/route-catalog.js";
import type { ActionPlanItem, ProjectUrgencyCounts } from "@sbom/shared";

/**
 * One part of the platform, described in one place.
 *
 * A module says what it adds - API addresses, background jobs, entries for a project's action
 * plan, extra services - and, when it is optional, how it is switched on and off. The server
 * reads the list in `index.ts` and wires each part in; nothing central names a module.
 *
 * ## What "off" means
 *
 * Off is a runtime state, not a wiring decision. A switched-off module keeps its addresses
 * (they answer that the feature is not enabled, so a pasted link explains itself), its jobs keep
 * their timer and do nothing, and **its data stays** - switching back on picks up where it was.
 * Nothing here deletes anything.
 */
export interface PlatformModule {
  /** Stable identifier. Used in addresses, the audit log and the web interface's own list. */
  readonly id: string;
  /** What an administrator sees on Administration -> Modules. */
  readonly name: string;
  readonly description: string;

  /** Present only on a module that can be switched off. */
  readonly toggle?: ModuleToggle;

  /**
   * API addresses, each mounted under `/api/v1` + `prefix`.
   *
   * `admin` routes are mounted behind `requireAdmin` by the frame itself, so a route added to
   * such a plugin is protected whether or not its author thought about it. `user` routes apply
   * their own session checks, exactly as the core read routes do.
   */
  readonly routes?: readonly ModuleRoutes[];

  /** API documentation for this module's own addresses, merged into the OpenAPI document. */
  readonly routeDocs?: Readonly<Record<string, RouteMeta>>;

  /** Background work. Started once the server is listening, stopped on shutdown. */
  readonly jobs?: readonly ModuleJob[];

  /** Checks run once at start-up, for problems worth a log line. Never fatal. */
  readonly startupCheck?: (ctx: AppContext) => Promise<void>;

  /**
   * Services a module brings along, built after the core graph and reachable as
   * `ctx.modules.services(id)`. For new modules; the two pipelines that predate the frame
   * (vulnerabilities, malicious packages) still have their services built in context.ts.
   */
  readonly services?: (ctx: AppContext) => unknown;

  /** Lines this module adds to a project's action plan. See registry.ts. */
  readonly actionPlan?: ActionPlanContributor;

  /**
   * How urgent each project is, as the counts a status is computed from (see `projectStatus` in
   * @sbom/shared). The developer view adds up what every switched-on module reports.
   */
  readonly projectUrgency?: ProjectUrgencyContributor;
}

export interface ProjectUrgencyContributor {
  /** Counts per application id. The ids are already access-checked by the caller. */
  counts(ctx: AppContext, applicationIds: readonly string[]): Promise<Map<string, ProjectUrgencyCounts>>;
}

export interface ModuleToggle {
  /** Whether the module is on now. Read from the module's own setting. */
  enabled(ctx: AppContext): Promise<boolean>;
  /**
   * Switches it. Writes its own audit entry and does whatever turning it on has always done
   * (the first database update, the first feed fetch), so the module switch and the module's
   * own settings page can never behave differently.
   */
  setEnabled(ctx: AppContext, enabled: boolean, actor: Actor): Promise<void>;
  /** Where the module's settings live in the web interface. */
  readonly settingsPath?: string;
}

export interface ModuleRoutes {
  readonly prefix: string;
  readonly access: "user" | "admin";
  readonly plugin: (fastify: FastifyInstance) => Promise<void>;
}

export interface ModuleJob {
  readonly name: string;
  /** Closes out work a killed process left marked as running. Returns how many it closed. */
  reconcile?(ctx: AppContext): Promise<number>;
  start(ctx: AppContext): void;
  stop(ctx: AppContext): void;
}

// --- action plan -------------------------------------------------------------------------

/**
 * The fixed place where modules add work to a project's action plan.
 *
 * One line per thing to do, not per vulnerability: "upgrade the base image" is one action even
 * when it clears forty findings. The developer view builds its action plan page on this; a module
 * that is switched off contributes nothing.
 */
export interface ActionPlanContributor {
  actions(ctx: AppContext, request: ActionPlanRequest): Promise<ActionPlanItem[]>;
}

export interface ActionPlanRequest {
  readonly applicationId: string;
  /** The caller's access. The frame has already checked the project is inside it. */
  readonly access: ReadAccess;
}

export type { ActionPlanItem, ModuleActionPlanItem } from "@sbom/shared";
