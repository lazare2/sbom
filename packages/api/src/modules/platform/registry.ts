import type { ModuleState } from "@sbom/shared";
import type { AppContext } from "../../context.js";
import type { Actor } from "../admin/audit.service.js";
import type { ReadAccess } from "../environments/environment.service.js";
import { BadRequestError, NotFoundError } from "../../lib/errors.js";
import type { ModuleActionPlanItem, PlatformModule } from "./module.js";

/**
 * The modules this server runs, and the questions asked about them: is it on, switch it, what
 * does it add to an action plan.
 *
 * Built once per process from the list in `index.ts` (or the list a test passes in). Holds no
 * state of its own beyond each module's services; whether a module is on is always read from
 * its setting, so two processes or a restore can never leave this out of date.
 */
export class ModuleRegistry {
  private readonly byId = new Map<string, PlatformModule>();
  private readonly built = new Map<string, unknown>();

  constructor(readonly list: readonly PlatformModule[]) {
    for (const module of list) {
      if (this.byId.has(module.id)) throw new Error(`module "${module.id}" is listed twice`);
      this.byId.set(module.id, module);
    }
  }

  /** Builds each module's own services. Called once, after the core graph exists. */
  buildServices(ctx: AppContext): void {
    for (const module of this.list) {
      if (module.services) this.built.set(module.id, module.services(ctx));
    }
  }

  /** A module's own services, as its `services` factory built them. */
  services<T>(id: string): T {
    if (!this.built.has(id)) throw new Error(`module "${id}" has no services`);
    return this.built.get(id) as T;
  }

  get(id: string): PlatformModule {
    const module = this.byId.get(id);
    if (!module) throw new NotFoundError(`No module "${id}".`);
    return module;
  }

  /** On or off. A module without a switch is always on. */
  async isEnabled(ctx: AppContext, id: string): Promise<boolean> {
    const module = this.get(id);
    return module.toggle ? module.toggle.enabled(ctx) : true;
  }

  /** Every module and whether it is on, in the order of the list. */
  async states(ctx: AppContext): Promise<ModuleState[]> {
    return Promise.all(
      this.list.map(async (module) => ({
        id: module.id,
        name: module.name,
        description: module.description,
        switchable: module.toggle !== undefined,
        enabled: module.toggle ? await module.toggle.enabled(ctx) : true,
        settingsPath: module.toggle?.settingsPath ?? null,
      })),
    );
  }

  /**
   * Switches a module on or off. The module's own toggle writes the audit entry, so the switch
   * here and the one on the module's settings page leave the same trail.
   */
  async setEnabled(ctx: AppContext, id: string, enabled: boolean, actor: Actor): Promise<ModuleState> {
    const module = this.get(id);
    if (!module.toggle) throw new BadRequestError(`The module "${module.name}" cannot be switched off.`);
    await module.toggle.setEnabled(ctx, enabled, actor);
    const state = (await this.states(ctx)).find((s) => s.id === id);
    if (!state) throw new NotFoundError(`No module "${id}".`);
    return state;
  }

  /**
   * A project's action plan: what every switched-on module says should be done.
   *
   * The project is fetched against the caller's access first, so an application outside it is a
   * 404 before any module is asked - a module cannot leak a project by forgetting to check.
   */
  async actionPlan(ctx: AppContext, applicationId: string, access: ReadAccess): Promise<ModuleActionPlanItem[]> {
    await ctx.applications.getById(applicationId, access);

    const items: ModuleActionPlanItem[] = [];
    for (const module of this.list) {
      if (!module.actionPlan) continue;
      if (module.toggle && !(await module.toggle.enabled(ctx))) continue;
      const actions = await module.actionPlan.actions(ctx, { applicationId, access });
      for (const action of actions) items.push({ ...action, moduleId: module.id });
    }
    // Most urgent first; within the same urgency, the order modules are listed in.
    return items
      .map((item, index) => ({ item, index }))
      .sort((a, b) => a.item.priority - b.item.priority || a.index - b.index)
      .map(({ item }) => item);
  }
}
