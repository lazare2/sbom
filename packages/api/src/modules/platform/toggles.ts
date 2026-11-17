import type { ModuleToggle } from "./module.js";

/**
 * The switch for a module that has no setting of its own: stored as `module.<id>`, on unless
 * somebody switched it off, and recorded in the audit log like every other admin change.
 */
export function settingToggle(id: string, settingsPath?: string): ModuleToggle {
  return {
    enabled: (ctx) => ctx.settings.moduleEnabled(id),
    async setEnabled(ctx, enabled, actor) {
      const before = await ctx.settings.moduleEnabled(id);
      await ctx.settings.setModuleEnabled(id, enabled, actor);
      if (before !== enabled) {
        await ctx.audit.record({
          actor,
          action: "module.switch",
          targetType: "module",
          targetId: id,
          metadata: { enabled: { from: before, to: enabled } },
        });
      }
    },
    ...(settingsPath ? { settingsPath } : {}),
  };
}
