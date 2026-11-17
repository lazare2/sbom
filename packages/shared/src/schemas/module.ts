import { z } from "zod";

/**
 * A part of the platform that can be described, and for some switched off, on its own:
 * Vulnerabilities, Malicious packages, and more as the platform is split up.
 */
export interface ModuleState {
  /** Stable identifier, the same on the server and in the web interface. */
  id: string;
  name: string;
  description: string;
  /** False for parts of the platform that are always on. */
  switchable: boolean;
  enabled: boolean;
  /** The admin page holding the module's own settings, when it has one. */
  settingsPath: string | null;
}

export interface ModuleListResponse {
  modules: ModuleState[];
}

export const moduleIdParamSchema = z.object({
  id: z.string().trim().regex(/^[a-z][a-z0-9-]{0,63}$/, "not a module id"),
});

export const setModuleEnabledSchema = z.object({
  enabled: z.boolean(),
});
export type SetModuleEnabled = z.infer<typeof setModuleEnabledSchema>;
