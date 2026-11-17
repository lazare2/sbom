import { maliciousModule } from "../malicious/module.js";
import { vulnerabilitiesModule } from "../vulnerabilities/module.js";
import type { PlatformModule } from "./module.js";

/**
 * Every module this server runs, in the order they appear on Administration -> Modules.
 *
 * Adding a module is adding it here; nothing else in the server names it. The web interface
 * keeps its own list (packages/web/src/modules/index.ts) with the same ids.
 */
export const PLATFORM_MODULES: readonly PlatformModule[] = [vulnerabilitiesModule, maliciousModule];
