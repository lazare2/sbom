import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../src/app.js";
import { loadConfig } from "../../src/config.js";
import type { AppContext } from "../../src/context.js";
import { NotFoundError } from "../../src/lib/errors.js";
import { maliciousModule } from "../../src/modules/malicious/module.js";
import { undocumentedRoutes, staleCatalogEntries } from "../../src/modules/openapi/openapi.service.js";
import { PLATFORM_MODULES } from "../../src/modules/platform/index.js";
import { runModuleStartupChecks, startModuleJobs, stopModuleJobs } from "../../src/modules/platform/lifecycle.js";
import type { PlatformModule } from "../../src/modules/platform/module.js";
import { ModuleRegistry } from "../../src/modules/platform/registry.js";
import { vulnerabilitiesModule } from "../../src/modules/vulnerabilities/module.js";
import type { ReadAccess } from "../../src/modules/environments/environment.service.js";

/**
 * The module frame (step 2): a module describes itself in one file, the server wires it in
 * from the list, and switching it off keeps its data.
 */

const actor = { id: "00000000-0000-0000-0000-000000000001", email: "admin@example.test" };
const access = {} as ReadAccess;
const silentLog = { info: vi.fn(), warn: vi.fn() } as unknown as AppContext["logger"];

/** A module that exists only in this file. Adding it touches no central file. */
function testModule(state = { enabled: true }) {
  const started: string[] = [];
  const module: PlatformModule = {
    id: "test-module",
    name: "Test module",
    description: "Exists only in the tests.",
    toggle: {
      enabled: async () => state.enabled,
      setEnabled: async (_ctx, enabled) => {
        state.enabled = enabled;
      },
      settingsPath: "/admin/test-module",
    },
    routes: [
      {
        prefix: "/test-module",
        access: "user",
        plugin: async (fastify) => {
          fastify.addHook("preHandler", fastify.requireAuth);
          fastify.get("/hello", async () => ({ hello: "world" }));
        },
      },
      {
        prefix: "/admin/test-module",
        access: "admin",
        // No guard of its own: the frame must add requireAdmin.
        plugin: async (fastify) => {
          fastify.post("/do", async () => ({ done: true }));
        },
      },
    ],
    routeDocs: {
      "GET /api/v1/test-module/hello": { summary: "Says hello.", tag: "Test", auth: "user" },
      "POST /api/v1/admin/test-module/do": { summary: "Does it.", tag: "Test", auth: "admin" },
    },
    jobs: [
      {
        name: "test job",
        start: () => started.push("start"),
        stop: () => started.push("stop"),
      },
    ],
    services: (ctx) => ({ greet: () => `hello from ${ctx.config.NODE_ENV}` }),
    actionPlan: {
      actions: async () => [
        { key: "b", title: "Second thing", reason: "less urgent", priority: 20 },
        { key: "a", title: "First thing", reason: "urgent", priority: 10 },
      ],
    },
  };
  return { module, state, started };
}

describe("a module plugs in through the list alone", () => {
  const config = loadConfig({
    NODE_ENV: "test",
    LOG_LEVEL: "silent",
    // Port 1: never a real database (see app-wiring.test.ts).
    DATABASE_URL: "postgres://sbom:sbom@127.0.0.1:1/sbom_test",
    SESSION_SECRET: "t".repeat(48),
    PUBLIC_URL: "http://localhost:5173",
  });
  const { module } = testModule();
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp({ config, modules: [...PLATFORM_MODULES, module] });
    await app.ready();
  });
  afterAll(async () => {
    await app.close();
  });

  it("mounts its addresses and keeps them signed-in only", async () => {
    const res = await app.inject({ method: "GET", url: "/api/v1/test-module/hello" });
    expect(res.statusCode).toBe(401);
  });

  it("puts its admin addresses behind requireAdmin without the module asking", async () => {
    const res = await app.inject({ method: "POST", url: "/api/v1/admin/test-module/do" });
    expect(res.statusCode).toBe(401);
  });

  it("documents its addresses from its own file", () => {
    expect(undocumentedRoutes(app.routeTable.list(), app.routeCatalog)).toEqual([]);
    expect(staleCatalogEntries(app.routeTable.list(), app.routeCatalog)).toEqual([]);
    expect(app.routeCatalog["GET /api/v1/test-module/hello"]?.summary).toBe("Says hello.");
  });

  it("builds its services after the core graph", () => {
    const services = app.ctx.modules.services<{ greet(): string }>("test-module");
    expect(services.greet()).toBe("hello from test");
  });

  it("keeps the addresses of the modules that were there before", () => {
    const routes = new Set(app.routeTable.list().map((r) => `${r.method} ${r.url}`));
    for (const key of [
      "GET /api/v1/vulnerabilities",
      "GET /api/v1/vuln-status",
      "PATCH /api/v1/admin/vuln/settings",
      "GET /api/v1/malicious",
      "GET /api/v1/malicious-status",
      "PATCH /api/v1/admin/malicious/settings",
      "DELETE /api/v1/admin/malicious/acknowledgements/:id",
      "GET /api/v1/modules",
      "PATCH /api/v1/admin/modules/:id",
    ]) {
      expect(routes.has(key), key).toBe(true);
    }
  });

  it("refuses the module switch without a session", async () => {
    const list = await app.inject({ method: "GET", url: "/api/v1/modules" });
    expect(list.statusCode).toBe(401);
    const patch = await app.inject({
      method: "PATCH",
      url: "/api/v1/admin/modules/vulnerabilities",
      payload: { enabled: false },
    });
    expect(patch.statusCode).toBe(401);
  });
});

describe("the module registry", () => {
  function fakeCtx(overrides: Partial<AppContext> = {}) {
    return {
      config: { NODE_ENV: "test" },
      applications: { getById: vi.fn(async () => ({})) },
      ...overrides,
    } as unknown as AppContext;
  }

  it("refuses the same id twice", () => {
    const { module } = testModule();
    expect(() => new ModuleRegistry([module, module])).toThrow(/listed twice/);
  });

  it("reports each module's state from its own switch", async () => {
    const t = testModule({ enabled: false });
    const always: PlatformModule = { id: "core", name: "Core", description: "Always on." };
    const registry = new ModuleRegistry([t.module, always]);
    expect(await registry.states(fakeCtx())).toEqual([
      {
        id: "test-module",
        name: "Test module",
        description: "Exists only in the tests.",
        switchable: true,
        enabled: false,
        settingsPath: "/admin/test-module",
      },
      { id: "core", name: "Core", description: "Always on.", switchable: false, enabled: true, settingsPath: null },
    ]);
  });

  it("switches a module through its own toggle and answers its new state", async () => {
    const t = testModule({ enabled: true });
    const registry = new ModuleRegistry([t.module]);
    const state = await registry.setEnabled(fakeCtx(), "test-module", false, actor);
    expect(state.enabled).toBe(false);
    expect(t.state.enabled).toBe(false);
  });

  it("will not switch a module that has no switch, nor one that does not exist", async () => {
    const registry = new ModuleRegistry([{ id: "core", name: "Core", description: "" }]);
    await expect(registry.setEnabled(fakeCtx(), "core", false, actor)).rejects.toThrow(/cannot be switched off/);
    await expect(registry.setEnabled(fakeCtx(), "nope", false, actor)).rejects.toBeInstanceOf(NotFoundError);
  });

  describe("action plan", () => {
    it("checks the project against the caller's access before asking any module", async () => {
      const t = testModule();
      const actions = vi.spyOn(t.module.actionPlan!, "actions");
      const ctx = fakeCtx({
        applications: {
          getById: vi.fn(async () => {
            throw new NotFoundError("Application not found");
          }),
        } as unknown as AppContext["applications"],
      });
      const registry = new ModuleRegistry([t.module]);
      await expect(registry.actionPlan(ctx, "app-1", access)).rejects.toBeInstanceOf(NotFoundError);
      expect(actions).not.toHaveBeenCalled();
    });

    it("collects from switched-on modules, most urgent first, tagged with the module", async () => {
      const t = testModule();
      const registry = new ModuleRegistry([t.module]);
      const items = await registry.actionPlan(fakeCtx(), "app-1", access);
      expect(items.map((i) => [i.key, i.moduleId])).toEqual([
        ["a", "test-module"],
        ["b", "test-module"],
      ]);
    });

    it("asks nothing of a switched-off module", async () => {
      const t = testModule({ enabled: false });
      const actions = vi.spyOn(t.module.actionPlan!, "actions");
      const registry = new ModuleRegistry([t.module]);
      expect(await registry.actionPlan(fakeCtx(), "app-1", access)).toEqual([]);
      expect(actions).not.toHaveBeenCalled();
    });
  });
});

describe("module jobs", () => {
  it("start whether or not the module is on, and stop on shutdown", async () => {
    const t = testModule({ enabled: false });
    const ctx = { modules: new ModuleRegistry([t.module]) } as unknown as AppContext;
    await startModuleJobs(ctx, silentLog);
    stopModuleJobs(ctx);
    expect(t.started).toEqual(["start", "stop"]);
  });

  it("start even when closing out interrupted work fails", async () => {
    const start = vi.fn();
    const failing: PlatformModule = {
      id: "failing",
      name: "Failing",
      description: "",
      jobs: [{ name: "job", reconcile: async () => Promise.reject(new Error("db down")), start, stop: vi.fn() }],
    };
    const ctx = { modules: new ModuleRegistry([failing]) } as unknown as AppContext;
    await startModuleJobs(ctx, silentLog);
    expect(start).toHaveBeenCalledOnce();
  });

  it("never let a failed start-up check stop the server", async () => {
    const broken: PlatformModule = {
      id: "broken",
      name: "Broken",
      description: "",
      startupCheck: async () => Promise.reject(new Error("no scanner")),
    };
    const ctx = { modules: new ModuleRegistry([broken]) } as unknown as AppContext;
    await expect(runModuleStartupChecks(ctx, silentLog)).resolves.toBeUndefined();
  });
});

describe("the vulnerabilities and malicious-packages switches", () => {
  function vulnCtx(before: boolean, after: boolean) {
    return {
      settings: {
        vulnScanningEnabled: vi.fn(async () => before),
        updateVulnSettings: vi.fn(async () => ({ before: { enabled: before }, after: { enabled: after } })),
      },
      audit: { record: vi.fn(async () => {}) },
      vulnWorker: { requestBackfillAfterEnable: vi.fn() },
    } as unknown as AppContext;
  }

  it("read the existing vulnerability setting, so an upgraded installation keeps its state", async () => {
    const ctx = vulnCtx(true, true);
    expect(await vulnerabilitiesModule.toggle!.enabled(ctx)).toBe(true);
    expect(ctx.settings.vulnScanningEnabled).toHaveBeenCalledOnce();
  });

  it("switching vulnerabilities on records it and starts the first backfill, as the settings page does", async () => {
    const ctx = vulnCtx(false, true);
    await vulnerabilitiesModule.toggle!.setEnabled(ctx, true, actor);
    expect(ctx.settings.updateVulnSettings).toHaveBeenCalledWith({ enabled: true }, actor);
    expect(ctx.audit.record).toHaveBeenCalledWith(
      expect.objectContaining({ action: "vuln.settings_update", actor }),
    );
    expect(ctx.vulnWorker.requestBackfillAfterEnable).toHaveBeenCalledOnce();
  });

  it("switching vulnerabilities off only changes the setting: the data stays", async () => {
    const ctx = vulnCtx(true, false);
    await vulnerabilitiesModule.toggle!.setEnabled(ctx, false, actor);
    expect(ctx.settings.updateVulnSettings).toHaveBeenCalledWith({ enabled: false }, actor);
    expect(ctx.vulnWorker.requestBackfillAfterEnable).not.toHaveBeenCalled();
    // The context offers nothing else; a delete would have thrown on a missing method.
  });

  it("malicious packages switch through the admin service, which audits and fetches the feed", async () => {
    const updateSettings = vi.fn(async () => ({}));
    const ctx = {
      settings: { getMaliciousSettings: vi.fn(async () => ({ enabled: true })) },
      adminMalicious: { updateSettings },
    } as unknown as AppContext;
    expect(await maliciousModule.toggle!.enabled(ctx)).toBe(true);
    await maliciousModule.toggle!.setEnabled(ctx, false, actor);
    expect(updateSettings).toHaveBeenCalledWith({ enabled: false }, actor);
  });

  it("are listed in order: the developer view (always on), vulnerabilities, malicious packages", () => {
    expect(PLATFORM_MODULES.map((m) => m.id)).toEqual(["developer", "vulnerabilities", "malicious"]);
    expect(PLATFORM_MODULES[0]!.toggle).toBeUndefined();
  });
});
