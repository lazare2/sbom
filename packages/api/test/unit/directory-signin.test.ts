import { describe, expect, it, vi } from "vitest";
import type { DirectoryPerson } from "@sbom/shared";
import { DirectoryError } from "../../src/modules/directory/connector.js";
import { DirectorySyncService } from "../../src/modules/directory/sync.service.js";

/** Squads from the directory at single sign-on: one person, at once, never blocking for long. */

const G_PAY = "g-pay";
const G_LED = "g-led";

function setup(opts: {
  account?: { directory_id?: string | null; auth_provider?: string; role?: string; is_active?: boolean };
  person?: DirectoryPerson | null;
  groups?: string[];
  current?: string[];
  enabled?: boolean;
  slow?: boolean;
  failWith?: Error;
}) {
  const statements: string[] = [];
  const db = {
    execute: vi.fn(async (q: unknown) => {
      const t = JSON.stringify(q);
      if (t.includes("SELECT squad_id, group_id FROM squad_directory_link")) {
        return { rows: [{ squad_id: "sq-pay", group_id: G_PAY }, { squad_id: "sq-led", group_id: G_LED }] };
      }
      if (t.includes('FROM \\"user\\" WHERE id')) {
        return {
          rows: [{ id: "u1", email: "alice@corp.example", directory_id: null, auth_provider: "oidc", role: "user", is_active: true, ...opts.account }],
        };
      }
      if (t.includes("SELECT squad_id FROM squad_member")) return { rows: (opts.current ?? []).map((squad_id) => ({ squad_id })) };
      return { rows: [] };
    }),
    transaction: vi.fn(async (fn: (tx: unknown) => Promise<void>) => fn({ execute: async (q: unknown) => void statements.push(JSON.stringify(q)) })),
  };
  const connector = {
    personByEmail: vi.fn(async () => {
      if (opts.failWith) throw opts.failWith;
      if (opts.slow) await new Promise((r) => setTimeout(r, 6_000));
      return opts.person === undefined ? { id: "ad-alice", email: "alice@corp.example", name: "Alice", enabled: true } : opts.person;
    }),
    groupsOf: vi.fn(async () => opts.groups ?? []),
  };
  const audit = { record: vi.fn(async () => {}) };
  const sessions = { revokeAllForUser: vi.fn(async () => 0) };
  const logger = { warn: vi.fn() };
  const svc = new DirectorySyncService({
    db: db as never,
    audit: audit as never,
    directory: { enabled: async () => opts.enabled !== false, connector: async () => connector } as never,
    sessions: sessions as never,
    logger: logger as never,
  });
  return { svc, db, statements, audit, sessions, logger, connector };
}

describe("squads at sign-in", () => {
  it("joins the linked squads whose groups the person is in, and stores their directory id", async () => {
    const { svc, statements, audit } = setup({ groups: [G_PAY, "some-other-group"] });
    expect(await svc.applyForSignIn("u1")).toBe("applied");
    const all = statements.join(" ");
    expect(all).toContain("SET directory_id");
    expect(all).toContain("INSERT INTO squad_member");
    expect(all).not.toContain("DELETE FROM squad_member");
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({ action: "user.squads_from_directory", metadata: expect.objectContaining({ added: ["sq-pay"], removed: [] }) }),
    );
  });

  it("moves a person who changed teams: leaves the old linked squad, joins the new one", async () => {
    const { svc, statements } = setup({ groups: [G_LED], current: ["sq-pay"] });
    expect(await svc.applyForSignIn("u1")).toBe("applied");
    expect(statements.join(" ")).toContain("DELETE FROM squad_member");
  });

  it("changes nothing when the squads already match", async () => {
    const { svc, audit } = setup({ groups: [G_PAY], current: ["sq-pay"] });
    expect(await svc.applyForSignIn("u1")).toBe("unchanged");
    expect(audit.record).not.toHaveBeenCalled();
  });

  it("deactivates and refuses a single sign-on account the directory has switched off", async () => {
    const { svc, statements, sessions } = setup({ person: { id: "ad-alice", email: "alice@corp.example", name: "Alice", enabled: false }, current: ["sq-pay"] });
    expect(await svc.applyForSignIn("u1")).toBe("disabled");
    expect(statements.join(" ")).toContain("SET is_active = false");
    expect(sessions.revokeAllForUser).toHaveBeenCalledWith("u1");
  });

  it("never deactivates an administrator, even one switched off in the directory", async () => {
    const { svc, statements } = setup({ account: { role: "admin" }, person: { id: "ad-alice", email: "alice@corp.example", name: "Alice", enabled: false } });
    expect(await svc.applyForSignIn("u1")).not.toBe("disabled");
    expect(statements.join(" ")).not.toContain("is_active = false");
  });

  it("leaves squads alone when the address belongs to a different directory person", async () => {
    const { svc, db } = setup({ account: { directory_id: "ad-someone-else" }, groups: [G_PAY] });
    expect(await svc.applyForSignIn("u1")).toBe("skipped");
    expect(db.transaction).not.toHaveBeenCalled();
  });

  it("does nothing for somebody the directory does not know, or while the module is off", async () => {
    expect(await setup({ person: null }).svc.applyForSignIn("u1")).toBe("skipped");
    const off = setup({ enabled: false });
    expect(await off.svc.applyForSignIn("u1")).toBe("skipped");
    expect(off.connector.personByEmail).not.toHaveBeenCalled();
  });

  it("never blocks a sign-in on the directory: unreachable or slow means squads as they were", async () => {
    const down = setup({ failWith: new DirectoryError("unreachable", "The server could not be reached.") });
    expect(await down.svc.applyForSignIn("u1")).toBe("skipped");
    expect(down.db.transaction).not.toHaveBeenCalled();

    vi.useFakeTimers();
    const slow = setup({ slow: true });
    const pending = slow.svc.applyForSignIn("u1");
    await vi.advanceTimersByTimeAsync(5_100);
    expect(await pending).toBe("skipped");
    expect(slow.db.transaction).not.toHaveBeenCalled();
    vi.useRealTimers();
  });
});
