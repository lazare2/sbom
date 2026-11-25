import { describe, expect, it, vi } from "vitest";
import type { DirectoryPerson } from "@sbom/shared";
import { DirectoryError } from "../../src/modules/directory/connector.js";
import { DIRECTORY_SYNC_KEY, DirectorySyncService } from "../../src/modules/directory/sync.service.js";

/** The sync: linked squads made equal to their directory groups, with the safety rules. */

const G_PAY = "11111111-1111-1111-1111-111111111111";
const G_LED = "22222222-2222-2222-2222-222222222222";

interface Data {
  links: Array<{ squad_id: string; squad_name: string; group_id: string; group_name: string; group_dn: string }>;
  users: Array<{ id: string; email: string; first_name?: string | null; last_name?: string | null; directory_id?: string | null; auth_provider?: string; role?: string; is_active?: boolean }>;
  members: Array<{ squad_id: string; user_id: string }>;
  groups: Record<string, DirectoryPerson[] | "missing">;
  applied?: boolean;
  failWith?: Error;
}

function setup(data: Data) {
  const stored = new Map<string, unknown>();
  if (data.applied) stored.set(DIRECTORY_SYNC_KEY, { lastAppliedAt: "2026-11-01T00:00:00Z" });
  const txStatements: string[] = [];
  const execute = vi.fn(async (q: unknown) => {
    const t = JSON.stringify(q);
    if (t.includes("FROM setting WHERE key")) return { rows: stored.has(DIRECTORY_SYNC_KEY) ? [{ value: stored.get(DIRECTORY_SYNC_KEY) }] : [] };
    if (t.includes("FROM squad_directory_link l JOIN squad s")) return { rows: data.links };
    if (t.includes('FROM \\"user\\"')) {
      return {
        rows: data.users.map((u) => ({
          first_name: null, last_name: null, directory_id: null, auth_provider: "oidc", role: "user", is_active: true, ...u,
        })),
      };
    }
    if (t.includes("FROM squad_member WHERE squad_id")) return { rows: data.members };
    return { rows: [] };
  });
  const db = {
    execute,
    insert: () => ({
      values: (v: { key: string; value: unknown }) => ({
        onConflictDoUpdate: async () => void stored.set(v.key, JSON.parse(JSON.stringify(v.value))),
      }),
    }),
    transaction: vi.fn(async (fn: (tx: unknown) => Promise<void>) =>
      fn({ execute: async (q: unknown) => void txStatements.push(JSON.stringify(q)) }),
    ),
  };
  const connector = {
    group: vi.fn(async (id: string) => {
      if (data.failWith) throw data.failWith;
      return data.groups[id] === "missing" ? null : { id, name: id === G_PAY ? "Squad Payments" : "Squad Ledger", dn: `CN=${id}`, description: null };
    }),
    members: vi.fn(async (id: string) => data.groups[id] as DirectoryPerson[]),
  };
  const audit = { record: vi.fn(async () => {}) };
  const sessions = { revokeAllForUser: vi.fn(async () => 0) };
  const svc = new DirectorySyncService({
    db: db as never,
    audit: audit as never,
    directory: { enabled: async () => true, connector: async () => connector } as never,
    sessions: sessions as never,
    logger: { warn: vi.fn() } as never,
  });
  return { svc, db, txStatements, sessions, audit, stored };
}

const admin = { id: "admin-1", email: "admin@sbom.local" };
const ad = (id: string, email: string | null, enabled = true): DirectoryPerson => ({ id, email, name: email, enabled });
const payments = { squad_id: "sq-pay", squad_name: "Payments", group_id: G_PAY, group_name: "Squad Payments", group_dn: "CN=pay" };
const ledger = { squad_id: "sq-led", squad_name: "Ledger", group_id: G_LED, group_name: "Squad Ledger", group_dn: "CN=led" };

describe("matching people", () => {
  it("matches by email the first time and keeps the directory id; others are listed, not created", async () => {
    const { svc } = setup({
      links: [payments],
      users: [{ id: "u-alice", email: "alice@corp.example" }],
      members: [],
      groups: { [G_PAY]: [ad("ad-alice", "alice@corp.example"), ad("ad-newbie", "new@corp.example"), ad("ad-dave", null)] },
    });
    const plan = await svc.preview();
    expect(plan.squads[0]!.add.map((p) => p.userId)).toEqual(["u-alice"]);
    expect(plan.newlyMatched).toBe(1);
    expect(plan.notInPlatform.map((p) => p.email)).toEqual(["new@corp.example"]);
    expect(plan.noEmail).toHaveLength(1);
  });

  it("follows a changed address by the stored id", async () => {
    const { svc } = setup({
      links: [payments],
      users: [{ id: "u-anna", email: "anna.smith@corp.example", directory_id: "ad-anna" }],
      members: [{ squad_id: "sq-pay", user_id: "u-anna" }],
      groups: { [G_PAY]: [ad("ad-anna", "anna.jones@corp.example")] },
      applied: true,
    });
    const plan = await svc.preview();
    expect(plan.emailUpdates).toEqual([{ userId: "u-anna", from: "anna.smith@corp.example", to: "anna.jones@corp.example" }]);
    expect(plan.squads[0]!.remove).toEqual([]);
  });

  it("refuses an address that now belongs to a different directory person", async () => {
    const { svc } = setup({
      links: [payments],
      users: [{ id: "u-old", email: "j.doe@corp.example", directory_id: "ad-old-john" }],
      members: [],
      groups: { [G_PAY]: [ad("ad-new-jane", "j.doe@corp.example")] },
      applied: true,
    });
    const plan = await svc.preview();
    expect(plan.squads[0]!.add).toEqual([]);
    expect(plan.conflicts[0]!.email).toBe("j.doe@corp.example");
  });
});

describe("people disabled in the directory", () => {
  it("leave their squads; only single sign-on accounts that are not admins are deactivated", async () => {
    const { svc } = setup({
      links: [payments],
      users: [
        { id: "u-carol", email: "carol@corp.example" },
        { id: "u-local", email: "local@corp.example", auth_provider: "local" },
        { id: "u-admin", email: "boss@corp.example", role: "admin" },
        { id: "u-bob", email: "bob@corp.example" },
      ],
      members: ["u-carol", "u-local", "u-admin", "u-bob"].map((user_id) => ({ squad_id: "sq-pay", user_id })),
      groups: {
        [G_PAY]: [
          ad("a1", "carol@corp.example", false),
          ad("a2", "local@corp.example", false),
          ad("a3", "boss@corp.example", false),
          ad("a4", "bob@corp.example"),
        ],
      },
      applied: true,
    });
    const plan = await svc.preview();
    expect(plan.squads[0]!.remove.map((p) => p.userId).sort()).toEqual(["u-admin", "u-carol", "u-local"]);
    expect(plan.deactivate.map((p) => p.userId)).toEqual(["u-carol"]);
  });
});

describe("waiting for an administrator", () => {
  const base = (over: Partial<Data> = {}): Data => ({
    links: [payments],
    users: Array.from({ length: 8 }, (_, i) => ({ id: `u${i}`, email: `p${i}@corp.example` })),
    members: Array.from({ length: 8 }, (_, i) => ({ squad_id: "sq-pay", user_id: `u${i}` })),
    groups: { [G_PAY]: Array.from({ length: 8 }, (_, i) => ad(`a${i}`, `p${i}@corp.example`)) },
    applied: true,
    ...over,
  });

  it("does not wait for a small change", async () => {
    const { svc } = setup(base({ groups: { [G_PAY]: Array.from({ length: 7 }, (_, i) => ad(`a${i}`, `p${i}@corp.example`)) } }));
    expect((await svc.preview()).holdReasons).toEqual([]);
  });

  it("waits on the first sync", async () => {
    const { svc } = setup(base({ applied: false }));
    expect((await svc.preview()).holdReasons[0]).toMatch(/first sync/);
  });

  it("waits when a squad would lose more than its share", async () => {
    const { svc } = setup(base({ groups: { [G_PAY]: Array.from({ length: 5 }, (_, i) => ad(`a${i}`, `p${i}@corp.example`)) } }));
    expect((await svc.preview()).holdReasons.join(" ")).toMatch(/3 of the 8 members of "Payments"/);
  });

  it("waits when a group comes back empty, and does not touch the squad", async () => {
    const { svc, txStatements } = setup(base({ groups: { [G_PAY]: [] } }));
    const run = await svc.run("nightly", null);
    expect(run.status).toBe("held");
    expect(run.plan!.holdReasons.join(" ")).toMatch(/leave "Payments" with nobody/);
    expect(txStatements).toEqual([]);
  });

  it("waits when more than the limit would leave across squads", async () => {
    const users = Array.from({ length: 30 }, (_, i) => ({ id: `u${i}`, email: `p${i}@corp.example` }));
    const { svc } = setup({
      links: [payments, ledger],
      users,
      members: users.map((u, i) => ({ squad_id: i < 15 ? "sq-pay" : "sq-led", user_id: u.id })),
      groups: {
        [G_PAY]: users.slice(0, 9).map((u, i) => ad(`a${i}`, u.email)),
        [G_LED]: users.slice(15, 24).map((u, i) => ad(`b${i}`, u.email)),
      },
      applied: true,
    });
    expect((await svc.preview()).holdReasons.join(" ")).toMatch(/remove 12 people/);
  });

  it("applies a held plan once an administrator approves it", async () => {
    const { svc, txStatements, stored } = setup(base({ applied: false }));
    expect((await svc.run("manual", admin)).status).toBe("held");
    expect(txStatements).toEqual([]);
    // Approved: the eight people are matched for the first time, so their directory ids are stored.
    const run = await svc.run("manual", admin, true);
    expect(run.status).toBe("applied");
    expect(run.trigger).toBe("approval");
    expect(txStatements.join(" ")).toContain("SET directory_id");
    expect((stored.get(DIRECTORY_SYNC_KEY) as { lastAppliedAt: string | null }).lastAppliedAt).not.toBeNull();
  });
});

describe("applying", () => {
  it("adds, removes, stores ids and deactivates in one transaction, signs the deactivated out, keeps leads", async () => {
    const { svc, db, txStatements, sessions } = setup({
      links: [payments],
      users: [
        { id: "u-alice", email: "alice@corp.example" },
        { id: "u-carol", email: "carol@corp.example", directory_id: "ad-carol" },
        { id: "u-gone", email: "gone@corp.example", directory_id: "ad-gone" },
      ],
      members: [
        { squad_id: "sq-pay", user_id: "u-carol" },
        { squad_id: "sq-pay", user_id: "u-gone" },
      ],
      groups: { [G_PAY]: [ad("ad-alice", "alice@corp.example"), ad("ad-carol", "carol@corp.example", false)] },
      applied: true,
    });
    const run = await svc.run("manual", admin, true);
    expect(run.status).toBe("applied");
    expect(db.transaction).toHaveBeenCalledTimes(1);
    const all = txStatements.join("\n");
    expect(all).toContain("DELETE FROM squad_member");
    expect(all).toContain("INSERT INTO squad_member");
    expect(all).toContain("SET directory_id");
    expect(all).toContain("SET is_active = false");
    // Only the leavers' rows are deleted, so the lead mark of people who stay is untouched.
    expect(all).not.toMatch(/DELETE FROM squad_member\s+WHERE squad_id = [^A]*$/m);
    expect(sessions.revokeAllForUser).toHaveBeenCalledWith("u-carol");
  });

  it("leaves a squad as it is when its group is gone", async () => {
    const { svc } = setup({
      links: [payments],
      users: [{ id: "u1", email: "a@corp.example" }],
      members: [{ squad_id: "sq-pay", user_id: "u1" }],
      groups: { [G_PAY]: "missing" },
      applied: true,
    });
    const plan = await svc.preview();
    expect(plan.squads[0]!.skipped).toMatch(/no longer exists/);
    expect(plan.totals.remove).toBe(0);
  });

  it("changes nothing when the directory cannot be read", async () => {
    const { svc, db, audit } = setup({
      links: [payments],
      users: [],
      members: [],
      groups: {},
      failWith: new DirectoryError("unreachable", "The server could not be reached."),
      applied: true,
    });
    const run = await svc.run("nightly", null);
    expect(run.status).toBe("failed");
    expect(run.error).toMatch(/could not be reached.*Nothing was changed/);
    expect(db.transaction).not.toHaveBeenCalled();
    expect(audit.record).toHaveBeenCalledWith(expect.objectContaining({ action: "directory.sync" }));
  });
});

describe("the nightly run", () => {
  it("runs once, at the set hour", async () => {
    const { svc, stored } = setup({ links: [], users: [], members: [], groups: {}, applied: true });
    await svc.tick(new Date(2026, 10, 25, 2, 59));
    expect((stored.get(DIRECTORY_SYNC_KEY) as { lastRun?: unknown }).lastRun).toBeUndefined();
    await svc.tick(new Date(2026, 10, 25, 3, 0));
    const after = stored.get(DIRECTORY_SYNC_KEY) as { lastRun: { at: string }; lastNightlyOn: string };
    expect(after.lastNightlyOn).toBe("2026-11-25");
    const first = after.lastRun.at;
    await svc.tick(new Date(2026, 10, 25, 3, 30));
    expect((stored.get(DIRECTORY_SYNC_KEY) as { lastRun: { at: string } }).lastRun.at).toBe(first);
  });
});

describe("the next nightly run", () => {
  it("is today at the hour until it has run, then tomorrow", async () => {
    const { nextRun } = await import("../../src/modules/directory/sync.service.js");
    expect(nextRun(3, null, new Date(2026, 10, 25, 1, 0))).toEqual(new Date(2026, 10, 25, 3, 0));
    expect(nextRun(3, null, new Date(2026, 10, 25, 5, 0))).toEqual(new Date(2026, 10, 26, 3, 0));
    expect(nextRun(3, "2026-11-25", new Date(2026, 10, 25, 3, 10))).toEqual(new Date(2026, 10, 26, 3, 0));
  });
});
