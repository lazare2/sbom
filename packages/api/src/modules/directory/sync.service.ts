import { sql } from "drizzle-orm";
import type { FastifyBaseLogger } from "fastify";
import {
  directorySyncSettingsSchema,
  type DirectoryPerson,
  type DirectorySyncPerson,
  type DirectorySyncPlan,
  type DirectorySyncRun,
  type DirectorySyncSettings,
  type DirectorySyncSquadChange,
  type DirectorySyncState,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import { setting } from "../../db/schema.js";
import { AppError } from "../../lib/errors.js";
import type { Actor, AuditService } from "../admin/audit.service.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import type { SessionService } from "../auth/session.service.js";
import { DirectoryError } from "./connector.js";
import type { DirectoryService } from "./directory.service.js";

export const DIRECTORY_SYNC_KEY = "directory.sync";

interface Stored {
  settings: DirectorySyncSettings;
  lastRun: DirectorySyncRun | null;
  lastAppliedAt: string | null;
  /** The server-local date the nightly sync last ran, so it runs once a night. */
  lastNightlyOn: string | null;
}

interface Account {
  id: string;
  email: string;
  name: string | null;
  directoryId: string | null;
  authProvider: string;
  role: string;
  isActive: boolean;
}

/** One directory person resolved against the accounts here. */
type Match =
  | { kind: "matched"; account: Account; firstMatch: boolean; newEmail: string | null }
  | { kind: "not_in_platform" }
  | { kind: "no_email" }
  | { kind: "conflict"; reason: string };

/** The work a plan stands for, kept beside it so applying never recomputes something different. */
interface Work {
  plan: DirectorySyncPlan;
  links: Array<{ squadId: string; groupId: string; groupName: string; groupDn: string }>;
  setDirectoryId: Array<{ userId: string; directoryId: string }>;
  changes: Array<{ squadId: string; add: string[]; remove: string[] }>;
  deactivate: string[];
}

const person = (p: DirectoryPerson, account?: Account): DirectorySyncPerson => ({
  userId: account?.id ?? null,
  email: account?.email ?? p.email,
  name: p.name ?? account?.name ?? null,
});

/** The next time the nightly sync is due: today at `hour` (server time) unless that has passed or run. */
export function nextRun(hour: number, lastNightlyOn: string | null, now = new Date()): Date {
  const next = new Date(now);
  next.setHours(hour, 0, 0, 0);
  if (next.getTime() + 60 * 60 * 1000 <= now.getTime() || lastNightlyOn === localDate(now)) {
    next.setDate(next.getDate() + 1);
  } else if (next.getTime() <= now.getTime()) {
    // Within the hour and not yet run: due at the next minute's check.
    return new Date(now.getTime() + 60 * 1000);
  }
  return next;
}

/** Today's date where the server is, YYYY-MM-DD. */
function localDate(d = new Date()): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

/**
 * The sync: every linked squad's members made equal to its directory group's.
 *
 * - People are matched by the directory id stored on their account; the first time, by email,
 *   and the id is stored then. An address that now belongs to a different directory person is
 *   refused, never taken over. An address changed in the directory is followed.
 * - People disabled in the directory leave every linked squad, and an account that came from
 *   single sign-on is deactivated and signed out. Local accounts and administrators never are.
 * - Nobody is created here: someone with no account gets one, and their squads, at first sign-in.
 * - A read that fails changes nothing. A group that no longer exists leaves its squad as it is.
 * - A plan that removes a lot - or the first sync - waits for an administrator.
 * - Applying is one transaction. The team-lead mark of people who stay is kept.
 */
export class DirectorySyncService {
  private running = false;
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private readonly deps: {
      db: Database;
      audit: AuditService;
      directory: DirectoryService;
      sessions: SessionService;
      logger: FastifyBaseLogger;
    },
  ) {}

  // ---- state -----------------------------------------------------------------------------------

  private async read(): Promise<Stored> {
    const rows = await this.deps.db.execute<Row<{ value: unknown }>>(sql`
      SELECT value FROM setting WHERE key = ${DIRECTORY_SYNC_KEY}
    `);
    const raw = (rowsOf(rows)[0]?.value ?? {}) as Partial<Stored>;
    const parsed = directorySyncSettingsSchema.safeParse(raw.settings ?? {});
    return {
      settings: parsed.success ? parsed.data : directorySyncSettingsSchema.parse({}),
      lastRun: raw.lastRun ?? null,
      lastAppliedAt: raw.lastAppliedAt ?? null,
      lastNightlyOn: raw.lastNightlyOn ?? null,
    };
  }

  private async write(next: Stored): Promise<void> {
    await this.deps.db
      .insert(setting)
      .values({ key: DIRECTORY_SYNC_KEY, value: next })
      .onConflictDoUpdate({ target: setting.key, set: { value: next, updatedAt: new Date() } });
  }

  async state(): Promise<DirectorySyncState> {
    const s = await this.read();
    return {
      settings: s.settings,
      timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      running: this.running,
      lastRun: s.lastRun,
      lastAppliedAt: s.lastAppliedAt,
      nextRunAt: nextRun(s.settings.hour, s.lastNightlyOn).toISOString(),
    };
  }

  async updateSettings(input: DirectorySyncSettings, actor: Actor): Promise<DirectorySyncState> {
    const current = await this.read();
    await this.write({ ...current, settings: input });
    await this.deps.audit.record({
      actor,
      action: "directory.sync_settings",
      targetType: "setting",
      targetId: DIRECTORY_SYNC_KEY,
      metadata: { from: current.settings, to: input },
    });
    return this.state();
  }

  // ---- the plan --------------------------------------------------------------------------------

  /** What a sync would do now. Changes nothing. */
  async preview(): Promise<DirectorySyncPlan> {
    return (await this.compute()).plan;
  }

  private async compute(): Promise<Work> {
    const stored = await this.read();
    const db = this.deps.db;

    const links = rowsOf(
      await db.execute<Row<{ squad_id: string; squad_name: string; group_id: string; group_name: string; group_dn: string }>>(sql`
        SELECT l.squad_id, s.name AS squad_name, l.group_id, l.group_name, l.group_dn
          FROM squad_directory_link l JOIN squad s ON s.id = l.squad_id
         ORDER BY lower(s.name)
      `),
    );
    const accounts = rowsOf(
      await db.execute<
        Row<{ id: string; email: string; first_name: string | null; last_name: string | null; directory_id: string | null; auth_provider: string; role: string; is_active: boolean }>
      >(sql`SELECT id, lower(email) AS email, first_name, last_name, directory_id, auth_provider, role, is_active FROM "user"`),
    ).map(
      (r): Account => ({
        id: r.id,
        email: r.email,
        name: [r.first_name, r.last_name].filter(Boolean).join(" ") || null,
        directoryId: r.directory_id,
        authProvider: r.auth_provider,
        role: r.role,
        isActive: r.is_active,
      }),
    );
    const byDirectoryId = new Map(accounts.filter((a) => a.directoryId).map((a) => [a.directoryId!, a]));
    const byEmail = new Map(accounts.map((a) => [a.email, a]));
    const squadIds = links.map((l) => l.squad_id);
    const currentRows =
      squadIds.length === 0
        ? []
        : rowsOf(
            await db.execute<Row<{ squad_id: string; user_id: string }>>(sql`
              SELECT squad_id, user_id FROM squad_member WHERE squad_id = ANY(${sql.param(squadIds)}::uuid[])
            `),
          );
    const current = new Map<string, Set<string>>(squadIds.map((id) => [id, new Set<string>()]));
    for (const r of currentRows) current.get(r.squad_id)!.add(r.user_id);
    const accountById = new Map(accounts.map((a) => [a.id, a]));

    // One answer per directory person, however many groups they are in.
    const matches = new Map<string, Match>();
    const resolve = (p: DirectoryPerson): Match => {
      const known = matches.get(p.id);
      if (known) return known;
      let m: Match;
      const byId = byDirectoryId.get(p.id);
      if (byId) {
        const other = p.email ? byEmail.get(p.email) : undefined;
        m =
          p.email && p.email !== byId.email && other && other.id !== byId.id
            ? { kind: "conflict", reason: `the directory gives ${byId.email} the address ${p.email}, which another account here already has` }
            : { kind: "matched", account: byId, firstMatch: false, newEmail: p.email && p.email !== byId.email ? p.email : null };
      } else if (!p.email) {
        m = { kind: "no_email" };
      } else {
        const account = byEmail.get(p.email);
        if (!account) m = { kind: "not_in_platform" };
        else if (account.directoryId && account.directoryId !== p.id) {
          m = { kind: "conflict", reason: "this address belongs to a different directory person than the one this account was matched to" };
        } else m = { kind: "matched", account, firstMatch: true, newEmail: null };
      }
      matches.set(p.id, m);
      return m;
    };

    const plan: DirectorySyncPlan = {
      computedAt: new Date().toISOString(),
      squads: [],
      totals: { add: 0, remove: 0 },
      newlyMatched: 0,
      emailUpdates: [],
      deactivate: [],
      notInPlatform: [],
      noEmail: [],
      conflicts: [],
      holdReasons: [],
    };
    const work: Work = {
      plan,
      links: links.map((l) => ({ squadId: l.squad_id, groupId: l.group_id, groupName: l.group_name, groupDn: l.group_dn })),
      setDirectoryId: [],
      changes: [],
      deactivate: [],
    };

    if (links.length === 0) return work;
    const connector = await this.deps.directory.connector();
    const seen = { notIn: new Set<string>(), noEmail: new Set<string>(), conflict: new Set<string>(), deactivate: new Set<string>() };

    for (const link of links) {
      const before = current.get(link.squad_id)!;
      const change: DirectorySyncSquadChange = {
        squadId: link.squad_id,
        squadName: link.squad_name,
        groupName: link.group_name,
        current: before.size,
        add: [],
        remove: [],
        skipped: null,
      };
      plan.squads.push(change);

      // Any failure to read here stops the whole sync before anything is changed.
      const group = await connector.group(link.group_id);
      if (!group) {
        change.skipped = `The group "${link.group_name}" no longer exists in the directory; the squad is left as it is. Link it to another group or unlink it.`;
        continue;
      }
      const l = work.links.find((x) => x.squadId === link.squad_id)!;
      l.groupName = group.name;
      l.groupDn = group.dn;
      change.groupName = group.name;

      const wanted = new Set<string>();
      for (const p of await connector.members(link.group_id)) {
        const m = resolve(p);
        if (m.kind === "not_in_platform") {
          if (!seen.notIn.has(p.id)) plan.notInPlatform.push(person(p));
          seen.notIn.add(p.id);
        } else if (m.kind === "no_email") {
          if (!seen.noEmail.has(p.id)) plan.noEmail.push(person(p));
          seen.noEmail.add(p.id);
        } else if (m.kind === "conflict") {
          if (!seen.conflict.has(p.id)) plan.conflicts.push({ email: p.email ?? "(none)", reason: m.reason });
          seen.conflict.add(p.id);
        } else {
          if (p.enabled) wanted.add(m.account.id);
          else if (
            m.account.isActive &&
            m.account.authProvider === "oidc" &&
            m.account.role !== "admin" &&
            !seen.deactivate.has(m.account.id)
          ) {
            seen.deactivate.add(m.account.id);
            plan.deactivate.push(person(p, m.account));
            work.deactivate.push(m.account.id);
          }
        }
      }

      const add = [...wanted].filter((id) => !before.has(id));
      // People already on the squad but disabled, unmatched or gone from the group all leave it.
      const remove = [...before].filter((id) => !wanted.has(id));
      change.add = add.map((id) => ({ userId: id, email: accountById.get(id)!.email, name: accountById.get(id)!.name }));
      change.remove = remove.map((id) => ({ userId: id, email: accountById.get(id)?.email ?? null, name: accountById.get(id)?.name ?? null }));
      work.changes.push({ squadId: link.squad_id, add, remove });
    }

    for (const [directoryId, m] of matches) {
      if (m.kind !== "matched") continue;
      if (m.firstMatch) work.setDirectoryId.push({ userId: m.account.id, directoryId });
      if (m.newEmail) plan.emailUpdates.push({ userId: m.account.id, from: m.account.email, to: m.newEmail });
    }
    plan.newlyMatched = work.setDirectoryId.length;
    plan.totals = {
      add: plan.squads.reduce((n, s) => n + s.add.length, 0),
      remove: plan.squads.reduce((n, s) => n + s.remove.length, 0),
    };

    // When to wait for an administrator.
    const { maxRemovals, maxSquadSharePct } = stored.settings;
    if (!stored.lastAppliedAt) plan.holdReasons.push("This is the first sync: check what it will do before it runs.");
    if (plan.totals.remove > maxRemovals) {
      plan.holdReasons.push(`It would remove ${plan.totals.remove} people from squads (the limit is ${maxRemovals}).`);
    }
    if (plan.deactivate.length > maxRemovals) {
      plan.holdReasons.push(`It would deactivate ${plan.deactivate.length} accounts (the limit is ${maxRemovals}).`);
    }
    for (const s of plan.squads) {
      if (s.current === 0 || s.remove.length === 0) continue;
      if (s.current - s.remove.length + s.add.length === 0) {
        plan.holdReasons.push(`It would leave "${s.squadName}" with nobody.`);
      } else if ((s.remove.length / s.current) * 100 > maxSquadSharePct) {
        plan.holdReasons.push(
          `It would remove ${s.remove.length} of the ${s.current} members of "${s.squadName}" (the limit is ${maxSquadSharePct}%).`,
        );
      }
    }
    return work;
  }

  // ---- running ---------------------------------------------------------------------------------

  /**
   * Runs a sync. A plan with hold reasons is stored as "held" unless `approve` says an
   * administrator has seen it. Never throws for a directory problem: the run says it failed.
   */
  async run(
    trigger: DirectorySyncRun["trigger"],
    actor: Actor | null,
    approve = false,
    /** For the nightly run: the night it ran for, so it runs once per night. */
    nightlyOn: string = localDate(),
  ): Promise<DirectorySyncRun> {
    if (!(await this.deps.directory.enabled())) {
      throw new AppError({ statusCode: 409, code: "module_disabled", message: "The directory is switched off." });
    }
    if (this.running) {
      throw new AppError({ statusCode: 409, code: "sync_running", message: "A sync is already running. Try again in a moment." });
    }
    this.running = true;
    const at = new Date().toISOString();
    let result: DirectorySyncRun;
    try {
      const work = await this.compute();
      const { plan } = work;
      const nothing =
        plan.totals.add + plan.totals.remove + plan.deactivate.length + plan.emailUpdates.length + work.setDirectoryId.length === 0;
      if (plan.holdReasons.length > 0 && !approve) {
        result = { at, trigger, status: "held", plan, error: null };
      } else if (nothing) {
        result = { at, trigger: approve ? "approval" : trigger, status: "nothing_to_do", plan, error: null };
        if (plan.holdReasons.length > 0) await this.markApplied(at);
      } else {
        await this.apply(work, actor);
        result = { at, trigger: approve ? "approval" : trigger, status: "applied", plan, error: null };
        await this.markApplied(at);
      }
    } catch (error) {
      const message =
        error instanceof DirectoryError
          ? `${error.message}${error.detail ? ` (${error.detail})` : ""} Nothing was changed.`
          : `The sync failed: ${error instanceof Error ? error.message : String(error)}. Nothing was changed.`;
      this.deps.logger.warn({ err: error }, "directory sync failed");
      result = { at, trigger, status: "failed", plan: null, error: message };
    } finally {
      this.running = false;
    }

    const current = await this.read();
    await this.write({
      ...current,
      lastRun: result,
      lastNightlyOn: trigger === "nightly" ? nightlyOn : current.lastNightlyOn,
    });
    await this.deps.audit.record({
      actor,
      action: "directory.sync",
      targetType: "module",
      targetId: "directory",
      metadata: {
        trigger: result.trigger,
        status: result.status,
        added: result.plan?.totals.add ?? 0,
        removed: result.plan?.totals.remove ?? 0,
        deactivated: result.status === "applied" ? (result.plan?.deactivate.length ?? 0) : 0,
        held: result.plan?.holdReasons ?? [],
        error: result.error,
      },
    });
    return result;
  }

  private async markApplied(at: string): Promise<void> {
    const current = await this.read();
    await this.write({ ...current, lastAppliedAt: at });
  }

  private async apply(work: Work, actor: Actor | null): Promise<void> {
    const { plan } = work;
    await this.deps.db.transaction(async (tx) => {
      for (const s of work.setDirectoryId) {
        await tx.execute(sql`UPDATE "user" SET directory_id = ${s.directoryId}, updated_at = now()
                               WHERE id = ${s.userId}::uuid AND directory_id IS NULL`);
      }
      for (const e of plan.emailUpdates) {
        await tx.execute(sql`UPDATE "user" SET email = ${e.to}, updated_at = now()
                               WHERE id = ${e.userId}::uuid
                                 AND NOT EXISTS (SELECT 1 FROM "user" o WHERE lower(o.email) = ${e.to} AND o.id <> ${e.userId}::uuid)`);
      }
      for (const c of work.changes) {
        if (c.remove.length > 0) {
          await tx.execute(sql`DELETE FROM squad_member
                                 WHERE squad_id = ${c.squadId}::uuid AND user_id = ANY(${sql.param(c.remove)}::uuid[])`);
        }
        for (const userId of c.add) {
          await tx.execute(sql`INSERT INTO squad_member (squad_id, user_id) VALUES (${c.squadId}::uuid, ${userId}::uuid)
                                 ON CONFLICT DO NOTHING`);
        }
      }
      for (const l of work.links) {
        await tx.execute(sql`UPDATE squad_directory_link SET group_name = ${l.groupName}, group_dn = ${l.groupDn}
                               WHERE squad_id = ${l.squadId}::uuid`);
      }
      if (work.deactivate.length > 0) {
        await tx.execute(sql`UPDATE "user" SET is_active = false, updated_at = now()
                               WHERE id = ANY(${sql.param(work.deactivate)}::uuid[])
                                 AND role <> 'admin' AND auth_provider = 'oidc'`);
      }
    });

    for (const id of work.deactivate) await this.deps.sessions.revokeAllForUser(id);
    for (const c of work.changes) {
      if (c.add.length + c.remove.length === 0) continue;
      await this.deps.audit.record({
        actor,
        action: "squad.members_synced",
        targetType: "squad",
        targetId: c.squadId,
        metadata: { added: c.add, removed: c.remove },
      });
    }
    for (const p of plan.deactivate) {
      await this.deps.audit.record({
        actor,
        action: "user.deactivated_by_directory",
        targetType: "user",
        targetId: p.userId,
        metadata: { email: p.email, reason: "disabled in the directory" },
      });
    }
  }

  // ---- nightly ---------------------------------------------------------------------------------

  /** Checks once a minute whether tonight's sync is due. Inert while the module is off. */
  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick(), 60_000);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async tick(now = new Date()): Promise<void> {
    try {
      if (this.running || !(await this.deps.directory.enabled())) return;
      const s = await this.read();
      if (now.getHours() !== s.settings.hour || s.lastNightlyOn === localDate(now)) return;
      await this.run("nightly", null, false, localDate(now));
    } catch (error) {
      this.deps.logger.warn({ err: error }, "directory nightly sync could not start");
    }
  }
}
