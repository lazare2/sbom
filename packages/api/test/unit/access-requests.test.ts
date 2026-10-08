import { describe, expect, it, vi } from "vitest";
import {
  AccessRequestService,
  toAccessRequest,
  type AccessRequestQueryRow,
} from "../../src/modules/auth/access-request.service.js";
import { AuthService } from "../../src/modules/auth/auth.service.js";
import type { Database } from "../../src/db/client.js";
import type { VerifiedIdentity } from "../../src/services/auth/id-token.js";

/**
 * The queue of people the directory vouched for and this platform refused.
 *
 * Two guarantees are protected here, and both are about failures that produce no symptom.
 *
 * The first is that recording never throws. It hangs off a code path whose entire job is to
 * refuse a sign-in politely, and an exception there replaces an explanation the person can act
 * on with a server error they cannot. The second is that a failure to record is *logged* —
 * because the first guarantee is implemented by swallowing exceptions, and a swallowed
 * exception would otherwise disable this whole feature in silence. The visible symptom of that
 * would be an empty queue, which is exactly what it looks like when nobody has tried.
 *
 * What is not here: the deduplication itself. One pending row per identity is enforced by the
 * partial unique index in migration 0020 and by the ON CONFLICT clause that targets it, and
 * neither can be exercised without a real Postgres. The statement is asserted below to still
 * name that index; whether the index does its job is a question for a live sign-in.
 */

const IDENTITY: VerifiedIdentity = {
  subject: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  email: "lazare.shavgulidze@bog.ge",
  name: "Lazare Shavgulidze",
};

/**
 * A database that records the statement it was handed.
 *
 * The SQL is captured rather than executed. Drizzle's `sql` template produces an object whose
 * query text is only assembled by a dialect, so the fragments are read off it directly — enough
 * to assert which clauses are present, which is the only thing a test without a server can
 * honestly check.
 */
function harness(over: { throws?: Error; rows?: unknown[] } = {}) {
  const statements: string[] = [];
  const logger = { warn: vi.fn() };

  const execute = vi.fn(async (statement: unknown) => {
    statements.push(fragmentsOf(statement));
    if (over.throws) throw over.throws;
    return { rows: over.rows ?? [{ id: "request-1" }] };
  });

  const db = { execute } as unknown as Database;
  return { service: new AccessRequestService({ db, logger }), statements, logger, execute };
}

/** The literal chunks of a drizzle `sql` template, joined — the shape of the statement. */
function fragmentsOf(statement: unknown): string {
  const chunks = (statement as { queryChunks?: unknown[] }).queryChunks ?? [];
  return chunks
    .map((chunk) => {
      // A null parameter lands in the chunk list as a bare null, so this cannot assume every
      // chunk is an object. Only the literal fragments carry a string array; everything else
      // is a bound value and contributes nothing to the shape being asserted.
      const value = (chunk as { value?: unknown } | null)?.value;
      return Array.isArray(value) ? value.join("") : "";
    })
    .join(" ");
}

describe("recording a refused sign-in", () => {
  it("reports that the request is on the queue", async () => {
    const { service } = harness();
    await expect(
      service.record(IDENTITY, { provider: "oidc", reason: "no_account" }),
    ).resolves.toBe(true);
  });

  it("reports false rather than throwing when the write fails", async () => {
    /*
      The sign-in page chooses between two sentences on this boolean, and one of them tells the
      person administrators have been notified. Throwing would replace a readable refusal with
      a 500; returning true would promise a notification nobody received.
    */
    const { service } = harness({ throws: new Error("deadlock detected") });
    await expect(
      service.record(IDENTITY, { provider: "oidc", reason: "no_account" }),
    ).resolves.toBe(false);
  });

  it("reports false when the statement affected nothing", async () => {
    // No RETURNING row means no request exists, whatever the reason. Reading that as success
    // is how the screen ends up claiming a queue entry that is not there.
    const { service } = harness({ rows: [] });
    await expect(
      service.record(IDENTITY, { provider: "oidc", reason: "no_account" }),
    ).resolves.toBe(false);
  });

  it("logs the failure instead of swallowing it silently", async () => {
    // The guarantee that makes the swallow above acceptable. Without this line, a statement
    // broken by a later edit would leave a permanently empty queue and no way to tell that
    // from nobody having been refused.
    const { service, logger } = harness({ throws: new Error("syntax error at or near ON") });
    await service.record(IDENTITY, { provider: "oidc", reason: "no_account" });
    expect(logger.warn).toHaveBeenCalled();
  });

  it("upserts onto the partial index rather than inserting a row per attempt", async () => {
    /*
      Two clauses, and the statement is wrong without either.

      ON CONFLICT is what folds a repeat attempt into the row already open — nine attempts by
      one person is one colleague waiting, and nine rows would turn a queue into a log nobody
      drains. The WHERE predicate is what lets Postgres identify *which* index is meant: the
      unique index is partial, and conflict inference against a partial index fails outright
      without its predicate repeated here. Since `record` swallows its errors, getting this
      wrong fails silently and forever.
    */
    const { service, statements } = harness();
    await service.record(IDENTITY, { provider: "oidc", reason: "no_account" });

    const sql = statements.join(" ");
    expect(sql).toContain("ON CONFLICT");
    expect(sql).toContain("status = 'pending'");
    // Folded, not replaced: an attempt count that resets on every retry conveys nothing.
    expect(sql).toContain("attempts = access_request.attempts + 1");
  });

  it("keeps a previously known address when a later token carries none", async () => {
    // `email` arrives only where that claim was consented to, and the same person can produce
    // a token with it and then one without. Overwriting with null would discard the only thing
    // that makes the row actionable.
    const { service, statements } = harness();
    await service.record(IDENTITY, { provider: "oidc", reason: "no_account" });
    expect(statements.join(" ")).toContain("COALESCE(EXCLUDED.email, access_request.email)");
  });
});

describe("clearing a request when the person finally gets in", () => {
  it("never throws, because the session has already been issued", async () => {
    // This runs after a successful sign-in. An exception here would cost somebody the session
    // they just legitimately earned, over a failure to tidy a queue.
    const { service } = harness({ throws: new Error("connection terminated") });
    await expect(
      service.resolveOnSignIn({ provider: "oidc", subject: IDENTITY.subject, userId: "u1" }),
    ).resolves.toBeUndefined();
  });

  it("logs that failure too", async () => {
    const { service, logger } = harness({ throws: new Error("connection terminated") });
    await service.resolveOnSignIn({
      provider: "oidc",
      subject: IDENTITY.subject,
      userId: "u1",
    });
    expect(logger.warn).toHaveBeenCalled();
  });

  it("touches only the pending row for that identity", async () => {
    const { service, statements } = harness();
    await service.resolveOnSignIn({
      provider: "oidc",
      subject: IDENTITY.subject,
      userId: "u1",
    });

    const sql = statements.join(" ");
    // Without the status guard this would reopen and re-stamp rows an administrator already
    // dismissed, overwriting a decision with an automatic one.
    expect(sql).toContain("status = 'pending'");
    // Only if still empty: an explicit resolution names the account that answered the
    // request, and a later sign-in must not overwrite it.
    expect(sql).toContain("COALESCE(created_user_id");
  });
});

describe("settling a request by hand", () => {
  it("reports false when nothing was pending under that id", async () => {
    // Two administrators working one queue is ordinary. The route turns this into a 404, so
    // "somebody got there first" is distinguishable from "the button does nothing".
    const { service } = harness({ rows: [] });
    await expect(
      service.settle({
        id: "req-1",
        status: "dismissed",
        actor: { id: "admin-1", email: "admin@bog.ge" },
      }),
    ).resolves.toBe(false);
  });

  it("refuses to settle a row that is not pending", async () => {
    const { service, statements } = harness();
    await service.settle({
      id: "req-1",
      status: "resolved",
      actor: { id: "admin-1", email: "admin@bog.ge" },
    });
    expect(statements.join(" ")).toContain("status = 'pending'");
  });
});

describe("reading a row back", () => {
  const row = (over: Partial<AccessRequestQueryRow> = {}): AccessRequestQueryRow => ({
    id: "req-1",
    provider: "oidc",
    email: "lazare.shavgulidze@bog.ge",
    display_name: "Lazare Shavgulidze",
    reason: "no_account",
    status: "pending",
    attempts: 3,
    first_seen_at: new Date("2026-10-06T08:00:00Z"),
    last_seen_at: new Date("2026-10-06T12:00:00Z"),
    resolved_at: null,
    resolved_by_email: null,
    ...over,
  });

  it("carries the fields the screen renders", () => {
    const request = toAccessRequest(row());
    expect(request.email).toBe("lazare.shavgulidze@bog.ge");
    expect(request.attempts).toBe(3);
    expect(request.firstSeenAt).toBe("2026-10-06T08:00:00.000Z");
  });

  it("keeps rendering when a column holds a value this build has never heard of", () => {
    /*
      `reason` and `status` are text, not enums, so adding a value stays a code change rather
      than a migration -- which means a row written by a newer version, or by hand, can hold
      something unknown. Throwing on it would take down the one screen an administrator opens
      to find out who is locked out, and would do so for every row because of the one.
    */
    expect(toAccessRequest(row({ reason: "something_new" })).reason).toBe("no_account");
    expect(toAccessRequest(row({ status: "half_done" })).status).toBe("pending");
  });

  it("passes through a missing address rather than inventing one", () => {
    // A token need not carry an address. An empty string here would render as a blank cell
    // that reads as a bug, and the screen branches on null to say so plainly instead.
    const request = toAccessRequest(row({ email: null, display_name: null }));
    expect(request.email).toBeNull();
    expect(request.displayName).toBeNull();
  });
});

// ---------------------------------------------------------------------------

/**
 * Which refusals reach the queue, and which deliberately do not.
 *
 * This is the scope decision, and it is the one most likely to be undone by somebody later
 * reasoning that "every failed sign-in should be visible". Two of the three refusals must stay
 * out, because the queue's only action is "create an account" and for those two that is the
 * wrong action:
 *
 * - `inactive` means the account exists and an administrator switched it off on purpose.
 *   Listing it as needing an account invites undoing a deliberate decision.
 * - `identity_conflict` means an identity needs unlinking, not an account creating.
 *
 * Both already appear in the error log. Only `no_account` describes somebody who needs
 * provisioning, so only `no_account` is queued.
 */
function authHarness(rows: unknown[][]) {
  /*
    A drizzle select chain deep enough for the two lookups this method performs, answering
    from a queue so each call can return something different. `update` has to be chainable the
    same way, because the success path writes `last_login_at`.
  */
  const queue = [...rows];
  const select = () => ({
    from: () => ({
      where: () => ({ limit: async () => queue.shift() ?? [] }),
    }),
  });
  const db = {
    select,
    update: () => ({
      set: () => ({
        where: async () => [],
        returning: async () => [],
      }),
    }),
  } as unknown as Database;

  const record = vi.fn(async () => true);
  const resolveOnSignIn = vi.fn(async () => undefined);
  const sessions = {
    create: async () => ({ token: "t", expiresAt: new Date("2026-10-07T00:00:00Z") }),
  };

  const service = new AuthService({
    db,
    config: {} as never,
    providers: {} as never,
    sessions: sessions as never,
    accessRequests: { record, resolveOnSignIn } as never,
    logger: { warn: vi.fn(), error: vi.fn() },
  });

  return { service, record, resolveOnSignIn };
}

const account = (over: Record<string, unknown> = {}) => ({
  id: "user-1",
  email: "lazare.shavgulidze@bog.ge",
  authProvider: "oidc",
  authSubject: IDENTITY.subject,
  isActive: true,
  ...over,
});

describe("which refusals are queued", () => {
  it("queues an identity nobody has provisioned", async () => {
    // Both lookups miss: no account by subject, none by address.
    const { service, record } = authHarness([[], []]);
    const outcome = await service.signInWithDirectory(IDENTITY, {});

    expect(outcome).toMatchObject({ ok: false, reason: "no_account", requested: true });
    expect(record).toHaveBeenCalledWith(
      IDENTITY,
      expect.objectContaining({ reason: "no_account" }),
    );
  });

  it("reports the refusal as unqueued when the write failed", async () => {
    // The sign-in page says "administrators have been notified" on the strength of this flag,
    // so it has to follow the write rather than the intention to write.
    const { service, record } = authHarness([[], []]);
    record.mockResolvedValueOnce(false);
    const outcome = await service.signInWithDirectory(IDENTITY, {});
    expect(outcome).toMatchObject({ ok: false, reason: "no_account", requested: false });
  });

  it("does not queue a deactivated account", async () => {
    const { service, record } = authHarness([[account({ isActive: false })]]);
    const outcome = await service.signInWithDirectory(IDENTITY, {});

    expect(outcome).toMatchObject({ ok: false, reason: "inactive" });
    expect(record).not.toHaveBeenCalled();
  });

  it("does not queue an identity that conflicts with an existing account", async () => {
    // Found by address, already bound to a different directory identity. Creating a second
    // account would not help; unlinking the first is the fix, and that is not this screen.
    const { service, record } = authHarness([
      [],
      [account({ authSubject: "somebody-elses-subject" })],
    ]);
    const outcome = await service.signInWithDirectory(IDENTITY, {});

    expect(outcome).toMatchObject({ ok: false, reason: "identity_conflict" });
    expect(record).not.toHaveBeenCalled();
  });

  it("clears the queue for somebody who gets in", async () => {
    /*
      What makes the queue drain itself. An administrator who creates the account from the
      queue resolves the row directly, but one who creates it from the Users page does not --
      and a queue that only empties on the right button accumulates rows that are already
      dealt with, which is how a triage screen stops being read.
    */
    const { service, resolveOnSignIn } = authHarness([[account()]]);
    const outcome = await service.signInWithDirectory(IDENTITY, {});

    expect(outcome.ok).toBe(true);
    expect(resolveOnSignIn).toHaveBeenCalledWith(
      expect.objectContaining({ subject: IDENTITY.subject, userId: "user-1" }),
    );
  });
});
