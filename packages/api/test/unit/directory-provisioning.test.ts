import { describe, expect, it, vi } from "vitest";
import { emailDomainAllowed } from "@sbom/shared";
import { AuthService } from "../../src/modules/auth/auth.service.js";
import { combineAccess } from "../../src/modules/access/application-access.service.js";
import type { Database } from "../../src/db/client.js";
import type { VerifiedIdentity } from "../../src/services/auth/id-token.js";

/**
 * Accounts created on first sign-in, and the squads that give them something to see.
 *
 * The property that makes provisioning safe is not that it creates an account -- it is *what*
 * account. Somebody the directory vouches for gets in and reaches nothing: restricted, no
 * grants, no environments. The tests below pin that shape, the refusals that still go to the
 * administrators' queue, and the rule that a squad adds to an account's reach without widening
 * it into estates it was never given.
 */

const IDENTITY: VerifiedIdentity = {
  subject: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  email: "nino.beridze@bog.ge",
  name: "Nino Beridze",
  givenName: "Nino",
  familyName: "Beridze",
};

/**
 * A database deep enough for the sign-in path: lookups answered from a queue, an insert whose
 * values are captured, and updates that do nothing.
 */
function harness(opts: {
  lookups: unknown[][];
  insertReturns?: unknown[];
  provisioning?: { enabled: boolean; allowedEmailDomains: string[] } | null;
}) {
  const queue = [...opts.lookups];
  let inserted: Record<string, unknown> | null = null;
  const db = {
    select: () => ({
      from: () => ({ where: () => ({ limit: async () => queue.shift() ?? [] }) }),
    }),
    insert: () => ({
      values: (values: Record<string, unknown>) => {
        inserted = values;
        return {
          onConflictDoNothing: () => ({
            returning: async () => opts.insertReturns ?? [{ id: "new-user", ...values, isActive: true }],
          }),
        };
      },
    }),
    update: () => ({ set: () => ({ where: async () => [], returning: async () => [] }) }),
  } as unknown as Database;

  const record = vi.fn(async () => true);
  const resolveOnSignIn = vi.fn(async () => undefined);
  const auditRecord = vi.fn(async () => undefined);

  const service = new AuthService({
    db,
    config: {} as never,
    providers: {} as never,
    sessions: {
      create: async () => ({ token: "t", expiresAt: new Date("2026-11-01T00:00:00Z") }),
    } as never,
    accessRequests: { record, resolveOnSignIn } as never,
    logger: { warn: vi.fn(), error: vi.fn() },
    audit: { record: auditRecord },
    ...(opts.provisioning === null
      ? {}
      : {
          provisioning: async () =>
            opts.provisioning ?? { enabled: true, allowedEmailDomains: [] },
        }),
  });

  return { service, record, auditRecord, inserted: () => inserted };
}

describe("an identity with no account, when provisioning is on", () => {
  it("creates an account that can sign in and reaches nothing", async () => {
    // No account by subject, none by address.
    const h = harness({ lookups: [[], []] });
    const outcome = await h.service.signInWithDirectory(IDENTITY, {});

    expect(outcome.ok).toBe(true);
    expect(h.inserted()).toMatchObject({
      email: "nino.beridze@bog.ge",
      role: "user",
      authProvider: "oidc",
      authSubject: IDENTITY.subject,
      passwordHash: null,
      // The line that makes this safe: unrestricted would be the whole of every estate.
      applicationAccessRestricted: true,
      firstName: "Nino",
      lastName: "Beridze",
    });
    // Created, so not queued as a refusal.
    expect(h.record).not.toHaveBeenCalled();
  });

  it("records who let them in, with nobody as the actor", async () => {
    const h = harness({ lookups: [[], []] });
    await h.service.signInWithDirectory(IDENTITY, {});
    expect(h.auditRecord).toHaveBeenCalledWith(
      expect.objectContaining({ actor: null, action: "user.provision" }),
    );
  });

  it("queues an address outside the allowed domains instead of creating it", async () => {
    const h = harness({
      lookups: [[], []],
      provisioning: { enabled: true, allowedEmailDomains: ["tbcbank.ge"] },
    });
    const outcome = await h.service.signInWithDirectory(IDENTITY, {});

    expect(outcome).toMatchObject({ ok: false, reason: "no_account", requested: true });
    expect(h.inserted()).toBeNull();
  });

  it("queues an identity with no address, because the address is the identifier", async () => {
    const h = harness({ lookups: [[]] });
    const outcome = await h.service.signInWithDirectory({ ...IDENTITY, email: null }, {});
    expect(outcome).toMatchObject({ ok: false, reason: "no_account" });
    expect(h.inserted()).toBeNull();
  });

  it("refuses rather than takes over a password account holding the same address", async () => {
    // The insert conflicts on the address and the re-read by subject finds nobody.
    const h = harness({ lookups: [[], [], []], insertReturns: [] });
    const outcome = await h.service.signInWithDirectory(IDENTITY, {});
    expect(outcome).toMatchObject({ ok: false, reason: "local_account" });
  });

  it("signs in to the row a concurrent first sign-in created", async () => {
    const theirs = { id: "won-the-race", isActive: true, authSubject: IDENTITY.subject };
    const h = harness({ lookups: [[], [], [theirs]], insertReturns: [] });
    const outcome = await h.service.signInWithDirectory(IDENTITY, {});
    expect(outcome).toMatchObject({ ok: true, user: { id: "won-the-race" } });
  });
});

describe("an identity with no account, when provisioning is off", () => {
  it("queues the refusal exactly as before", async () => {
    const h = harness({ lookups: [[], []], provisioning: { enabled: false, allowedEmailDomains: [] } });
    const outcome = await h.service.signInWithDirectory(IDENTITY, {});
    expect(outcome).toMatchObject({ ok: false, reason: "no_account", requested: true });
    expect(h.inserted()).toBeNull();
  });

  it("treats a service wired without the setting as off", async () => {
    const h = harness({ lookups: [[], []], provisioning: null });
    const outcome = await h.service.signInWithDirectory(IDENTITY, {});
    expect(outcome).toMatchObject({ ok: false, reason: "no_account" });
  });
});

describe("which domains may have an account made for them", () => {
  it("allows everything when no domain is listed", () => {
    expect(emailDomainAllowed("a@anything.example", [])).toBe(true);
  });

  it("matches the domain and its subdomains, never a lookalike suffix", () => {
    expect(emailDomainAllowed("a@bog.ge", ["bog.ge"])).toBe(true);
    expect(emailDomainAllowed("a@corp.bog.ge", ["bog.ge"])).toBe(true);
    expect(emailDomainAllowed("a@notbog.ge", ["bog.ge"])).toBe(false);
  });
});

describe("what a squad adds to an account", () => {
  const NO_SQUAD = { groupIds: [], applicationIds: [] };
  const SQUAD = { groupIds: ["payments-group"], applicationIds: ["ledger-app"] };

  it("leaves an unrestricted account on no squad exactly as it was", () => {
    expect(
      combineAccess({
        restricted: false,
        ownEnvironmentIds: ["test"],
        ownGroupIds: [],
        ownApplicationIds: [],
        squad: NO_SQUAD,
      }),
    ).toMatchObject({ unrestricted: true });
  });

  it("keeps an unrestricted account's own estates whole and adds only the squad's applications", () => {
    /*
      The case that needs the new field. An account that sees everything in test, put on a
      squad owning one production service, must see that service -- not the whole of
      production, which is what simply adding production to its estates would mean.
    */
    expect(
      combineAccess({
        restricted: false,
        ownEnvironmentIds: ["test"],
        ownGroupIds: ["ignored-while-unrestricted"],
        ownApplicationIds: [],
        squad: SQUAD,
      }),
    ).toEqual({
      unrestricted: false,
      wholeEnvironmentIds: ["test"],
      groupIds: ["payments-group"],
      applicationIds: ["ledger-app"],
    });
  });

  it("unions a restricted account's own grants with the squad's", () => {
    expect(
      combineAccess({
        restricted: true,
        ownEnvironmentIds: ["prod"],
        ownGroupIds: ["mine"],
        ownApplicationIds: ["ledger-app"],
        squad: SQUAD,
      }),
    ).toEqual({
      unrestricted: false,
      wholeEnvironmentIds: [],
      groupIds: ["mine", "payments-group"],
      // Granted twice is granted once.
      applicationIds: ["ledger-app"],
    });
  });

  it("gives a freshly provisioned account on a squad exactly the squad's reach", () => {
    expect(
      combineAccess({
        restricted: true,
        ownEnvironmentIds: [],
        ownGroupIds: [],
        ownApplicationIds: [],
        squad: SQUAD,
      }),
    ).toEqual({
      unrestricted: false,
      wholeEnvironmentIds: [],
      groupIds: ["payments-group"],
      applicationIds: ["ledger-app"],
    });
  });
});
