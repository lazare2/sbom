import { describe, expect, it, vi } from "vitest";
import { AdminUsersService } from "../../src/modules/admin/users.service.js";
import { BadRequestError, ConflictError } from "../../src/lib/errors.js";
import type { Database } from "../../src/db/client.js";

/**
 * Converting an account between a local password and the directory.
 *
 * The property worth protecting is not that the conversion works — it is that one of the two
 * directions is refused in a specific case. An estate where *every* administrator signs in
 * through the directory has no way into its own admin screens when the directory is
 * unreachable, and that is not hypothetical: it happened during this platform's rollout, and
 * the page that would have explained the outage was behind it.
 *
 * So one active administrator must keep a password. Everything else here guards the two
 * credential edits that make the conversion destructive in each direction — discarding a hash
 * going one way, issuing a password coming back — and the stale directory identity that is
 * easy to leave behind.
 */

const ACTOR = { id: "actor-1", email: "admin@bog.ge" };

type Row = {
  id: string;
  email: string;
  role: string;
  isActive: boolean;
  authProvider: string;
  authSubject: string | null;
  passwordHash: string | null;
  mustChangePassword: boolean;
  applicationAccessRestricted: boolean;
  lastLoginAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

const row = (over: Partial<Row> = {}): Row => ({
  id: "user-1",
  email: "lazare@bog.ge",
  role: "user",
  isActive: true,
  authProvider: "local",
  authSubject: null,
  passwordHash: "argon2-hash",
  mustChangePassword: false,
  applicationAccessRestricted: false,
  lastLoginAt: null,
  createdAt: new Date("2026-10-01T09:00:00Z"),
  updatedAt: new Date("2026-10-01T09:00:00Z"),
  ...over,
});

/**
 * A database deep enough for this one method: the lookup, the counting query behind the
 * guard, and the update whose patch is captured so the credential edits can be asserted.
 */
function harness(target: Row, otherLocalAdmins = 1) {
  let patch: Record<string, unknown> | null = null;

  const db = {
    select: () => ({
      from: () => ({ where: () => ({ limit: async () => [target] }) }),
    }),
    update: () => ({
      set: (p: Record<string, unknown>) => {
        patch = p;
        return {
          where: () => ({
            returning: async () => [{ ...target, ...p }],
          }),
        };
      },
    }),
    // Only the last-local-admin count reaches this.
    execute: async () => ({ rows: [{ count: otherLocalAdmins }] }),
  } as unknown as Database;

  const revokeAllForUser = vi.fn(async () => 3);
  const record = vi.fn(async () => undefined);

  const service = new AdminUsersService({
    db,
    sessions: { revokeAllForUser } as never,
    audit: { record } as never,
    environments: {} as never,
  });

  return { service, revokeAllForUser, record, patchOf: () => patch };
}

describe("switching an account to the directory", () => {
  it("discards the password hash", async () => {
    // A directory account must not also hold a password: it would be a second way in that
    // no policy covers and nobody would ever rotate.
    const h = harness(row());
    await h.service.setSignInMethod("user-1", { method: "directory" }, ACTOR);

    expect(h.patchOf()).toMatchObject({ authProvider: "oidc", passwordHash: null });
  });

  it("hands back no password, because none was made", async () => {
    const h = harness(row());
    const result = await h.service.setSignInMethod("user-1", { method: "directory" }, ACTOR);
    expect(result.temporaryPassword).toBeUndefined();
  });

  it("clears the forced-password-change flag", async () => {
    // The flag refuses every authenticated route until it is cleared, and the only thing that
    // clears it is a password change this account can no longer perform. Left set, it locks
    // the account out while offering a form that cannot help.
    const h = harness(row({ mustChangePassword: true }));
    await h.service.setSignInMethod("user-1", { method: "directory" }, ACTOR);
    expect(h.patchOf()).toMatchObject({ mustChangePassword: false });
  });

  it("ends every session", async () => {
    // The usual reason to convert an account is that its local password should stop working.
    // Leaving live sessions open would defeat precisely that.
    const h = harness(row());
    await h.service.setSignInMethod("user-1", { method: "directory" }, ACTOR);
    expect(h.revokeAllForUser).toHaveBeenCalledWith("user-1");
  });

  it("refuses the last administrator who can sign in with a password", async () => {
    /*
      The break-glass rule. With no local administrator left, an unreachable directory means
      nobody can open the admin screens -- including the Authentication page that reports why
      the directory is unreachable.
    */
    const h = harness(row({ role: "admin" }), 0);
    await expect(
      h.service.setSignInMethod("user-1", { method: "directory" }, ACTOR),
    ).rejects.toThrow(BadRequestError);
  });

  it("allows an administrator while another keeps a password", async () => {
    const h = harness(row({ role: "admin" }), 1);
    await expect(
      h.service.setSignInMethod("user-1", { method: "directory" }, ACTOR),
    ).resolves.toBeTruthy();
  });

  it("does not apply the rule to a non-admin, or to a deactivated admin", async () => {
    // Neither can open the admin screens, so neither is the account that would rescue the
    // estate. Refusing them would be a rule that blocks work without preventing the outage.
    await expect(
      harness(row({ role: "user" }), 0).service.setSignInMethod(
        "user-1",
        { method: "directory" },
        ACTOR,
      ),
    ).resolves.toBeTruthy();
    await expect(
      harness(row({ role: "admin", isActive: false }), 0).service.setSignInMethod(
        "user-1",
        { method: "directory" },
        ACTOR,
      ),
    ).resolves.toBeTruthy();
  });
});

describe("switching an account back to a password", () => {
  const directory = row({ authProvider: "oidc", authSubject: "oid-123", passwordHash: null });

  it("issues a password, because the account would otherwise have no way in", async () => {
    // `auth_provider = 'local'` with no hash is unreachable by every route, and there is no
    // self-service recovery to fall back on.
    const h = harness(directory);
    const result = await h.service.setSignInMethod("user-1", { method: "local" }, ACTOR);

    expect(result.temporaryPassword).toBeTruthy();
    expect(h.patchOf()).toMatchObject({ authProvider: "local", mustChangePassword: true });
  });

  it("stores a hash, never the password itself", async () => {
    const h = harness(directory);
    const result = await h.service.setSignInMethod("user-1", { method: "local" }, ACTOR);
    const hash = (h.patchOf() as { passwordHash: string }).passwordHash;

    expect(hash).toBeTruthy();
    expect(hash).not.toContain(result.temporaryPassword!);
  });

  it("clears the directory identity it is leaving behind", async () => {
    // The easy one to miss. Left in place, the row goes on asserting a directory identity
    // that no longer applies to it, and the next account legitimately created for that
    // person is matched against a stale claim.
    const h = harness(directory);
    await h.service.setSignInMethod("user-1", { method: "local" }, ACTOR);
    expect(h.patchOf()).toMatchObject({ authSubject: null });
  });

  it("is never blocked by the break-glass rule", async () => {
    // The rule protects the ability to sign in without the directory. Moving *towards* a
    // password can only help, and if the directory has just broken this is the way back in.
    const h = harness(row({ authProvider: "oidc", role: "admin", passwordHash: null }), 0);
    await expect(
      h.service.setSignInMethod("user-1", { method: "local" }, ACTOR),
    ).resolves.toBeTruthy();
  });
});

describe("the audit trail", () => {
  it("records the transition and that a password was issued, never the password", async () => {
    const h = harness(row({ authProvider: "oidc", passwordHash: null }));
    const result = await h.service.setSignInMethod("user-1", { method: "local" }, ACTOR);

    expect(h.record).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "user.sign_in_method_set",
        targetType: "user",
        metadata: expect.objectContaining({ from: "oidc", to: "local", passwordIssued: true }),
      }),
    );
    expect(JSON.stringify(h.record.mock.calls)).not.toContain(result.temporaryPassword);
  });
});

describe("asking for the method it already has", () => {
  it("is refused rather than recorded as a change", async () => {
    // A no-op success would put a row in the audit trail saying a conversion happened when
    // none did, and the trail is only worth reading if every row describes a real change.
    await expect(
      harness(row()).service.setSignInMethod("user-1", { method: "local" }, ACTOR),
    ).rejects.toThrow(ConflictError);
    await expect(
      harness(row({ authProvider: "oidc" })).service.setSignInMethod(
        "user-1",
        { method: "directory" },
        ACTOR,
      ),
    ).rejects.toThrow(ConflictError);
  });
});
