import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { directoryConnectionInputSchema } from "@sbom/shared";
import { LdapConnector } from "../../src/modules/directory/ldap-connector.js";

/**
 * The Active Directory connector against a real AD domain controller (Samba 4, scripts/samba-ad):
 * run by scripts/test-directory-ad.ps1, which starts it and sets AD_TEST_SERVER and
 * AD_TEST_CA_FILE. Skipped when they are not set, so `npm test` needs no directory.
 *
 * The test domain corp.example: alice and carol (disabled) in "Squad Payments", bob in "Squad
 * Ledger", dave (no mail) in "Squad (Legacy)", both first squads nested in "Dev Teams", and
 * 1,200 people in "Squad Big".
 */
const server = process.env.AD_TEST_SERVER;
const caFile = process.env.AD_TEST_CA_FILE;

describe.skipIf(!server || !caFile)("Active Directory connector, against a real domain controller", () => {
  let caDir: string;
  const base = () =>
    ({
      ...directoryConnectionInputSchema.parse({
        servers: [server!],
        baseDn: "DC=corp,DC=example",
        bindUser: "svc-sbom@corp.example",
      }),
      bindPassword: "Svc-pass-2026!",
    }) as const;
  const connector = (patch: Record<string, unknown> = {}, dir: string | null = caDir) =>
    new LdapConnector({ ...base(), ...patch } as never, dir);

  beforeAll(() => {
    caDir = mkdtempSync(join(tmpdir(), "sbom-ad-ca-"));
    writeFileSync(join(caDir, "test-ca.crt"), readFileSync(caFile!, "utf8"));
  });

  describe("the connection test names the step that failed", () => {
    it("passes with the right settings", async () => {
      const result = await connector().test();
      expect(result.code, result.detail ?? "").toBe("ok");
      expect(result.sampleGroups).toBeGreaterThan(4);
    });

    it("wrong password", async () => {
      expect((await connector({ bindPassword: "wrong" }).test()).code).toBe("bind_rejected");
    });

    it("wrong base DN", async () => {
      expect((await connector({ baseDn: "DC=nowhere,DC=example" }).test()).code).toBe("base_dn_not_found");
    });

    it("certificate from an authority nobody trusts", async () => {
      const result = await connector({}, null).test();
      expect(result.code).toBe("tls_untrusted");
      expect(result.hint).toMatch(/ca folder/);
    });

    it("the same CA pasted on the screen instead of the folder", async () => {
      expect((await connector({ caCertificate: readFileSync(caFile!, "utf8") }, null).test()).code).toBe("ok");
    });

    it("nothing listening", async () => {
      expect((await connector({ servers: ["localhost:1"] }).test()).code).toBe("unreachable");
    });

    it("tries the next server when the first cannot be reached", async () => {
      const result = await connector({ servers: ["localhost:1", server!] }).test();
      expect(result.code).toBe("ok");
      expect(result.server).toBe(server);
    });
  });

  describe("groups", () => {
    it("finds groups by part of their name", async () => {
      const names = (await connector().findGroups("Squad")).map((g) => g.name);
      expect(names).toEqual(expect.arrayContaining(["Squad Payments", "Squad Ledger", "Squad (Legacy)", "Squad Big"]));
    });

    it("searches for characters that mean something in a filter, and cannot be widened by them", async () => {
      expect((await connector().findGroups("(Legacy)")).map((g) => g.name)).toEqual(["Squad (Legacy)"]);
      expect(await connector().findGroups("*)(cn=*")).toEqual([]);
    });

    it("finds a group again by its permanent id", async () => {
      const [payments] = await connector().findGroups("Squad Payments");
      expect(payments!.id).toMatch(/^[0-9a-f-]{36}$/);
      expect((await connector().group(payments!.id))?.name).toBe("Squad Payments");
      expect(await connector().group("00000000-0000-0000-0000-000000000000")).toBeNull();
    });
  });

  describe("members", () => {
    it("include people in nested groups, with disabled ones marked", async () => {
      const [dev] = await connector().findGroups("Dev Teams");
      const people = await connector().members(dev!.id);
      expect(people.map((p) => p.email).sort()).toEqual(["alice@corp.example", "bob@corp.example", "carol@corp.example"]);
      expect(people.find((p) => p.email === "carol@corp.example")?.enabled).toBe(false);
      expect(people.find((p) => p.email === "alice@corp.example")?.enabled).toBe(true);
    });

    it("of a group past AD's 1,000-entry page are all read", async () => {
      const [big] = await connector().findGroups("Squad Big");
      expect((await connector().members(big!.id)).length).toBe(1200);
    });

    it("without an email address are kept, with no email", async () => {
      const [legacy] = await connector().findGroups("(Legacy)");
      const [dave] = await connector().members(legacy!.id);
      expect(dave?.email).toBeNull();
      expect(dave?.name).toMatch(/Dave/);
    });
  });

  describe("people", () => {
    it("are found by email whatever its case, and their groups include nested ones", async () => {
      const alice = await connector().personByEmail("ALICE@corp.example");
      expect(alice?.email).toBe("alice@corp.example");
      const groups = await connector().groupsOf(alice!.id);
      const [payments] = await connector().findGroups("Squad Payments");
      const [dev] = await connector().findGroups("Dev Teams");
      expect(groups).toEqual(expect.arrayContaining([payments!.id, dev!.id]));
    });

    it("are not guessed: an unknown address finds nobody", async () => {
      expect(await connector().personByEmail("nobody@corp.example")).toBeNull();
    });

    it("can be matched on the sign-in name instead of mail", async () => {
      const bob = await connector({ emailAttribute: "userPrincipalName" }).personByEmail("bob@corp.example");
      expect(bob).not.toBeNull();
    });
  });
});
