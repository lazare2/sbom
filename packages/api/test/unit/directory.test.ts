import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rootCertificates } from "node:tls";
import { describe, expect, it, vi } from "vitest";
import { directoryConnectionInputSchema, type DirectoryDiagnosis } from "@sbom/shared";
import type { DirectoryConnector } from "../../src/modules/directory/connector.js";
import { DIRECTORY_SETTING_KEY, DirectoryService } from "../../src/modules/directory/directory.service.js";
import {
  escapeFilterValue,
  guidToBytes,
  guidToString,
  isDisabled,
  trustedCertificates,
} from "../../src/modules/directory/ldap-connector.js";

/** Reading squad membership from Active Directory: step 1, the connection. */

describe("LDAP filter safety", () => {
  it("escapes the five characters that change a filter (RFC 4515)", () => {
    expect(escapeFilterValue("a*b(c)d\\e\0")).toBe("a\\2ab\\28c\\29d\\5ce\\00");
    // A group name cannot widen or close the query.
    expect(escapeFilterValue("*)(objectClass=*")).toBe("\\2a\\29\\28objectClass=\\2a");
    expect(escapeFilterValue("Payments Squad")).toBe("Payments Squad");
  });
});

describe("AD objectGUID", () => {
  // Microsoft's own example: {3F2504E0-4F89-11D3-9A0C-0305E82C3301} is stored little-endian in
  // its first three parts.
  const bytes = Buffer.from("E004253F894FD3119A0C0305E82C3301", "hex");

  it("reads the stored bytes as the usual text", () => {
    expect(guidToString(bytes)).toBe("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
  });

  it("writes the text back as the bytes AD stores (searched as bytes, never as filter text)", () => {
    expect(guidToBytes("3F2504E0-4F89-11D3-9A0C-0305E82C3301").equals(bytes)).toBe(true);
    expect(guidToString(guidToBytes("3f2504e0-4f89-11d3-9a0c-0305e82c3301"))).toBe("3f2504e0-4f89-11d3-9a0c-0305e82c3301");
  });

  it("refuses anything that is not an id, rather than searching with it", () => {
    expect(() => guidToBytes("*")).toThrow();
    expect(() => guidToString(Buffer.alloc(4))).toThrow();
  });
});

describe("disabled accounts", () => {
  it("reads AD's userAccountControl", () => {
    expect(isDisabled("514")).toBe(true); // normal account + disabled
    expect(isDisabled("66050")).toBe(true); // + password never expires
    expect(isDisabled("512")).toBe(false);
    expect(isDisabled(null)).toBe(false);
  });
});

describe("trusted certificates", () => {
  it("adds the installation's CA files and a pasted one to the public authorities, nothing else", () => {
    const dir = mkdtempSync(join(tmpdir(), "sbom-ca-"));
    const pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    writeFileSync(join(dir, "corp-root.crt"), pem);
    writeFileSync(join(dir, "README.md"), "Put certificates here.");
    writeFileSync(join(dir, "notes.pem"), "not a certificate");
    const pasted = pem.replace("MIIB", "MIIC");
    const trusted = trustedCertificates(dir, pasted);
    expect(trusted.length).toBe(rootCertificates.length + 2);
    expect(trusted).toContain(pem);
    expect(trusted).toContain(pasted);
  });

  it("works without the folder", () => {
    expect(trustedCertificates(join(tmpdir(), "no-such-folder-sbom"), null).length).toBe(rootCertificates.length);
  });
});

describe("the connection settings", () => {
  it("offer LDAPS only, and Active Directory as the one preset tested", () => {
    const parsed = directoryConnectionInputSchema.parse({
      servers: ["dc1.corp.example", "dc2.corp.example:3269"],
      baseDn: "DC=corp,DC=example",
      bindUser: "svc-sbom@corp.example",
    });
    expect(parsed.port).toBe(636);
    expect(parsed.preset).toBe("active-directory");
    expect(parsed.emailAttribute).toBe("mail");
    expect(directoryConnectionInputSchema.safeParse({ ...parsed, servers: ["ldap://dc1"] }).success).toBe(false);
    expect(directoryConnectionInputSchema.safeParse({ ...parsed, preset: "openldap" }).success).toBe(false);
    expect(directoryConnectionInputSchema.safeParse({ ...parsed, caCertificate: "hello" }).success).toBe(false);
  });
});

/** A setting table of one row, enough for the service. */
function fakeDb() {
  const rows = new Map<string, unknown>();
  const db = {
    rows,
    execute: vi.fn(async () => ({ rows: rows.has(DIRECTORY_SETTING_KEY) ? [{ value: rows.get(DIRECTORY_SETTING_KEY) }] : [] })),
    insert: () => ({
      values: (v: { key: string; value: unknown }) => ({
        onConflictDoUpdate: async () => {
          rows.set(v.key, JSON.parse(JSON.stringify(v.value)));
        },
      }),
    }),
  };
  return db;
}

const KEY = "k".repeat(40);
const actor = { id: "admin-1", email: "admin@sbom.local" };
const input = directoryConnectionInputSchema.parse({
  servers: ["dc1.corp.example"],
  baseDn: "DC=corp,DC=example",
  bindUser: "svc-sbom@corp.example",
  bindPassword: "S3cret-password!",
});

function service(opts: { secretsKey?: string; connector?: DirectoryConnector } = {}) {
  const db = fakeDb();
  const audit = { record: vi.fn(async () => {}) };
  const svc = new DirectoryService({
    db: db as never,
    config: { SECRETS_KEY: opts.secretsKey, GRYPE_DB_CA_DIR: "/certs" } as never,
    audit: audit as never,
    ...(opts.connector ? { connectorFor: () => opts.connector! } : {}),
  });
  return { svc, db, audit };
}

describe("the directory service", () => {
  it("never stores or returns the password in the clear", async () => {
    const { svc, db, audit } = service({ secretsKey: KEY });
    const settings = await svc.save(input, actor);
    expect(JSON.stringify(db.rows.get(DIRECTORY_SETTING_KEY))).not.toContain("S3cret-password!");
    expect(JSON.stringify(settings)).not.toContain("S3cret-password!");
    expect(settings.connection?.passwordConfigured).toBe(true);
    expect(JSON.stringify(audit.record.mock.calls)).not.toContain("S3cret-password!");
  });

  it("keeps the stored password when a save leaves it out", async () => {
    const { svc, db } = service({ secretsKey: KEY });
    await svc.save(input, actor);
    const sealed = (db.rows.get(DIRECTORY_SETTING_KEY) as { passwordEnvelope: string }).passwordEnvelope;
    const { bindPassword: _omit, ...withoutPassword } = input;
    await svc.save({ ...withoutPassword, servers: ["dc2.corp.example"] }, actor);
    expect((db.rows.get(DIRECTORY_SETTING_KEY) as { passwordEnvelope: string }).passwordEnvelope).toBe(sealed);
  });

  it("refuses to store a password without SECRETS_KEY", async () => {
    const { svc } = service({});
    await expect(svc.save(input, actor)).rejects.toThrow(/SECRETS_KEY/);
  });

  it("is off until switched on, and cannot be switched on without a connection", async () => {
    const { svc, audit } = service({ secretsKey: KEY });
    expect(await svc.enabled()).toBe(false);
    await expect(svc.setEnabled(true, actor)).rejects.toThrow(/connection/);
    await svc.save(input, actor);
    await svc.setEnabled(true, actor);
    expect(await svc.enabled()).toBe(true);
    expect(audit.record).toHaveBeenCalledWith(expect.objectContaining({ action: "module.switch", targetId: "directory" }));
  });

  it("keeps the test result, and drops it when the connection changes", async () => {
    const result: DirectoryDiagnosis = {
      ok: true, code: "ok", summary: "Connected", hint: null, detail: null, server: "dc1", sampleGroups: 3, at: new Date().toISOString(),
    };
    const connector = { test: vi.fn(async () => result) } as unknown as DirectoryConnector;
    const { svc } = service({ secretsKey: KEY, connector });
    await svc.save(input, actor);
    expect((await svc.test()).ok).toBe(true);
    expect((await svc.settings()).lastTest?.summary).toBe("Connected");
    await svc.save({ ...input, bindPassword: undefined }, actor);
    expect((await svc.settings()).lastTest).toBeNull();
  });

  it("explains a missing connection or key instead of failing", async () => {
    const { svc } = service({ secretsKey: KEY });
    expect((await svc.test()).code).toBe("not_configured");
    const withKey = service({ secretsKey: KEY });
    await withKey.svc.save(input, actor);
    const withoutKey = service({});
    withoutKey.db.rows.set(DIRECTORY_SETTING_KEY, withKey.db.rows.get(DIRECTORY_SETTING_KEY));
    expect((await withoutKey.svc.test()).code).toBe("secrets_key_missing");
  });
});

describe("linking squads to directory groups", () => {
  const group = { id: "3f2504e0-4f89-11d3-9a0c-0305e82c3301", name: "Squad Payments", dn: "CN=Squad Payments,DC=corp,DC=example", description: null };

  async function links(opts: { enabled?: boolean; squad?: boolean; found?: boolean; insertError?: unknown }) {
    const { DirectoryLinksService } = await import("../../src/modules/directory/links.service.js");
    const audit = { record: vi.fn(async () => {}) };
    const execute = vi.fn(async (query: unknown) => {
      const text = JSON.stringify(query);
      if (text.includes("SELECT name FROM squad WHERE")) return { rows: opts.squad === false ? [] : [{ name: "Payments" }] };
      if (text.includes("INSERT INTO squad_directory_link")) {
        if (opts.insertError) throw opts.insertError;
        return { rows: [] };
      }
      if (text.includes("WHERE l.group_id")) return { rows: [{ name: "Ledger" }] };
      if (text.includes("FROM squad_directory_link l JOIN squad s")) {
        return { rows: [{ squad_id: "s1", squad_name: "Payments", member_count: 0, group_id: group.id, group_name: group.name, group_dn: group.dn, linked_at: new Date() }] };
      }
      return { rows: [] };
    });
    const directory = {
      enabled: async () => opts.enabled !== false,
      connector: async () => ({ group: async () => (opts.found === false ? null : group) }),
    };
    return { svc: new DirectoryLinksService({ db: { execute } as never, audit: audit as never, directory: directory as never }), audit, execute };
  }

  it("links when the module is on and the group exists, and audits it", async () => {
    const { svc, audit } = await links({});
    const link = await svc.link("s1", group.id, actor);
    expect(link.groupName).toBe("Squad Payments");
    expect(audit.record).toHaveBeenCalledWith(expect.objectContaining({ action: "squad.directory_link" }));
  });

  it("refuses while the module is off", async () => {
    const { svc } = await links({ enabled: false });
    await expect(svc.link("s1", group.id, actor)).rejects.toMatchObject({ statusCode: 409, code: "module_disabled" });
  });

  it("refuses a group the directory no longer has", async () => {
    const { svc } = await links({ found: false });
    await expect(svc.link("s1", group.id, actor)).rejects.toMatchObject({ statusCode: 404 });
  });

  it("names the squad that already takes its members from the group", async () => {
    const { svc } = await links({ insertError: { cause: { code: "23505" } } });
    await expect(svc.link("s1", group.id, actor)).rejects.toThrow(/already feeds the squad "Ledger"/);
  });
});
