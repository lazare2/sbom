import { sql } from "drizzle-orm";
import type { DirectoryConnection, DirectoryDiagnosis, DirectoryGroup, DirectorySettings } from "@sbom/shared";
import type { Config } from "../../config.js";
import type { Database } from "../../db/client.js";
import { setting } from "../../db/schema.js";
import { BadRequestError } from "../../lib/errors.js";
import { openSecret, sealSecret } from "../../lib/secret-box.js";
import type { Actor, AuditService } from "../admin/audit.service.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import { DirectoryError, type DirectoryConnector } from "./connector.js";
import { LdapConnector } from "./ldap-connector.js";

/** One setting row: the switch, the connection, its sealed password and the last test. */
export const DIRECTORY_SETTING_KEY = "directory.connection";

type StoredConnection = Omit<DirectoryConnection, "bindPassword">;
interface Stored {
  enabled: boolean;
  connection: StoredConnection | null;
  /** The service account's password, sealed with SECRETS_KEY. Never returned in any form. */
  passwordEnvelope: string | null;
  lastTest: DirectoryDiagnosis | null;
}
const EMPTY: Stored = { enabled: false, connection: null, passwordEnvelope: null, lastTest: null };

/**
 * The directory connection: stored, read back without its password, tested, and turned into a
 * connector for the rest of the platform.
 *
 * Off on a fresh install, like any feature that reaches another system. Saving a connection
 * does not switch it on: it can be set up and tested before anything acts on it.
 */
export class DirectoryService {
  constructor(
    private readonly deps: {
      db: Database;
      config: Config;
      audit: AuditService;
      /** Builds the connector; replaced in tests. */
      connectorFor?: (conn: DirectoryConnection & { bindPassword: string }) => DirectoryConnector;
    },
  ) {}

  private async read(): Promise<Stored> {
    const rows = await this.deps.db.execute<Row<{ value: unknown }>>(sql`
      SELECT value FROM setting WHERE key = ${DIRECTORY_SETTING_KEY}
    `);
    const raw = rowsOf(rows)[0]?.value;
    if (!raw || typeof raw !== "object") return { ...EMPTY };
    const v = raw as Partial<Stored>;
    return {
      enabled: v.enabled === true,
      connection: v.connection && typeof v.connection === "object" ? (v.connection as StoredConnection) : null,
      passwordEnvelope: typeof v.passwordEnvelope === "string" ? v.passwordEnvelope : null,
      lastTest: v.lastTest && typeof v.lastTest === "object" ? (v.lastTest as DirectoryDiagnosis) : null,
    };
  }

  private async write(next: Stored): Promise<void> {
    await this.deps.db
      .insert(setting)
      .values({ key: DIRECTORY_SETTING_KEY, value: next })
      .onConflictDoUpdate({ target: setting.key, set: { value: next, updatedAt: new Date() } });
  }

  async enabled(): Promise<boolean> {
    return (await this.read()).enabled;
  }

  /** What the admin screen reads. Never the password, only whether one is stored. */
  async settings(): Promise<DirectorySettings> {
    const s = await this.read();
    return {
      enabled: s.enabled,
      connection: s.connection ? { ...s.connection, passwordConfigured: s.passwordEnvelope !== null } : null,
      lastTest: s.lastTest,
    };
  }

  /**
   * Saves the connection. An omitted password keeps the stored one, so a typo in a server name
   * can be fixed without re-entering a credential. Any change clears the last test: its result
   * described the connection as it was.
   */
  async save(input: DirectoryConnection, actor: Actor): Promise<DirectorySettings> {
    const current = await this.read();
    let envelope = current.passwordEnvelope;
    if (input.bindPassword !== undefined && input.bindPassword !== "") {
      const key = this.deps.config.SECRETS_KEY;
      if (!key) {
        throw new BadRequestError(
          "SECRETS_KEY is not set on this installation, so the password cannot be stored. Add it to .env and restart, then save again.",
        );
      }
      envelope = sealSecret(input.bindPassword, key);
    }
    const { bindPassword, ...connection } = input;
    if (connection.caCertificate === "") delete connection.caCertificate;
    await this.write({ ...current, connection, passwordEnvelope: envelope, lastTest: null });
    await this.deps.audit.record({
      actor,
      action: "directory.connection_update",
      targetType: "setting",
      targetId: DIRECTORY_SETTING_KEY,
      metadata: {
        servers: connection.servers,
        baseDn: connection.baseDn,
        bindUser: connection.bindUser,
        passwordChanged: bindPassword !== undefined && bindPassword !== "",
      },
    });
    return this.settings();
  }

  async setEnabled(enabled: boolean, actor: Actor | null): Promise<void> {
    const current = await this.read();
    if (current.enabled === enabled) return;
    if (enabled && !current.connection) {
      throw new BadRequestError("Set up and save the directory connection first (Administration > Directory).");
    }
    await this.write({ ...current, enabled });
    await this.deps.audit.record({
      actor,
      action: "module.switch",
      targetType: "module",
      targetId: "directory",
      metadata: { enabled: { from: current.enabled, to: enabled } },
    });
  }

  /** A connector for the stored connection; a DirectoryError when it cannot be used. */
  async connector(): Promise<DirectoryConnector> {
    const s = await this.read();
    if (!s.connection || !s.passwordEnvelope) {
      throw new DirectoryError("not_configured", "No directory connection is set up.");
    }
    const key = this.deps.config.SECRETS_KEY;
    if (!key) throw new DirectoryError("secrets_key_missing", "SECRETS_KEY is not set, so the stored password cannot be read.");
    let bindPassword: string;
    try {
      bindPassword = openSecret(s.passwordEnvelope, key);
    } catch {
      throw new DirectoryError(
        "secrets_key_missing",
        "The stored password cannot be read (SECRETS_KEY changed since it was saved). Enter the password again.",
      );
    }
    const conn = { ...s.connection, bindPassword } as DirectoryConnection & { bindPassword: string };
    return this.deps.connectorFor
      ? this.deps.connectorFor(conn)
      : new LdapConnector(conn, this.deps.config.GRYPE_DB_CA_DIR || null);
  }

  /** Runs the connection test and records its result for the screen. */
  async test(): Promise<DirectoryDiagnosis> {
    let result: DirectoryDiagnosis;
    try {
      result = await (await this.connector()).test();
    } catch (error) {
      const e = error instanceof DirectoryError ? error : new DirectoryError("search_failed", String(error));
      result = {
        ok: false,
        code: e.code,
        summary: e.message,
        hint: e.code === "not_configured" ? "Fill in the connection and save it first." : null,
        detail: e.detail,
        server: null,
        sampleGroups: null,
        at: new Date().toISOString(),
      };
    }
    const current = await this.read();
    await this.write({ ...current, lastTest: result });
    return result;
  }

  async findGroups(query: string): Promise<DirectoryGroup[]> {
    return (await this.connector()).findGroups(query);
  }
}
