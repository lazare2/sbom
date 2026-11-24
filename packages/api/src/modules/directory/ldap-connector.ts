import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { rootCertificates } from "node:tls";
import { AndFilter, Client, EqualityFilter, FilterParser, InvalidCredentialsError, NoSuchObjectError, type Entry, type Filter } from "ldapts";
import type { DirectoryConnection, DirectoryDiagnosis, DirectoryGroup, DirectoryPerson } from "@sbom/shared";
import { DirectoryError, type DirectoryConnector } from "./connector.js";

/**
 * Active Directory over LDAPS.
 *
 * - TLS always (ldaps://, port 636 by default). A service-account password never crosses the
 *   network in the clear, so plain LDAP on 389 is not offered at all.
 * - Trusts the usual public authorities, the installation's own CA certificates (ca/, mounted
 *   at /certs - where the organisation's root goes for a TLS-inspecting proxy too), and an
 *   optional certificate pasted on the screen. Never "accept any certificate".
 * - objectGUID is the permanent id of people and groups: names and even DNs change on a rename
 *   or a move between OUs, the GUID does not.
 * - Nested groups in one query each way, with AD's in-chain matching rule
 *   (1.2.840.113556.1.4.1941), instead of walking the tree from the client.
 * - Paged results, so a group past AD's 1,000-entry page limit is read whole.
 * - Every value placed in a filter is escaped (RFC 4515), so a group or address can never
 *   change the shape of the query.
 */

const TIMEOUT_MS = 10_000;
const PAGE_SIZE = 500;
const IN_CHAIN = "1.2.840.113556.1.4.1941";
/** userAccountControl bit for a disabled account. */
const ACCOUNTDISABLE = 0x2;
const PERSON = "(objectCategory=person)(objectClass=user)";
const GROUP = "(objectClass=group)";

/** RFC 4515: the five characters that would change a filter's meaning. */
export function escapeFilterValue(value: string): string {
  return value.replace(/[\\*()\0]/g, (c) => "\\" + c.charCodeAt(0).toString(16).padStart(2, "0"));
}

/**
 * AD's objectGUID bytes as the usual text form. The first three parts are stored little-endian,
 * which is why the text and the byte order differ ({b0b1b2b3...} -> b3b2b1b0-...).
 */
export function guidToString(bytes: Buffer): string {
  if (bytes.length !== 16) throw new Error(`an objectGUID has 16 bytes, not ${bytes.length}`);
  const h = (i: number) => bytes[i]!.toString(16).padStart(2, "0");
  return (
    h(3) + h(2) + h(1) + h(0) + "-" + h(5) + h(4) + "-" + h(7) + h(6) + "-" + h(8) + h(9) + "-" +
    h(10) + h(11) + h(12) + h(13) + h(14) + h(15)
  );
}

/**
 * The text form back as the bytes AD stores, in its byte order. Searched as bytes, in a filter
 * object: written into filter text, bytes above 0x7f would be re-encoded as UTF-8 and match nothing.
 */
export function guidToBytes(guid: string): Buffer {
  const hex = guid.replace(/-/g, "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new DirectoryError("search_failed", "Not a directory id.", guid);
  const b = (i: number) => hex.slice(i * 2, i * 2 + 2);
  return Buffer.from([3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15].map(b).join(""), "hex");
}

/** `classes` (filter text) and objectGUID equal to `guid`. */
function byGuid(classes: string, guid: string): Filter {
  return new AndFilter({
    filters: [FilterParser.parseString(`(&${classes})`), new EqualityFilter({ attribute: "objectGUID", value: guidToBytes(guid) })],
  });
}

/** Whether a userAccountControl value marks the account disabled. */
export function isDisabled(userAccountControl: string | null): boolean {
  if (!userAccountControl) return false;
  const n = Number.parseInt(userAccountControl, 10);
  return Number.isFinite(n) && (n & ACCOUNTDISABLE) !== 0;
}

/** CA certificates trusted besides the public ones: every PEM file in `dir`, plus `extra`. */
export function trustedCertificates(dir: string | null, extra: string | null | undefined): string[] {
  const found: string[] = [];
  if (dir) {
    try {
      for (const name of readdirSync(dir)) {
        if (!/\.(pem|crt|cer)$/i.test(name)) continue;
        const text = readFileSync(join(dir, name), "utf8");
        if (text.includes("-----BEGIN CERTIFICATE-----")) found.push(text);
      }
    } catch {
      // No folder: only the public authorities and the pasted certificate.
    }
  }
  if (extra && extra.trim() !== "") found.push(extra);
  return [...rootCertificates, ...found];
}

function text(entry: Entry, attribute: string): string | null {
  const v = entry[attribute];
  if (v === undefined) return null;
  const first = Array.isArray(v) ? v[0] : v;
  if (first === undefined) return null;
  return Buffer.isBuffer(first) ? first.toString("utf8") : String(first);
}

function guidOf(entry: Entry): string | null {
  const v = entry.objectGUID;
  const first = Array.isArray(v) ? v[0] : v;
  return Buffer.isBuffer(first) && first.length === 16 ? guidToString(first) : null;
}

/** A failure explained: which step, what to do. */
function explain(error: unknown): DirectoryError {
  if (error instanceof DirectoryError) return error;
  const e = error as { code?: unknown; message?: string };
  const message = e?.message ?? String(error);
  const code = typeof e?.code === "string" ? e.code : "";
  if (error instanceof InvalidCredentialsError) {
    return new DirectoryError("bind_rejected", "The directory refused the service account's user name or password.", message);
  }
  if (error instanceof NoSuchObjectError) {
    return new DirectoryError("base_dn_not_found", "The base DN does not exist in this directory.", message);
  }
  if (/CERT|SELF_SIGNED|UNABLE_TO_(GET|VERIFY)/.test(code)) {
    return new DirectoryError("tls_untrusted", "The server's certificate is not trusted.", `${code}: ${message}`);
  }
  if (code === "ERR_TLS_CERT_ALTNAME_INVALID") {
    return new DirectoryError("tls_untrusted", "The server's certificate is for a different name.", message);
  }
  if (["ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "ETIMEDOUT", "EHOSTUNREACH", "ENETUNREACH", "ECONNRESET"].includes(code) || /timeout/i.test(message)) {
    return new DirectoryError("unreachable", "The server could not be reached.", code ? `${code}: ${message}` : message);
  }
  if (/tls|ssl|handshake/i.test(message)) {
    return new DirectoryError("tls_failed", "The secure connection could not be set up.", message);
  }
  return new DirectoryError("search_failed", "The directory answered with an error.", message);
}

const HINTS: Record<DirectoryDiagnosis["code"], string | null> = {
  ok: null,
  not_configured: "Fill in the connection and save it first.",
  secrets_key_missing: "SECRETS_KEY is not set on this installation, so the password cannot be stored or read.",
  unreachable:
    "Check the server name and port (LDAPS is 636), and that the firewall lets this installation reach it. On Windows Server the request comes from the platform's virtual machine.",
  tls_untrusted:
    "Put your organisation's root CA certificate in the installation's ca folder (or paste it here), and use the name the certificate was issued for.",
  tls_failed: "The server may not offer LDAPS on this port. Ask for LDAPS (636) to be enabled on the domain controllers.",
  bind_rejected:
    "Check the account (user@domain, DOMAIN\\name or its DN) and the password. An expired or locked password is refused the same way.",
  base_dn_not_found: "Use your domain's base, e.g. DC=corp,DC=example.",
  search_failed: "The account may lack read rights there. A normal domain account can read users and groups.",
};

export class LdapConnector implements DirectoryConnector {
  constructor(
    private readonly conn: DirectoryConnection & { bindPassword: string },
    private readonly caDir: string | null,
  ) {}

  /** Signs in on the first server that answers and runs `work`; always unbinds. */
  private async session<T>(work: (client: Client, server: string) => Promise<T>): Promise<T> {
    const ca = trustedCertificates(this.caDir, this.conn.caCertificate);
    let last: DirectoryError | null = null;
    for (const entry of this.conn.servers) {
      const [host, port] = entry.includes(":") ? entry.split(":") : [entry, String(this.conn.port)];
      const client = new Client({
        url: `ldaps://${host}:${port}`,
        timeout: TIMEOUT_MS,
        connectTimeout: TIMEOUT_MS,
        tlsOptions: { ca, servername: host, minVersion: "TLSv1.2" },
        strictDN: false,
      });
      try {
        await client.bind(this.conn.bindUser, this.conn.bindPassword);
        return await work(client, entry);
      } catch (error) {
        last = explain(error);
        // Another server can help only when this one could not be reached or not secured;
        // a wrong password or base is wrong everywhere.
        if (!["unreachable", "tls_failed", "tls_untrusted"].includes(last.code)) throw last;
      } finally {
        await client.unbind().catch(() => undefined);
      }
    }
    throw last ?? new DirectoryError("not_configured", "No server is configured.");
  }

  private async search(client: Client, filter: string | Filter, attributes: string[], sizeLimit = 0): Promise<Entry[]> {
    const { searchEntries } = await client.search(this.conn.baseDn, {
      scope: "sub",
      filter,
      attributes,
      explicitBufferAttributes: ["objectGUID"],
      paged: sizeLimit > 0 && sizeLimit < PAGE_SIZE ? false : { pageSize: PAGE_SIZE },
      ...(sizeLimit > 0 ? { sizeLimit } : {}),
    });
    return searchEntries;
  }

  private toGroup(entry: Entry): DirectoryGroup | null {
    const id = guidOf(entry);
    if (!id) return null;
    return { id, name: text(entry, "cn") ?? entry.dn, dn: entry.dn, description: text(entry, "description") };
  }

  private toPerson(entry: Entry): DirectoryPerson | null {
    const id = guidOf(entry);
    if (!id) return null;
    const email = text(entry, this.conn.emailAttribute);
    return {
      id,
      email: email ? email.trim().toLowerCase() : null,
      name: text(entry, "displayName") ?? text(entry, "cn"),
      enabled: !isDisabled(text(entry, "userAccountControl")),
    };
  }

  private readonly personAttributes = () => ["objectGUID", "displayName", "cn", "userAccountControl", this.conn.emailAttribute];
  private readonly groupAttributes = ["objectGUID", "cn", "description"];

  async test(): Promise<DirectoryDiagnosis> {
    const at = new Date().toISOString();
    let server: string | null = this.conn.servers[0] ?? null;
    try {
      const sample = await this.session(async (client, answered) => {
        server = answered;
        // The base itself must exist: a typo there would otherwise read as "no groups found".
        await client.search(this.conn.baseDn, { scope: "base", filter: "(objectClass=*)", attributes: ["1.1"] });
        return (await this.search(client, GROUP, ["objectGUID"], 50)).length;
      });
      return {
        ok: true,
        code: "ok",
        summary: `Connected to ${server}, signed in, and found ${sample}${sample === 50 ? "+" : ""} group(s).`,
        hint: sample === 0 ? "No groups under this base DN: check that it is the domain's base." : null,
        detail: null,
        server,
        sampleGroups: sample,
        at,
      };
    } catch (error) {
      const e = explain(error);
      return { ok: false, code: e.code, summary: e.message, hint: HINTS[e.code], detail: e.detail, server, sampleGroups: null, at };
    }
  }

  async findGroups(query: string, limit = 25): Promise<DirectoryGroup[]> {
    const q = escapeFilterValue(query.trim());
    const filter = `(&${GROUP}(|(cn=*${q}*)(description=*${q}*)))`;
    return this.session(async (client) =>
      (await this.search(client, filter, this.groupAttributes, limit))
        .map((e) => this.toGroup(e))
        .filter((g): g is DirectoryGroup => g !== null)
        .sort((a, b) => a.name.localeCompare(b.name)),
    ).catch((error) => {
      throw explain(error);
    });
  }

  async group(id: string): Promise<DirectoryGroup | null> {
    const filter = byGuid(GROUP, id);
    return this.session(async (client) => {
      const [entry] = await this.search(client, filter, this.groupAttributes, 1);
      return entry ? this.toGroup(entry) : null;
    }).catch((error) => {
      throw explain(error);
    });
  }

  async members(groupId: string): Promise<DirectoryPerson[]> {
    return this.session(async (client) => {
      const [group] = await this.search(client, byGuid(GROUP, groupId), ["objectGUID"], 1);
      if (!group) throw new DirectoryError("search_failed", "The group no longer exists in the directory.", groupId);
      const filter = `(&${PERSON}(memberOf:${IN_CHAIN}:=${escapeFilterValue(group.dn)}))`;
      return (await this.search(client, filter, this.personAttributes()))
        .map((e) => this.toPerson(e))
        .filter((p): p is DirectoryPerson => p !== null);
    }).catch((error) => {
      throw explain(error);
    });
  }

  async personByEmail(email: string): Promise<DirectoryPerson | null> {
    const filter = `(&${PERSON}(${this.conn.emailAttribute}=${escapeFilterValue(email.trim())}))`;
    return this.session(async (client) => {
      const found = await this.search(client, filter, this.personAttributes(), 2);
      // Two people with one address is a directory problem; matching either would be a guess.
      if (found.length !== 1) return null;
      return this.toPerson(found[0]!);
    }).catch((error) => {
      throw explain(error);
    });
  }

  async groupsOf(personId: string): Promise<string[]> {
    return this.session(async (client) => {
      const [person] = await this.search(client, byGuid(PERSON, personId), ["objectGUID"], 1);
      if (!person) return [];
      const filter = `(&${GROUP}(member:${IN_CHAIN}:=${escapeFilterValue(person.dn)}))`;
      return (await this.search(client, filter, ["objectGUID"]))
        .map((e) => guidOf(e))
        .filter((g): g is string => g !== null);
    }).catch((error) => {
      throw explain(error);
    });
  }
}
