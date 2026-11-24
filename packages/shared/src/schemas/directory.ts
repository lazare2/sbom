import { z } from "zod";

/**
 * The organisation's directory, read so squad membership can follow it (Active Directory first).
 *
 * Read only, ever: the platform searches groups and people and never writes. Sign-in stays single
 * sign-on; the directory decides which squads a person is in, not whether they may sign in.
 *
 * Connectors are kinds of directory. `ldap` speaks LDAP over TLS; its preset only fills in the
 * attribute names a kind of LDAP server uses, so Active Directory and later OpenLDAP or FreeIPA are one
 * connector. Another protocol (Microsoft Graph for Entra ID) would be another connector, and
 * the code above the connectors does not change.
 */

export const directoryConnectorTypes = ["ldap"] as const;
export type DirectoryConnectorType = (typeof directoryConnectorTypes)[number];

// Only Active Directory so far: OpenLDAP and FreeIPA keep people and groups differently and are
// added once they can be tested against a real server, as AD is against Samba.
export const directoryPresets = ["active-directory"] as const;
export type DirectoryPreset = (typeof directoryPresets)[number];

/** Which attribute holds the address single sign-on reports, so the two can be matched. */
export const directoryEmailAttributes = ["mail", "userPrincipalName"] as const;
export type DirectoryEmailAttribute = (typeof directoryEmailAttributes)[number];

/** A host name or address, optionally with `:port`. No scheme: the connection is always TLS. */
const hostSchema = z
  .string()
  .trim()
  .min(1)
  .max(253)
  .regex(/^[A-Za-z0-9.-]+(:\d{1,5})?$/, "a host name such as dc1.corp.example, optionally with :port");

export const directoryConnectionInputSchema = z.object({
  type: z.enum(directoryConnectorTypes).default("ldap"),
  preset: z.enum(directoryPresets).default("active-directory"),
  /** Domain controllers / LDAP servers, tried in order. */
  servers: z.array(hostSchema).min(1, "at least one server").max(10),
  /** LDAPS. 636 is the standard port; plain LDAP (389) without TLS is not offered. */
  port: z.number().int().min(1).max(65535).default(636),
  /** Where people and groups are searched, e.g. DC=corp,DC=example. */
  baseDn: z.string().trim().min(3, "required, e.g. DC=corp,DC=example").max(500),
  /** The read-only service account: a user principal name, DOMAIN\name, or a DN. */
  bindUser: z.string().trim().min(1, "required").max(500),
  /** Omitted to keep the stored one. Sealed with SECRETS_KEY; never returned. */
  bindPassword: z.string().min(1).max(1000).optional(),
  emailAttribute: z.enum(directoryEmailAttributes).default("mail"),
  /**
   * An extra CA certificate (PEM) to trust for the servers' TLS certificates. Optional: the
   * certificates in the installation's ca/ folder (mounted at /certs) are trusted already.
   */
  caCertificate: z
    .string()
    .trim()
    .max(20_000)
    .refine((v) => v === "" || v.includes("-----BEGIN CERTIFICATE-----"), "a PEM certificate")
    .optional(),
});
export type DirectoryConnectionInput = z.input<typeof directoryConnectionInputSchema>;
export type DirectoryConnection = z.output<typeof directoryConnectionInputSchema>;

export const directoryGroupSearchSchema = z.object({
  q: z.string().trim().min(2, "at least two characters").max(100),
});

/** The step a connection test stopped at - each needs a different fix. */
export const directoryDiagnosisCodes = [
  "ok",
  "not_configured",
  "secrets_key_missing",
  "unreachable",
  "tls_untrusted",
  "tls_failed",
  "bind_rejected",
  "base_dn_not_found",
  "search_failed",
] as const;
export type DirectoryDiagnosisCode = (typeof directoryDiagnosisCodes)[number];

export interface DirectoryDiagnosis {
  ok: boolean;
  code: DirectoryDiagnosisCode;
  /** One sentence for the screen. */
  summary: string;
  /** What to do about it, or null. */
  hint: string | null;
  /** The server's own words, when there are any. */
  detail: string | null;
  /** The server that answered (or the last one tried). */
  server: string | null;
  /** How many groups a sample search found, once the search was reached. */
  sampleGroups: number | null;
  at: string;
}

/** What the admin screen reads back. Never the password, only whether one is stored. */
export interface DirectorySettings {
  enabled: boolean;
  connection: (Omit<DirectoryConnection, "bindPassword"> & { passwordConfigured: boolean }) | null;
  lastTest: DirectoryDiagnosis | null;
}

/** A group as the directory names it. `id` is permanent (AD: objectGUID); the name may change. */
export interface DirectoryGroup {
  id: string;
  name: string;
  dn: string;
  description: string | null;
}

/** A person as the directory knows them. */
export interface DirectoryPerson {
  id: string;
  email: string | null;
  name: string | null;
  enabled: boolean;
}
