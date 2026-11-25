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

// ---------------------------------------------------------------------------------------------
// The sync: linked squads' members from their directory groups
// ---------------------------------------------------------------------------------------------

/** A person in a sync plan: a platform account when there is one, else as the directory names them. */
export interface DirectorySyncPerson {
  userId: string | null;
  email: string | null;
  name: string | null;
}

export interface DirectorySyncSquadChange {
  squadId: string;
  squadName: string;
  groupName: string;
  /** Members now, before the change. */
  current: number;
  add: DirectorySyncPerson[];
  remove: DirectorySyncPerson[];
  /** Why this squad is left as it is this time (its group is gone, for instance), or null. */
  skipped: string | null;
}

/** What a sync would do, or did. Nothing in it has happened until the run says "applied". */
export interface DirectorySyncPlan {
  computedAt: string;
  squads: DirectorySyncSquadChange[];
  totals: { add: number; remove: number };
  /** Accounts matched to their directory person for the first time (by email). */
  newlyMatched: number;
  /** Addresses changed in the directory, followed here: the account keeps everything else. */
  emailUpdates: Array<{ userId: string; from: string; to: string }>;
  /** Disabled in the directory: removed from linked squads, and (SSO accounts) deactivated. */
  deactivate: DirectorySyncPerson[];
  /** In a linked group, with no account here yet: they get one, and their squads, at first sign-in. */
  notInPlatform: DirectorySyncPerson[];
  /** In a linked group with no email in the directory, so they cannot be matched to anybody. */
  noEmail: DirectorySyncPerson[];
  /** Refused matches, e.g. an address that now belongs to a different directory person. */
  conflicts: Array<{ email: string; reason: string }>;
  /** Why this plan waits for an administrator, empty when it may run on its own. */
  holdReasons: string[];
}

export const directorySyncStatuses = ["applied", "held", "failed", "nothing_to_do"] as const;
export type DirectorySyncStatus = (typeof directorySyncStatuses)[number];

export interface DirectorySyncRun {
  at: string;
  trigger: "nightly" | "manual" | "approval";
  status: DirectorySyncStatus;
  plan: DirectorySyncPlan | null;
  /** Why it failed; nothing was changed. */
  error: string | null;
}

export const directorySyncSettingsSchema = z.object({
  /** Hour of the nightly sync, in the server's time zone. */
  hour: z.number().int().min(0).max(23).default(3),
  /** A sync removing more people than this, across all squads, waits for approval. */
  maxRemovals: z.number().int().min(0).max(100_000).default(10),
  /** A sync removing more than this share of one squad's members waits for approval. */
  maxSquadSharePct: z.number().int().min(0).max(100).default(25),
});
export type DirectorySyncSettings = z.output<typeof directorySyncSettingsSchema>;

export const directorySyncRequestSchema = z.object({
  /** Apply even though the plan would wait for approval: the administrator has seen it. */
  approve: z.boolean().default(false),
});

export interface DirectorySyncState {
  settings: DirectorySyncSettings;
  /** The server's time zone, which the nightly hour is in. */
  timeZone: string;
  running: boolean;
  lastRun: DirectorySyncRun | null;
  /** When a sync last changed anything; null before the first. */
  lastAppliedAt: string | null;
  /** When the next nightly sync is due, so a screen can show it in the viewer's own time. */
  nextRunAt: string;
}
