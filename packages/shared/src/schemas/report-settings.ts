import { z } from "zod";

/**
 * Delivery settings for the monthly report.
 *
 * These live in the database rather than the environment, which is a deliberate exception to
 * the rule the rest of this platform follows. Executable paths and credentials stay in the
 * environment because changing them should require deployment access; a mail server address
 * is neither. It is an operational detail an administrator is expected to correct without
 * waiting for a redeploy, and getting it wrong fails visibly and harmlessly.
 *
 * There is no password field, and that is not an oversight. The organisation's relay accepts
 * mail from inside the network without authenticating it. If credentials are ever needed they
 * belong in the environment with everything else secret, because a password stored here would
 * be readable by every administrator and written to the audit log the moment someone changed
 * it.
 */

/** How the connection to the relay is protected. */
export const smtpEncryptions = ["none", "starttls", "tls"] as const;
export const smtpEncryptionSchema = z.enum(smtpEncryptions);
export type SmtpEncryption = z.infer<typeof smtpEncryptionSchema>;

export const REPORT_RECIPIENT_LIMIT = 50;
export const REPORT_SEND_HOUR_MIN = 0;
export const REPORT_SEND_HOUR_MAX = 23;

/**
 * A hostname or IP address, and nothing else.
 *
 * Narrow on purpose. This value is handed to a network client, so anything that could carry a
 * scheme, a port, a path or a credential pair has to be rejected here rather than interpreted
 * later — "smtp://user:pass@host:25/" typed into this box should fail loudly rather than
 * silently connect somewhere unintended.
 */
export const smtpHostSchema = z
  .string()
  .trim()
  .min(1, "required")
  .max(255)
  .regex(
    /^[A-Za-z0-9._:-]+$/,
    "must be a hostname or IP address, with no scheme, port, path or credentials",
  );

/**
 * A sender address.
 *
 * Deliberately looser than a full RFC 5322 parser and stricter than "contains an @": these
 * are internal addresses, and a validator that rejects a valid one an administrator has to
 * use is worse than one that accepts an address the relay will reject anyway.
 */
export const emailAddressSchema = z
  .string()
  .trim()
  .min(3)
  .max(320)
  .regex(/^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+$/, "must be an email address");

export interface ReportSettings {
  /** Whether the scheduled monthly report is sent at all. Off until configured. */
  enabled: boolean;
  smtpHost: string;
  smtpPort: number;
  smtpEncryption: SmtpEncryption;
  smtpFrom: string;
  recipients: string[];
  /** IANA zone deciding both the reporting month and the hour the report is sent. */
  timeZone: string;
  /** Local hour on the first working day of the month at which the report is sent. */
  sendHour: number;
  subjectTemplate: string;
  bodyTemplate: string;
}

/**
 * Placeholders an administrator may use in the subject and body.
 *
 * A fixed, documented set rather than a template language. The body is edited by an
 * administrator through a web form and rendered by the server, so anything with control flow
 * or property access would be an injection surface for the sake of a feature nobody asked
 * for. Substitution is literal and unknown placeholders are left untouched, so a typo shows
 * up in the email as itself rather than as an empty space.
 */
export const REPORT_TEMPLATE_PLACEHOLDERS = [
  "{{period}}",
  "{{applications}}",
  "{{findings}}",
  "{{resolved}}",
  "{{introduced}}",
  "{{reintroduced}}",
  "{{critical}}",
  "{{high}}",
  "{{generatedAt}}",
] as const;

export const DEFAULT_REPORT_SUBJECT = "Dependency and vulnerability report — {{period}}";

export const DEFAULT_REPORT_BODY = `Dear all,

Attached is the dependency and vulnerability report for {{period}}.

Summary
  Applications tracked: {{applications}}
  Open findings: {{findings}} ({{critical}} critical, {{high}} high)
  Resolved since the last report: {{resolved}}
  Introduced since the last report: {{introduced}}

The attached PDF attributes each change to a cause, and separates findings in
application dependencies from those inherited from base images.

Generated automatically on {{generatedAt}}.`;

export const updateReportSettingsSchema = z.object({
  enabled: z.coerce.boolean(),
  smtpHost: smtpHostSchema,
  smtpPort: z.coerce.number().int().min(1).max(65535),
  smtpEncryption: smtpEncryptionSchema,
  smtpFrom: emailAddressSchema,
  /*
    Deduplicated and capped. The cap is not about load -- fifty recipients is nothing for a
    relay -- but about a paste of an entire address book turning one misconfiguration into a
    monthly all-staff mailing.
  */
  recipients: z
    .array(emailAddressSchema)
    .max(REPORT_RECIPIENT_LIMIT)
    .transform((list) => [...new Set(list.map((address) => address.toLowerCase()))]),
  timeZone: z
    .string()
    .trim()
    .min(1)
    .max(64)
    .refine((zone) => {
      // Validated against the platform's own zone database rather than a regex, so a
      // plausible-looking but non-existent zone cannot silently shift the reporting month.
      try {
        new Intl.DateTimeFormat("en-US", { timeZone: zone });
        return true;
      } catch {
        return false;
      }
    }, "must be an IANA time zone, such as Asia/Tbilisi"),
  sendHour: z.coerce.number().int().min(REPORT_SEND_HOUR_MIN).max(REPORT_SEND_HOUR_MAX),
  subjectTemplate: z.string().trim().min(1).max(300),
  bodyTemplate: z.string().min(1).max(10_000),
});
export type UpdateReportSettings = z.infer<typeof updateReportSettingsSchema>;

/** Body for the "send a test email" action, which proves the relay works before a month passes. */
export const testReportEmailSchema = z.object({
  recipient: emailAddressSchema,
});
export type TestReportEmail = z.infer<typeof testReportEmailSchema>;
