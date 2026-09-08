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
 * Narrow on purpose. This value is handed to a network client, so anything carrying a scheme,
 * a port, a path or a credential pair has to be rejected here rather than interpreted later —
 * "smtp://user:pass@host:25/" typed into this box should fail loudly rather than silently
 * connect somewhere unintended.
 *
 * ## Why each mistake gets its own message
 *
 * The first version was one regex with one message: "must be a hostname or IP address, with
 * no scheme, port, path or credentials". It is accurate and it is useless — it lists four
 * possible mistakes and leaves the reader to work out which one they made, in a field where
 * pasting a connection string is the single most likely thing to do. Each case is now
 * recognised and answered with the specific correction.
 *
 * ## And why `host:port` is now refused
 *
 * That regex allowed a colon, for IPv6 literals. The side effect was that `smtp.corp:25`
 * passed validation, was stored, and was handed to the resolver as a host literally named
 * "smtp.corp:25" — which fails at send time as ENOTFOUND, weeks later, pointing at DNS
 * rather than at the typo. An IPv6 literal is still accepted, in the bracketed form the URL
 * syntax uses for exactly this reason.
 */
const IPV6_LITERAL = /^\[[0-9A-Fa-f:.]+\]$/;
const HOSTNAME_OR_IPV4 = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;

export const smtpHostSchema = z
  .string()
  .trim()
  .max(255)
  .superRefine((value, ctx) => {
    if (value === "") return;

    const fail = (message: string) =>
      ctx.addIssue({ code: z.ZodIssueCode.custom, message });

    if (/:\/\//.test(value)) {
      fail(`Enter the host name on its own — drop the "${value.split("://")[0]}://" prefix.`);
      return;
    }
    if (value.includes("@")) {
      fail(
        "Enter the host name on its own. This platform does not send credentials to the relay, so a user name here would be ignored.",
      );
      return;
    }
    if (value.includes("/")) {
      fail("Enter the host name on its own, with no path.");
      return;
    }

    const withPort = /^(.+):(\d{1,5})$/.exec(value);
    if (withPort && !IPV6_LITERAL.test(value)) {
      fail(`Put the port in the Port field. The host is "${withPort[1]}".`);
      return;
    }

    if (IPV6_LITERAL.test(value)) return;
    if (!HOSTNAME_OR_IPV4.test(value)) {
      fail("Must be a host name or IP address. An IPv6 address goes in brackets, like [::1].");
    }
  });

/**
 * An email address.
 *
 * Deliberately looser than an RFC 5322 parser: a validator that rejects an address the
 * administrator actually has to use is worse than one that accepts an address the relay will
 * refuse anyway — the relay's refusal names the address, and this one used to name nothing.
 *
 * A dot in the domain is NOT required, which is the specific case that made this unusable.
 * Internal relays commonly deliver to a single-label domain, and `sbom@intranet` is a real
 * sender on a real network. Requiring a dot rejected it with "must be an email address",
 * which reads as "you typed this wrong" about an address that was correct.
 */
export const emailAddressSchema = z
  .string()
  .trim()
  .min(3)
  .max(320)
  .regex(
    /^[^\s@,;<>]+@[^\s@,;<>]+$/,
    'must be an email address, like "reports@example.org"',
  );

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

/**
 * Saving the delivery settings.
 *
 * ## Half-configured is a legal state, and refusing it was the bug
 *
 * This used to require a host AND a sender AND them both being valid, on every save. Setting
 * up a relay is not one action — an administrator types the host, saves, tries it, adds the
 * sender, saves again — and every one of those intermediate saves was refused with "Body
 * validation failed" naming a field the person had not reached yet. The form looked
 * configurable and was not, which is exactly how it was reported.
 *
 * So the fields may be blank, and completeness is required only when `enabled` is true. That
 * is not a relaxation of the rule; it moves it to where it belongs. `enabled` is the
 * administrator saying "send this every month", and a platform that accepted that instruction
 * with no sender address would fail silently at 09:00 on the first working day of the month.
 * The check now sits on the promise rather than on the keystroke.
 *
 * The condition mirrors `reportDeliveryConfigured()` on the server exactly. Two definitions
 * of "ready to send" is how a switch that the API accepted ends up never firing.
 */
/**
 * The fields, before the cross-field rule below is applied.
 *
 * Exported separately because `superRefine` returns a wrapper with no `.shape`, and the
 * settings service reads the per-field schemas to recover a stored object one field at a
 * time — so that one value which no longer validates does not discard the recipient list
 * beside it. Tightening a rule here (as the host rule just was) is exactly when that matters.
 */
export const reportSettingsFieldsSchema = z.object({
  enabled: z.coerce.boolean(),
  smtpHost: smtpHostSchema,
  /*
    Not coerced from a blank string. `z.coerce.number()` turns "" into 0, which then failed
    `min(1)` with "Number must be greater than or equal to 1" -- a message about a value the
    administrator never typed, on a field they had merely cleared before typing the real one.
  */
  smtpPort: z
    .union([z.number(), z.string().trim().regex(/^\d+$/, "must be a number")])
    .pipe(z.coerce.number().int().min(1, "must be between 1 and 65535").max(65535, "must be between 1 and 65535")),
  smtpEncryption: smtpEncryptionSchema,
  smtpFrom: z.union([z.literal(""), emailAddressSchema]),
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

export const updateReportSettingsSchema = reportSettingsFieldsSchema.superRefine(
  (value, ctx) => {
    if (!value.enabled) return;

    /*
      Reported against the field that is missing, not as one message about the object. An
      error attached to `enabled` would highlight the switch, which is the one thing that is
      not wrong.
    */
    if (value.smtpHost === "") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["smtpHost"],
        message: "A mail server is needed before the report can be sent automatically.",
      });
    }
    if (value.smtpFrom === "") {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["smtpFrom"],
        message: "A sender address is needed before the report can be sent automatically.",
      });
    }
    if (value.recipients.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["recipients"],
        message: "Add at least one recipient before turning scheduled sending on.",
      });
    }
  },
);
export type UpdateReportSettings = z.infer<typeof updateReportSettingsSchema>;

/**
 * The connection half of the settings, on its own.
 *
 * Both test actions accept these so an administrator can try what is on screen before
 * committing it. Without that the only way to test a change is to save it first — which means
 * the stored configuration briefly describes a relay nobody has confirmed, and if the test
 * fails the previous working values are already gone.
 *
 * Admin-only, and reaching an arbitrary host is something the same person can already do by
 * saving and testing. This removes a step rather than a restriction.
 */
export const smtpConnectionSchema = z.object({
  smtpHost: smtpHostSchema,
  smtpPort: z.coerce.number().int().min(1).max(65535),
  smtpEncryption: smtpEncryptionSchema,
  smtpFrom: emailAddressSchema,
});
export type SmtpConnection = z.infer<typeof smtpConnectionSchema>;

/**
 * Body for the "send a test email" action, which proves the relay works before a month passes.
 *
 * `connection` is optional: absent means test what is saved.
 */
export const testReportEmailSchema = z.object({
  recipient: emailAddressSchema,
  connection: smtpConnectionSchema.optional(),
});
export type TestReportEmail = z.infer<typeof testReportEmailSchema>;

/** Body for the connection check, which opens the session and stops short of sending. */
export const verifySmtpSchema = z.object({
  connection: smtpConnectionSchema.optional(),
});
export type VerifySmtp = z.infer<typeof verifySmtpSchema>;

/**
 * What a test or a connection check reports back.
 *
 * A failure is a 502 carrying this shape rather than an error string, because the useful part
 * is not the relay's raw text — it is which of the handful of things that go wrong went
 * wrong, and what to change. `detail` keeps the original message: it is what an administrator
 * pastes to whoever runs the relay.
 */
export interface SmtpDiagnosis {
  ok: boolean;
  /** Short, stable identifier for the failure kind. `ok` when nothing went wrong. */
  code: string;
  /** One sentence saying what happened, in the reader's terms. */
  summary: string;
  /** What to change, when the failure implies a specific correction. */
  hint: string | null;
  /** The relay's or the network stack's own words, unedited. */
  detail: string | null;
}

/**
 * The conventional port/encryption pairings, offered as presets.
 *
 * Not enforced. Relays are configured by people with their own reasons, and a platform that
 * refused STARTTLS on 2525 because it is unusual would be wrong about somebody's network.
 * They exist so the common cases are one click rather than two fields and a guess, and so an
 * unusual combination can be pointed out without being blocked.
 */
export const SMTP_PRESETS = [
  {
    port: 25,
    encryption: "none" as SmtpEncryption,
    label: "25 — plain",
    hint: "The usual choice for an internal relay that accepts mail from inside the network.",
  },
  {
    port: 587,
    encryption: "starttls" as SmtpEncryption,
    label: "587 — STARTTLS",
    hint: "Submission port. The connection starts in the clear and is upgraded to TLS.",
  },
  {
    port: 465,
    encryption: "tls" as SmtpEncryption,
    label: "465 — TLS",
    hint: "TLS from the first byte.",
  },
] as const;

/**
 * Whether a port and an encryption setting are an unusual pairing, and why.
 *
 * Returns advice, never a verdict. The specific case worth catching is TLS selected against
 * port 25: the connection hangs until the timeout and then reports a socket error, which
 * reads as the relay being down rather than as this platform speaking TLS to something
 * expecting plain text.
 */
export function smtpPairingWarning(port: number, encryption: SmtpEncryption): string | null {
  if (port === 25 && encryption === "tls") {
    return "Port 25 rarely speaks TLS from the first byte. If the connection times out, try Plain or STARTTLS.";
  }
  if (port === 465 && encryption !== "tls") {
    return "Port 465 normally expects TLS from the first byte.";
  }
  if (port === 587 && encryption === "tls") {
    return "Port 587 normally expects STARTTLS rather than TLS from the first byte.";
  }
  return null;
}
