import { createTransport, type Transporter } from "nodemailer";
import type { ReportSettings, SmtpConnection, SmtpDiagnosis } from "@sbom/shared";
import type { FastifyBaseLogger } from "fastify";

/**
 * Sending the monthly report.
 *
 * A thin wrapper over nodemailer rather than a raw SMTP conversation, because MIME encoding
 * of a binary attachment, line-ending rules and STARTTLS negotiation are all places where a
 * hand-rolled implementation is wrong in ways that only show up against one particular relay.
 *
 * No authentication is configured. The organisation's relay accepts mail from inside the
 * network, and a password held in a database row that every administrator can read and that
 * gets written to an audit entry when changed would be worse than no feature at all. If
 * credentials are ever required they belong in the environment, and this is the one place
 * that would have to change.
 */

export interface SendResult {
  /** Addresses the relay accepted. */
  accepted: string[];
  /** Addresses it refused. A partial send is a success with a list, not a failure. */
  rejected: string[];
  messageId: string;
}

export interface MailAttachment {
  filename: string;
  content: Buffer;
  contentType: string;
}

/**
 * How long to wait on a relay that is not answering.
 *
 * Bounded so a scheduled send cannot wedge the process for the default TCP timeout. Fifteen
 * seconds is generous for a relay on the same network and short enough that a firewall
 * silently dropping the connection is reported the same day rather than looking like a hang.
 */
const TIMEOUT_MS = 15_000;

/**
 * A relay failure, translated.
 *
 * Everything that goes wrong with SMTP arrives as an `Error` carrying a short code and a
 * message written for whoever wrote the network stack. Left alone it reached the API's error
 * handler as an unrecognised exception and came back as **500 Internal server error** — the
 * one answer that is both alarming and useless, because it says the platform is broken when
 * the platform is working and the relay is not.
 *
 * This class is what lets the routes answer 502 with something an administrator can act on.
 * The original text is kept in `detail` rather than replaced: it is what gets pasted to
 * whoever runs the mail server, and it is the only part they will recognise.
 */
export class MailTransportError extends Error {
  constructor(readonly diagnosis: SmtpDiagnosis) {
    super(diagnosis.summary);
    this.name = "MailTransportError";
  }
}

interface NodeMailerError {
  code?: string;
  errno?: number;
  syscall?: string;
  responseCode?: number;
  command?: string;
  message?: string;
}

/**
 * What went wrong, in the reader's terms.
 *
 * ## Read the syscall, not nodemailer's code
 *
 * The first version of this switched on `error.code`, which is the obvious thing to do and
 * produces confidently wrong answers. Nodemailer does not pass the operating system's error
 * through: it normalises everything into a handful of coarse codes of its own, and the useful
 * detail survives only in `syscall` and in the message text. Measured against a real relay:
 *
 *   unresolvable host   code EDNS,    syscall getaddrinfo, message "getaddrinfo ENOTFOUND …"
 *   refused connection  code ESOCKET, syscall connect,     message "connect ECONNREFUSED …"
 *   TLS to a plain port code ESOCKET, syscall connect,     message "connect ECONNREFUSED …"
 *
 * So `ESOCKET` is a catch-all for socket-level trouble, not the encryption failure it looks
 * like — mapping it to "encryption mismatch" reported a closed port as a TLS problem and sent
 * the reader to change a dropdown that was already right. A vague answer wastes time; a
 * confident wrong one wastes more.
 *
 * The underlying errno is therefore matched first, and nodemailer's own code is consulted
 * only for the states that have no syscall behind them — authentication and envelope
 * rejection, which are SMTP-level answers rather than network ones.
 */
export function diagnose(error: unknown, connection: SmtpConnection): SmtpDiagnosis {
  const err = (error ?? {}) as NodeMailerError;
  const detail = typeof err.message === "string" && err.message !== "" ? err.message : null;
  const text = detail ?? "";
  const where = `${connection.smtpHost}:${connection.smtpPort}`;
  const say = (code: string, summary: string, hint: string | null): SmtpDiagnosis => ({
    ok: false,
    code,
    summary,
    hint,
    detail,
  });

  // --- network-level, read from the syscall that actually failed -------------

  if (err.code === "EDNS" || err.syscall === "getaddrinfo" || /ENOTFOUND|EAI_AGAIN/.test(text)) {
    return say(
      "host_not_found",
      `The name "${connection.smtpHost}" could not be resolved.`,
      "Check the spelling, and that this server's DNS can resolve it. An IP address works too.",
    );
  }

  if (/ECONNREFUSED/.test(text)) {
    return say(
      "connection_refused",
      `Nothing is listening on ${where}.`,
      `The host was reached, so the address is right and the port is probably wrong — or the mail service is not running. Port 25 is the usual one for an internal relay.`,
    );
  }

  if (err.code === "ETIMEDOUT" || /ETIMEDOUT|timeout|Greeting never received/i.test(text)) {
    return say(
      "timed_out",
      `No answer from ${where} within ${TIMEOUT_MS / 1000} seconds.`,
      connection.smtpEncryption === "tls"
        ? 'A firewall may be dropping the connection — or the relay expects plain text and is waiting for a command it cannot read. Try Encryption "Plain".'
        : "A firewall dropping the connection silently looks exactly like this, as does a host that is up but not running a mail service.",
    );
  }

  if (/ERR_SSL|ERR_TLS|wrong version number|SSL routines|self.signed|certificate/i.test(text)) {
    return say(
      "encryption_mismatch",
      `Encryption could not be negotiated with ${where}.`,
      "The Encryption setting does not match what the relay expects. Port 25 is usually Plain, 587 STARTTLS, 465 TLS.",
    );
  }

  /*
    STARTTLS was required and the relay did not offer it. Raised as a plain message with no
    distinguishing code, so it is matched on text -- fragile, and still far better than
    reporting a one-dropdown fix as an internal server error.
  */
  if (/STARTTLS/i.test(text)) {
    return say(
      "starttls_unavailable",
      `${where} does not offer STARTTLS.`,
      'Set Encryption to "Plain" if this is an internal relay, or "TLS" if it expects encryption from the first byte.',
    );
  }

  // --- SMTP-level, where nodemailer's own code is the real signal ------------

  if (err.code === "EAUTH" || err.responseCode === 530 || err.responseCode === 535) {
    return say(
      "authentication_required",
      `${where} will not accept mail from this server without authentication.`,
      "This platform deliberately holds no mail password. The relay has to be configured to accept mail from this server's IP address unauthenticated.",
    );
  }

  if (err.code === "EENVELOPE" || err.responseCode === 550 || err.responseCode === 553) {
    return say(
      "address_refused",
      "The relay refused an address.",
      `Most often the sender: "${connection.smtpFrom}" has to be an address the relay accepts from this server.`,
    );
  }

  if (typeof err.responseCode === "number") {
    return say(
      "relay_refused",
      `The relay answered ${err.responseCode} and refused the request.`,
      "The message below is the relay's own — whoever administers it will recognise the code.",
    );
  }

  if (err.code === "ESOCKET") {
    return say(
      "connection_failed",
      `The connection to ${where} failed.`,
      "The host and port are worth checking first, then whether a firewall allows this server to reach it.",
    );
  }

  return say("failed", `Could not reach ${where}.`, null);
}

export class Mailer {
  constructor(private readonly deps: { logger: FastifyBaseLogger }) {}

  private transportFor(settings: SmtpConnection): Transporter {
    return createTransport({
      host: settings.smtpHost,
      port: settings.smtpPort,
      // `secure` means TLS from the first byte; STARTTLS upgrades a plaintext connection.
      // `requireTLS` is what stops a relay that does not offer STARTTLS from silently
      // falling back to sending the report in the clear.
      secure: settings.smtpEncryption === "tls",
      requireTLS: settings.smtpEncryption === "starttls",
      connectionTimeout: TIMEOUT_MS,
      greetingTimeout: TIMEOUT_MS,
      socketTimeout: TIMEOUT_MS,
      // No `auth`: see the note above.
    });
  }

  /**
   * Confirms the relay is reachable and willing, without sending anything.
   *
   * Offered to the admin page so a misconfiguration is found when someone is looking at the
   * screen, rather than at 09:00 on the first working day of next month. It opens the
   * session, greets, negotiates encryption and stops — which is where all but one of the
   * failures above happen, so it answers "will this work" without putting a test message in
   * somebody's inbox.
   *
   * Returns the diagnosis rather than throwing it, because both outcomes are results here:
   * this is a question, and "no, because the port is closed" is an answer to it.
   */
  async verify(settings: SmtpConnection): Promise<SmtpDiagnosis> {
    const transport = this.transportFor(settings);
    try {
      await transport.verify();
      return {
        ok: true,
        code: "ok",
        summary: `${settings.smtpHost}:${settings.smtpPort} accepted the connection.`,
        hint: null,
        detail: null,
      };
    } catch (error) {
      const diagnosis = diagnose(error, settings);
      this.deps.logger.warn(
        { host: settings.smtpHost, port: settings.smtpPort, code: diagnosis.code },
        "smtp connection check failed",
      );
      return diagnosis;
    } finally {
      transport.close();
    }
  }

  async send(
    settings: ReportSettings,
    message: {
      to: string[];
      subject: string;
      text: string;
      attachments?: MailAttachment[];
    },
  ): Promise<SendResult> {
    const transport = this.transportFor(settings);
    try {
      const info = await transport.sendMail({
        from: settings.smtpFrom,
        to: message.to,
        subject: message.subject,
        // Plain text only. The body is edited by an administrator through a web form, and
        // rendering it as HTML would turn that form into a way to author markup that lands
        // in other people's inboxes. Nothing in the report needs formatting the attachment
        // does not already provide.
        text: message.text,
        attachments: message.attachments,
      });

      const accepted = (info.accepted ?? []).map(String);
      const rejected = (info.rejected ?? []).map(String);

      if (rejected.length > 0) {
        // Logged rather than thrown: the report reached everyone else, and failing the whole
        // send because one address is wrong would deny nine people a report to punish a typo.
        this.deps.logger.warn(
          { rejected, accepted: accepted.length },
          "some report recipients were rejected by the relay",
        );
      }

      return { accepted, rejected, messageId: String(info.messageId ?? "") };
    } catch (error) {
      /*
        Translated on the way out, so every caller reports the same thing.

        This is the path that produced "Internal server error": nothing here caught the
        failure, so a refused connection reached the API's error handler as an unrecognised
        exception. The scheduler is affected too -- it records `error` on the run, and that
        string is what an administrator reads next month when asking why the report never
        arrived.
      */
      const diagnosis = diagnose(error, settings);
      this.deps.logger.warn(
        { host: settings.smtpHost, port: settings.smtpPort, code: diagnosis.code },
        "sending mail failed",
      );
      throw new MailTransportError(diagnosis);
    } finally {
      transport.close();
    }
  }
}

/**
 * Fills the placeholders an administrator may use in the subject and body.
 *
 * Literal substitution, with no expression evaluation and no property access. The template is
 * authored through a web form and rendered by the server, so anything richer would be an
 * injection surface bought for a convenience nobody asked for. An unknown placeholder is left
 * exactly as typed, so a mistake arrives in the email as `{{aplications}}` rather than as a
 * blank the reader has to guess at.
 */
export function renderTemplate(template: string, values: Record<string, string>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (whole, key: string) =>
    Object.prototype.hasOwnProperty.call(values, key) ? values[key]! : whole,
  );
}
