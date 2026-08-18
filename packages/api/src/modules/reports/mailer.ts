import { createTransport, type Transporter } from "nodemailer";
import type { ReportSettings } from "@sbom/shared";
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

export class Mailer {
  constructor(private readonly deps: { logger: FastifyBaseLogger }) {}

  private transportFor(settings: ReportSettings): Transporter {
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
   * screen, rather than at 09:00 on the first working day of next month.
   */
  async verify(settings: ReportSettings): Promise<void> {
    const transport = this.transportFor(settings);
    try {
      await transport.verify();
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
