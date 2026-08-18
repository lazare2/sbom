import type { FastifyInstance } from "fastify";
import {
  generateReportSchema,
  idParamSchema,
  testReportEmailSchema,
  updateReportSettingsSchema,
} from "@sbom/shared";
import { parseOrThrow } from "../../lib/validate.js";
import { getUser } from "../../plugins/auth.plugin.js";

/**
 * The management report: generate, list, read.
 *
 * Registered inside the admin scope, so every route here inherits `requireAdmin`. That is a
 * stricter rule than the rest of the read API, which any authenticated user may call, and it
 * is deliberate: generating a report is a write that files a permanent record and moves
 * nothing else — but the history it writes into is the audit trail for what management was
 * told, and an ad-hoc run appearing in it should be attributable to a named person.
 */
export async function reportRoutes(fastify: FastifyInstance): Promise<void> {
  const { reports, audit, settings, mailer } = fastify.ctx;

  /*
    Registered before `/:id` so the literal path wins. Fastify prefers a static segment over
    a parameter, so this ordering is belt and braces rather than load-bearing -- but a reader
    should not have to know that to be sure "settings" is not being parsed as a report id.
  */
  fastify.get("/settings", async (_request, reply) => {
    return reply.send(await settings.getReportSettings());
  });

  fastify.put("/settings", async (request, reply) => {
    const body = parseOrThrow(updateReportSettingsSchema, request.body, "Body");
    const user = getUser(request);

    const { before, after } = await settings.updateReportSettings(body, {
      id: user.id,
      email: user.email,
    });

    await audit.record({
      actor: { id: user.id, email: user.email },
      action: "report_settings.update",
      targetType: "setting",
      targetId: "report.delivery",
      /*
        Recipients are recorded as a count rather than as addresses. The trail needs to show
        that the distribution list changed and by how much; reproducing every address into a
        second table that is never pruned is a copy of personal data nobody asked for.
      */
      metadata: {
        enabled: { from: before.enabled, to: after.enabled },
        smtpHost: { from: before.smtpHost, to: after.smtpHost },
        smtpPort: { from: before.smtpPort, to: after.smtpPort },
        smtpEncryption: { from: before.smtpEncryption, to: after.smtpEncryption },
        recipientCount: { from: before.recipients.length, to: after.recipients.length },
        sendHour: { from: before.sendHour, to: after.sendHour },
        timeZone: { from: before.timeZone, to: after.timeZone },
      },
    });

    return reply.send(after);
  });

  /**
   * Send a test email now.
   *
   * The alternative to this is discovering that the relay refuses the sender address at
   * 09:00 on the first working day of the month, in front of the people the report was for.
   */
  fastify.post("/settings/test", async (request, reply) => {
    const body = parseOrThrow(testReportEmailSchema, request.body, "Body");
    const user = getUser(request);
    const config = await settings.getReportSettings();

    await mailer.send(config, {
      to: [body.recipient],
      subject: "SBOM platform test message",
      text: "This is a test message from the SBOM platform. If you received it, the monthly report can be delivered to this address.",
    });

    await audit.record({
      actor: { id: user.id, email: user.email },
      action: "report_settings.test",
      targetType: "setting",
      targetId: "report.delivery",
      metadata: { recipient: body.recipient },
    });

    return reply.send({ sent: true });
  });

  fastify.get("/", async (_request, reply) => {
    return reply.send({ items: await reports.list() });
  });

  fastify.get("/:id", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const { run, delta } = await reports.get(id);
    return reply.send({ run, delta });
  });

  /**
   * The report as a PDF.
   *
   * A path ending in `.pdf` rather than content negotiation on the route above: this link
   * gets pasted into a browser, forwarded, and saved to disk, and all three work better when
   * the URL itself says what comes back.
   */
  fastify.get("/:id.pdf", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const { buffer, filename } = await reports.pdf(id);

    return reply
      .header("Content-Type", "application/pdf")
      .header("Content-Disposition", `attachment; filename="${filename}"`)
      .header("Content-Length", String(buffer.length))
      .send(buffer);
  });

  /**
   * Generate a report now.
   *
   * Defaults to `adhoc`, which is what the button sends. An ad-hoc run is compared against
   * the last monthly report but never becomes the baseline for the next one, so pressing
   * this cannot quietly shorten next month's reporting period.
   */
  fastify.post("/", async (request, reply) => {
    const body = parseOrThrow(generateReportSchema, request.body ?? {}, "Body");
    const user = getUser(request);

    const result = await reports.generate({
      kind: body.kind,
      actor: { id: user.id, email: user.email },
    });

    await audit.record({
      actor: { id: user.id, email: user.email },
      action: "report.generate",
      targetType: "report_run",
      targetId: result.run.id,
      metadata: {
        kind: result.run.kind,
        period: result.run.periodLabel,
        // Recorded because it is the difference between "generated" and "already existed",
        // and a scheduler retry landing here should not read as a second report.
        alreadyExisted: result.alreadyExisted,
      },
    });

    // 200 rather than 201 when the monthly guard returned the existing run: nothing was
    // created, and a CI caller checking for 201 should be able to tell the two apart.
    return reply.status(result.alreadyExisted ? 200 : 201).send({
      run: result.run,
      delta: result.delta,
      alreadyExisted: result.alreadyExisted,
    });
  });

  /**
   * Send an already-generated report.
   *
   * Separate from generation so the button can produce a report to look at without mailing
   * it to management, and so a delivery that failed can be retried without regenerating --
   * which would otherwise mean the resent report counted a different estate from the one the
   * first attempt described.
   */
  fastify.post("/:id/send", async (request, reply) => {
    const { id } = parseOrThrow(idParamSchema, request.params, "Params");
    const user = getUser(request);

    const result = await reports.deliver(id);

    await audit.record({
      actor: { id: user.id, email: user.email },
      action: "report.send",
      targetType: "report_run",
      targetId: id,
      metadata: { sent: result.sent, recipients: result.recipients.length, error: result.error },
    });

    // A delivery failure is reported as 502 rather than 500: the platform worked and the
    // relay did not, and the distinction decides who gets called about it.
    return reply.status(result.error ? 502 : 200).send(result);
  });
}
