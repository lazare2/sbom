import { describe, expect, it, vi } from "vitest";
import type { ReportSettings } from "@sbom/shared";
import { ReportScheduler } from "../../src/modules/reports/report-scheduler.js";
import { renderTemplate } from "../../src/modules/reports/mailer.js";
import type { ReportService } from "../../src/modules/reports/report.service.js";
import type { SettingsService } from "../../src/modules/settings/settings.service.js";

/**
 * The scheduler's job is to send the report once a month and never twice.
 *
 * "Never twice" is enforced in the database, not here — but this decides when an attempt is
 * made at all, and the failure that matters is the one nobody sees: a container restarted at
 * the wrong moment either mailing management two copies or silently skipping the month.
 */

const TBILISI = "Asia/Tbilisi";

function settingsOf(over: Partial<ReportSettings> = {}): ReportSettings {
  return {
    enabled: true,
    smtpHost: "relay.internal",
    smtpPort: 25,
    smtpEncryption: "none",
    smtpFrom: "sbom@example.org",
    recipients: ["management@example.org"],
    timeZone: TBILISI,
    sendHour: 9,
    subjectTemplate: "Report {{period}}",
    bodyTemplate: "Findings: {{findings}}",
    ...over,
  };
}

function harness(over: { settings?: Partial<ReportSettings>; sentAt?: string | null } = {}) {
  const config = settingsOf(over.settings);

  const generate = vi.fn(async () => ({
    run: { id: "run-1", sentAt: over.sentAt ?? null },
    alreadyExisted: false,
  }));
  const deliver = vi.fn(async () => ({ sent: true, recipients: config.recipients }));

  const settings = {
    getReportSettings: async () => config,
    reportDeliveryConfigured: async () =>
      config.enabled && !!config.smtpHost && !!config.smtpFrom && config.recipients.length > 0,
  } as unknown as SettingsService;

  const logger = { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() };

  const scheduler = new ReportScheduler({
    settings,
    reports: { generate, deliver } as unknown as ReportService,
    logger: logger as never,
  });

  return { scheduler, generate, deliver, logger };
}

// 09:00 local on Monday 3 August 2026, the first working day of that month.
const DUE = new Date("2026-08-03T05:00:00Z");

describe("monthly report scheduler", () => {
  it("generates and sends on the first working day, at the configured hour", async () => {
    const { scheduler, generate, deliver } = harness();

    await scheduler.tick(DUE);

    expect(generate).toHaveBeenCalledTimes(1);
    expect(generate.mock.calls[0]?.[0]).toMatchObject({ kind: "monthly", timeZone: TBILISI });
    expect(deliver).toHaveBeenCalledWith("run-1");
  });

  it("does nothing at all while delivery is switched off", async () => {
    const { scheduler, generate, deliver } = harness({ settings: { enabled: false } });

    await scheduler.tick(DUE);

    // Not even generation. A disabled feature that quietly files a monthly record is a
    // surprise waiting for whoever eventually enables it.
    expect(generate).not.toHaveBeenCalled();
    expect(deliver).not.toHaveBeenCalled();
  });

  it("does not send before the configured hour", async () => {
    const { scheduler, generate } = harness();

    // 08:00 local on the same day.
    await scheduler.tick(new Date("2026-08-03T04:00:00Z"));

    expect(generate).not.toHaveBeenCalled();
  });

  it("does not send on the weekend at the start of the month", async () => {
    const { scheduler, generate } = harness();

    // 1 August 2026 is a Saturday and 2 August a Sunday, both past the configured hour.
    await scheduler.tick(new Date("2026-08-01T09:00:00Z"));
    await scheduler.tick(new Date("2026-08-02T09:00:00Z"));

    expect(generate).not.toHaveBeenCalled();
  });

  it("does not resend a report that has already been sent", async () => {
    // The state after a restart: this month's run exists and was delivered.
    const { scheduler, deliver } = harness({ sentAt: "2026-08-03T05:00:10.000Z" });

    await scheduler.tick(DUE);
    await scheduler.tick(new Date("2026-08-04T09:00:00Z"));

    expect(deliver).not.toHaveBeenCalled();
  });

  it("retries a report that was generated but never sent", async () => {
    // The relay was down on the day. The report exists, so generation is a no-op, but the
    // send has to be attempted again rather than the month being written off.
    const { scheduler, deliver } = harness({ sentAt: null });

    await scheduler.tick(new Date("2026-08-06T09:00:00Z"));

    expect(deliver).toHaveBeenCalledWith("run-1");
  });

  it("generates but does not attempt delivery while the relay is unconfigured", async () => {
    const { scheduler, generate, deliver } = harness({
      settings: { recipients: [] },
    });

    await scheduler.tick(DUE);

    // The report is still worth producing: it is the record of the month, and it can be
    // downloaded from the admin panel even if nobody can be mailed yet.
    expect(generate).toHaveBeenCalledTimes(1);
    expect(deliver).not.toHaveBeenCalled();
  });

  it("swallows a failure rather than letting it escape into the platform", async () => {
    const { scheduler, logger } = harness();
    const broken = new ReportScheduler({
      settings: {
        getReportSettings: async () => {
          throw new Error("settings table unreachable");
        },
      } as unknown as SettingsService,
      reports: {} as unknown as ReportService,
      logger: logger as never,
    });

    // Must resolve, not reject: this runs on a timer with nothing to catch it.
    await expect(broken.tick(DUE)).resolves.toBeUndefined();
    expect(logger.warn).toHaveBeenCalled();
    expect(scheduler).toBeDefined();
  });
});

describe("email template rendering", () => {
  it("substitutes documented placeholders", () => {
    expect(renderTemplate("Report {{period}}: {{findings}} findings", {
      period: "2026-07",
      findings: "895",
    })).toBe("Report 2026-07: 895 findings");
  });

  it("leaves an unknown placeholder visible instead of blanking it", () => {
    // A typo has to arrive in the inbox as a typo. Rendering it as an empty string produces
    // a sentence that reads as complete and states something false.
    expect(renderTemplate("Apps: {{aplications}}", { applications: "9" })).toBe(
      "Apps: {{aplications}}",
    );
  });

  it("does not evaluate anything in the template", () => {
    // The body is authored through a web form. Substitution is literal by design: no
    // property access, no expressions, nothing that turns an admin field into code.
    const template = "{{constructor}} {{__proto__}} {{toString}}";
    expect(renderTemplate(template, { period: "2026-07" })).toBe(template);
  });
});
