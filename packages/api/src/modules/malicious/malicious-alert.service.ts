import { sql } from "drizzle-orm";
import type { Database } from "../../db/client.js";
import type { Logger } from "../ingestion/ingestion.service.js";
import type { Mailer } from "../reports/mailer.js";
import type { SettingsService } from "../settings/settings.service.js";
import { rowsOf, type Row } from "../applications/applications.service.js";

/**
 * Telling somebody a malicious package is in their estate.
 *
 * The dashboard and the findings page are where this is investigated; the email exists
 * because nobody is looking at a dashboard at 02:00, and this is the one class of finding
 * where the gap between discovery and response is measured in hours. A malicious release is
 * usually pulled from its registry within a day, and everything it touched keeps its stolen
 * credentials afterwards.
 *
 * ## Sent once per package per application
 *
 * `malicious_alert_sent` records what has already gone out, keyed on the pair rather than on
 * the report alone. A report reaching a SECOND application is news -- the blast radius grew --
 * while the same pair re-detected on every sweep is not, and would train people to filter
 * these into a folder they never open.
 *
 * ## Failure is never anybody else's problem
 *
 * A relay that is down must not fail a sweep, hold up matching or surface anywhere in the
 * platform. An unsent alert is recorded and retried on the next pass, because the pair is
 * only marked sent after the relay accepts it.
 */

/**
 * Findings named individually in one email before it summarises the rest.
 *
 * A first sweep of a neglected estate can produce a great many at once. Twenty is enough to
 * act on; beyond that the message says how many more there are and points at the page, which
 * is a better artifact than a five-hundred-line email nobody reads to the end.
 */
const MAX_LISTED = 20;

interface PendingRow {
  malicious_package_id: string;
  application_id: string;
  application_name: string;
  package_name: string;
  ecosystem: string;
  version: string | null;
  in_current_build: boolean;
  reference_url: string | null;
}

export class MaliciousAlertService {
  constructor(
    private readonly deps: {
      db: Database;
      settings: SettingsService;
      mailer: Mailer;
      logger: Logger;
      publicUrl: string;
    },
  ) {}

  /**
   * Mail anything found since the last run.
   *
   * Returns the number of findings announced, which is zero in the ordinary case and is not a
   * failure. Never throws.
   */
  async dispatch(): Promise<number> {
    try {
      const malicious = await this.deps.settings.getMaliciousSettings();
      if (!malicious.enabled || !malicious.alertsEnabled) return 0;
      if (malicious.alertRecipients.length === 0) return 0;

      const report = await this.deps.settings.getReportSettings();
      // The relay is configured once, with the monthly report. Alerts reuse it rather than
      // asking an administrator to enter the same host twice and keep the two in step.
      if (report.smtpHost.trim() === "" || report.smtpFrom.trim() === "") {
        this.deps.logger.warn(
          {},
          "malicious alerts are enabled but no SMTP relay is configured on the report settings",
        );
        return 0;
      }

      const pending = await this.pending();
      if (pending.length === 0) return 0;

      const message = this.compose(pending);
      await this.deps.mailer.send(report, {
        to: malicious.alertRecipients,
        subject: this.subject(pending),
        text: message,
      });

      await this.markSent(pending);
      this.deps.logger.info(
        { findings: pending.length, recipients: malicious.alertRecipients.length },
        "malicious package alert sent",
      );
      return pending.length;
    } catch (err) {
      // Nothing above may take down the sweep that called it. The pairs stay unmarked, so the
      // next pass tries again rather than losing the alert with this one.
      this.deps.logger.warn(
        { err: err instanceof Error ? err.message : String(err) },
        "malicious package alert could not be sent",
      );
      return 0;
    }
  }

  /** Findings whose (report, application) pair has never been announced. */
  private async pending(): Promise<PendingRow[]> {
    const rows = await this.deps.db.execute<Row<PendingRow>>(sql`
      SELECT DISTINCT ON (mp.id, a.id)
        mp.id AS malicious_package_id,
        a.id AS application_id,
        a.name AS application_name,
        mp.package_name, mp.ecosystem, mp.reference_url,
        c.version,
        bool_or(sc.scan_id = a.latest_scan_id) OVER (PARTITION BY mp.id, a.id) AS in_current_build
      FROM component_malicious cm
      JOIN malicious_package mp ON mp.id = cm.malicious_package_id AND mp.withdrawn_at IS NULL
      JOIN component c ON c.id = cm.component_id
      JOIN scan_component sc ON sc.component_id = cm.component_id
      JOIN application a ON a.id = sc.application_id
      WHERE NOT EXISTS (
        SELECT 1 FROM malicious_alert_sent sent
        WHERE sent.malicious_package_id = mp.id AND sent.application_id = a.id
      )
      ORDER BY mp.id, a.id
    `);
    return rowsOf(rows);
  }

  private subject(pending: PendingRow[]): string {
    const packages = new Set(pending.map((p) => p.malicious_package_id)).size;
    const apps = new Set(pending.map((p) => p.application_id)).size;
    const noun = packages === 1 ? "malicious package" : "malicious packages";
    return `[SBOM] ${packages} ${noun} detected across ${apps} application${apps === 1 ? "" : "s"}`;
  }

  /**
   * The message.
   *
   * Written to be acted on rather than filed. It leads with what to do, because the recipient
   * is being told their build machines may already have handed over their credentials, and
   * the instinct to simply delete the package and move on leaves the actual damage in place.
   */
  private compose(pending: PendingRow[]): string {
    const current = pending.filter((p) => p.in_current_build);
    const historical = pending.filter((p) => !p.in_current_build);

    const lines: string[] = [
      "Malicious packages have been detected in the software inventory.",
      "",
      "WHAT TO DO",
      "",
      "  1. Remove the package and rebuild.",
      "  2. Rotate every credential that was readable from the machines that installed it --",
      "     CI tokens, registry credentials, cloud keys, anything in the build environment.",
      "     Package managers run install scripts, so the payload executed at install time,",
      "     before this was reported. Removing the package does not undo that.",
      "  3. Check the upstream report before acting further. It usually describes exactly",
      "     what the payload did.",
      "",
    ];

    const render = (rows: PendingRow[], heading: string, note: string): void => {
      if (rows.length === 0) return;
      lines.push(heading, note, "");
      for (const row of rows.slice(0, MAX_LISTED)) {
        lines.push(`  ${row.application_name}`);
        lines.push(
          `    ${row.ecosystem}/${row.package_name}${row.version ? `@${row.version}` : ""}  (${row.malicious_package_id})`,
        );
        if (row.reference_url) lines.push(`    ${row.reference_url}`);
        lines.push("");
      }
      if (rows.length > MAX_LISTED) {
        lines.push(`  ...and ${rows.length - MAX_LISTED} more. See the platform for the full list.`, "");
      }
    };

    render(
      current,
      "IN A CURRENT BUILD",
      "  These are still being shipped. Remove them first.",
    );
    render(
      historical,
      "IN A PREVIOUS BUILD ONLY",
      "  Already gone from the current build, but they ran on the machines that built it." +
        "\n  The credentials those machines held are still to be treated as compromised.",
    );

    lines.push(`Full detail: ${this.deps.publicUrl.replace(/\/+$/, "")}/malicious`, "");
    return lines.join("\n");
  }

  /** Marked only after the relay accepted, so a failed send is retried rather than lost. */
  private async markSent(pending: PendingRow[]): Promise<void> {
    const values = pending.map(
      (p) => sql`(${p.malicious_package_id}, ${p.application_id}::uuid)`,
    );
    await this.deps.db.execute(sql`
      INSERT INTO malicious_alert_sent (malicious_package_id, application_id)
      VALUES ${sql.join(values, sql`, `)}
      ON CONFLICT (malicious_package_id, application_id) DO NOTHING
    `);
  }
}
