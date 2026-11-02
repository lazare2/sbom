import { open } from "node:fs/promises";
import type { FastifyBaseLogger } from "fastify";
import type { VulnScanner, VulnScannerSettings, VulnScannerStatus, VulnDbUpdateOutcome } from "@sbom/shared";
import { vulnScanners, VULN_SCANNER_LABELS } from "@sbom/shared";
import type { ParsedFinding } from "./grype-output.js";
import { mergeFindings } from "./merge.js";
import type {
  DbUpdateResult,
  MatchResult,
  ReachabilityResult,
  ScannablePackage,
  ScannerAvailability,
  ScannerDbStatus,
  VulnerabilityScanner,
} from "./types.js";

/**
 * Every switched-on scanner, presented to the rest of the platform as one.
 *
 * The sweep, the database service and the fix advisor all talk to a single
 * `VulnerabilityScanner`; this is it. A match runs each usable scanner over the batch and
 * merges the results (see `mergeFindings`), so every finding stored records which scanners
 * reported it.
 *
 * ## Run the ones that work
 *
 * A scanner that is switched on but cannot run - binary missing, database never downloaded,
 * a firewall not yet opened for it - is left out of the sweep rather than stopping it, and
 * the admin screen says why. Leaving it out has to be undone when it recovers, which is what
 * the watermark below is for.
 *
 * ## The watermark
 *
 * The sweep decides what to re-assess by comparing each component's stamp with one
 * timestamp. With one database that timestamp was its build date. With several, it is the
 * moment the *set* last changed: which scanners are usable, and each one's database build.
 * That set is fingerprinted, and when the fingerprint differs from the stored one the
 * watermark moves to now. So any database update, a scanner switched on or off, or one that
 * failed and came back, re-queues the estate - and every existing "older than the
 * watermark" query keeps its meaning unchanged.
 *
 * A scanner that fails during a match is suspended for a while and the batch is abandoned
 * rather than stored without it; the next tick runs without it, under a new fingerprint, and
 * its return produces another.
 */

/**
 * A scanner that throws during a match sits out before it is tried again: 30 minutes, then
 * twice as long after each further failure, up to a day. Its return re-queues the estate, so
 * a fixed short pause would turn one broken scanner into a full re-assessment every half
 * hour; the doubling keeps that rare while a scanner that recovers is back within the hour.
 */
const SUSPEND_MS = 30 * 60 * 1000;
const SUSPEND_MAX_MS = 24 * 60 * 60 * 1000;

/** Member state is cached briefly: the admin page polls status, and each check spawns a process. */
const STATE_TTL_MS = 10_000;

export interface ScannerMember {
  name: VulnScanner;
  scanner: VulnerabilityScanner;
}

interface MemberState extends ScannerMember {
  availability: ScannerAvailability;
  db: ScannerDbStatus;
  usable: boolean;
  problem: string | null;
}

export interface WatermarkStore {
  read(): Promise<{ fingerprint: string; at: Date } | null>;
  write(value: { fingerprint: string; at: Date }): Promise<void>;
}

export class CompositeScanner implements VulnerabilityScanner {
  readonly name = "composite";
  private cache: { at: number; states: MemberState[] } | null = null;
  private readonly suspended = new Map<VulnScanner, { until: number; reason: string }>();
  /** Consecutive failed matches per scanner, for the back-off. Cleared by a successful match. */
  private readonly failures = new Map<VulnScanner, number>();

  constructor(
    private readonly deps: {
      /** The switched-on scanners, resolved per call so settings changes apply at once. */
      members: () => Promise<ScannerMember[]>;
      settings: () => Promise<VulnScannerSettings>;
      watermarkStore: WatermarkStore;
      /**
       * For these advisory names (as reported), the stored advisory carrying each one - as
       * its id or an alias - keyed by the upper-cased name.
       */
      knownAdvisories: (names: string[]) => Promise<Map<string, string>>;
      /** Where each scanner's database comes from, for the admin screen. */
      updateSources: Record<VulnScanner, () => Promise<string | null>>;
      logger: FastifyBaseLogger;
    },
  ) {}

  /** Forget cached member state, after anything that changes it. */
  invalidate(): void {
    this.cache = null;
  }

  private async states(): Promise<MemberState[]> {
    if (this.cache && Date.now() - this.cache.at < STATE_TTL_MS) return this.cache.states;
    const members = await this.deps.members();
    const states = await Promise.all(
      members.map(async (member): Promise<MemberState> => {
        const [availability, db] = await Promise.all([
          member.scanner.availability(),
          member.scanner.dbStatus(),
        ]);
        const suspension = this.suspended.get(member.name);
        const suspendedNow = suspension !== undefined && suspension.until > Date.now();
        if (suspension && !suspendedNow) this.suspended.delete(member.name);
        const problem = !availability.available
          ? (availability.attempts.at(-1)?.reason ?? "not available")
          : !db.present || db.builtAt === null
            ? (db.error ?? "no database installed")
            : suspendedNow
              ? `failed during the last match and sits out until ${new Date(suspension!.until).toISOString()}: ${suspension!.reason}`
              : null;
        return { ...member, availability, db, usable: problem === null, problem };
      }),
    );
    this.cache = { at: Date.now(), states };
    return states;
  }

  private async usable(): Promise<MemberState[]> {
    return (await this.states()).filter((s) => s.usable);
  }

  /** Each scanner's state for the admin screen, switched on or not. */
  async memberStatuses(): Promise<VulnScannerStatus[]> {
    const [settings, states] = await Promise.all([this.deps.settings(), this.states()]);
    return Promise.all(
      vulnScanners.map(async (name): Promise<VulnScannerStatus> => {
        const state = states.find((s) => s.name === name);
        return {
          name,
          enabled: settings[name],
          available: state?.availability.available ?? false,
          version: state?.availability.version ?? null,
          problem: state ? state.problem : null,
          database: {
            present: state?.db.present ?? false,
            builtAt: state?.db.builtAt?.toISOString() ?? null,
            path: state?.db.path ?? null,
          },
          updateSource: await this.deps.updateSources[name]().catch(() => null),
        };
      }),
    );
  }

  async availability(): Promise<ScannerAvailability> {
    const states = await this.states();
    const running = states.filter((s) => s.availability.available);
    return {
      available: running.length > 0,
      version: running.map((s) => `${VULN_SCANNER_LABELS[s.name]} ${s.availability.version ?? ""}`.trim()).join(" · ") || null,
      path: running.map((s) => s.availability.path).filter(Boolean).join(", ") || null,
      resolvedBy: "composite",
      supportedDbSchema: null,
      attempts: states
        .filter((s) => s.problem !== null)
        .map((s) => ({ strategy: s.name, location: s.availability.path ?? s.name, reason: `${VULN_SCANNER_LABELS[s.name]}: ${s.problem}` })),
    };
  }

  /** Present when any scanner can match, and dated by the watermark - see the class comment. */
  async dbStatus(): Promise<ScannerDbStatus> {
    const states = await this.states();
    const usable = states.filter((s) => s.usable);
    const problems = states.filter((s) => s.problem !== null).map((s) => `${VULN_SCANNER_LABELS[s.name]}: ${s.problem}`);
    const builtAt = await this.watermark();
    return {
      present: usable.length > 0 && builtAt !== null,
      builtAt,
      schemaVersion: usable.map((s) => s.name).join("+") || null,
      valid: usable.length > 0,
      error: usable.length === 0 ? problems.join(" ") || "No scanner is switched on." : null,
      path: null,
    };
  }

  /** Which scanners and which database builds the current findings come from. */
  private fingerprint(usable: MemberState[]): string {
    return usable
      .map((s) => `${s.name}@${s.db.builtAt!.toISOString()}`)
      .sort()
      .join("|");
  }

  async watermark(): Promise<Date | null> {
    const usable = await this.usable();
    if (usable.length === 0) return null;
    const fingerprint = this.fingerprint(usable);
    const stored = await this.deps.watermarkStore.read();
    if (stored && stored.fingerprint === fingerprint) return stored.at;
    const at = new Date();
    await this.deps.watermarkStore.write({ fingerprint, at });
    this.deps.logger.info({ fingerprint, previous: stored?.fingerprint ?? null }, "vulnerability scanner set changed; estate re-queued");
    return at;
  }

  async listingUrl(): Promise<string> {
    const states = await this.states();
    const urls = await Promise.all(states.map((s) => s.scanner.listingUrl().catch(() => null)));
    return urls.filter(Boolean).join(" · ");
  }

  async checkReachable(): Promise<ReachabilityResult> {
    const states = await this.states();
    const results = await Promise.all(states.map((s) => s.scanner.checkReachable()));
    const failed = results.filter((r) => !r.reachable);
    return {
      reachable: failed.length < results.length,
      url: results.map((r) => r.url).join(" · "),
      message: failed.length > 0 ? failed.map((r) => r.message).join(" ") : null,
    };
  }

  /**
   * Update every switched-on scanner's database, one after another.
   *
   * Reported as one attempt with a line per scanner. "Updated" when any of them installed a
   * newer database - one scanner's firewall rule not being open yet must not hide that the
   * others did update.
   */
  async updateDb(): Promise<DbUpdateResult> {
    const before = await this.watermark();
    const states = await this.states();
    const outcomes: Array<{ name: VulnScanner; result: DbUpdateResult }> = [];
    for (const state of states) {
      if (!state.availability.available) {
        outcomes.push({
          name: state.name,
          result: {
            outcome: "failed",
            message: `not available: ${state.problem ?? "unknown reason"}`,
            builtBefore: null,
            builtAfter: null,
            schemaVersion: null,
            sourceUrl: null,
          },
        });
        continue;
      }
      try {
        outcomes.push({ name: state.name, result: await state.scanner.updateDb() });
      } catch (err) {
        outcomes.push({
          name: state.name,
          result: {
            outcome: "failed",
            message: err instanceof Error ? err.message : String(err),
            builtBefore: null,
            builtAfter: null,
            schemaVersion: null,
            sourceUrl: null,
          },
        });
      }
    }
    this.invalidate();
    const after = await this.watermark();

    const kinds = outcomes.map((o) => o.result.outcome);
    const outcome: VulnDbUpdateOutcome = kinds.some((k) => k === "updated" || k === "imported")
      ? "updated"
      : kinds.every((k) => k === "already-current")
        ? "already-current"
        : kinds.every((k) => k === "unreachable")
          ? "unreachable"
          : kinds.some((k) => k === "already-current")
            ? "already-current"
            : "failed";

    return {
      outcome,
      message: outcomes.map((o) => `${VULN_SCANNER_LABELS[o.name]}: ${o.result.message}`).join(" | ").slice(0, 2000),
      builtBefore: before,
      builtAfter: after,
      schemaVersion: (await this.usable()).map((s) => s.name).join("+") || null,
      sourceUrl: outcomes.map((o) => o.result.sourceUrl).filter(Boolean).join(" · ") || null,
    };
  }

  /**
   * Import a database archive by hand, routed by what it is: a zstd archive is Grype's, a
   * gzip archive is Trivy's.
   */
  async importDb(archivePath: string): Promise<DbUpdateResult> {
    const head = Buffer.alloc(4);
    const handle = await open(archivePath, "r");
    try {
      await handle.read(head, 0, 4, 0);
    } finally {
      await handle.close();
    }
    const target: VulnScanner = head[0] === 0x1f && head[1] === 0x8b ? "trivy" : "grype";
    const member = (await this.deps.members()).find((m) => m.name === target);
    if (!member) {
      return {
        outcome: "failed",
        message: `This looks like a ${VULN_SCANNER_LABELS[target]} database, and ${VULN_SCANNER_LABELS[target]} is switched off.`,
        builtBefore: null,
        builtAfter: null,
        schemaVersion: null,
        sourceUrl: archivePath,
      };
    }
    const result = await member.scanner.importDb(archivePath);
    this.invalidate();
    return { ...result, message: `${VULN_SCANNER_LABELS[target]}: ${result.message}` };
  }

  async match(packages: readonly ScannablePackage[]): Promise<MatchResult> {
    const submittedComponentIds = packages.map((p) => p.componentId);
    const usable = await this.usable();
    const watermark = await this.watermark();
    if (packages.length === 0 || usable.length === 0) {
      return { findings: [], grypeVersion: null, dbBuiltAt: watermark, unmappedFindings: 0, submittedComponentIds };
    }

    const collected: ParsedFinding[] = [];
    let unmappedFindings = 0;
    // One after another rather than in parallel: each holds its whole database in memory.
    for (const state of usable) {
      try {
        const result = await state.scanner.match(packages);
        collected.push(...result.findings.map((f) => ({ ...f, source: state.name })));
        unmappedFindings += result.unmappedFindings;
        this.failures.delete(state.name);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        const failures = (this.failures.get(state.name) ?? 0) + 1;
        this.failures.set(state.name, failures);
        const pause = Math.min(SUSPEND_MAX_MS, SUSPEND_MS * 2 ** (failures - 1));
        this.suspended.set(state.name, { until: Date.now() + pause, reason: reason.slice(0, 300) });
        this.invalidate();
        this.deps.logger.warn({ scanner: state.name, err }, "scanner failed during a match; suspended, batch abandoned");
        throw new Error(`${VULN_SCANNER_LABELS[state.name]} failed while matching: ${reason}`);
      }
    }

    const names = [...new Set(collected.flatMap((f) => [f.vulnerabilityId, ...f.aliases]))];
    const known = await this.deps.knownAdvisories(names);
    return {
      findings: mergeFindings(collected, known),
      grypeVersion: usable.map((s) => `${s.name} ${s.availability.version ?? ""}`.trim()).join(", "),
      dbBuiltAt: watermark,
      unmappedFindings,
      submittedComponentIds,
    };
  }
}
