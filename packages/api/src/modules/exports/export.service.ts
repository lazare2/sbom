import type { EnvironmentAccess } from "@sbom/shared";
import { applicationReadableBy, groupReadableBy, type ReadAccess } from "../environments/environment.service.js";
import { sql } from "drizzle-orm";
import {
  classifyComponentOrigin,
  type ExportFlavour,
  type VexJustification,
  type VexStatus,
  type VulnSeverity,
} from "@sbom/shared";
import type { Database } from "../../db/client.js";
import type { SettingsService } from "../settings/settings.service.js";
import { NotFoundError } from "../../lib/errors.js";
import { rowsOf, type Row } from "../applications/applications.service.js";
import { NOT_SUPPRESSED } from "../vulnerabilities/scope.js";
import type {
  ExportComponent,
  ExportDocument,
  ExportMalicious,
  ExportSource,
  ExportSubject,
  ExportVulnerability,
  VexDocument,
  VexStatement,
} from "./export.types.js";

/**
 * Assembles the export document. Rendering into a wire format happens elsewhere.
 *
 * ## Everything routes through one assembler
 *
 * An application resolves to its current build, a group to the current build of each member,
 * a scan to itself -- and then all three call the same assemble(). Subject resolution is the
 * only part that differs. That matters because the three would otherwise drift: a group
 * export that deduplicated differently from an application export would report a different
 * package count for a group of one, and nobody would find that for months.
 *
 * ## Deduplication picks the newest build's view
 *
 * A component can appear in several of a group's applications with different paths. The
 * inventory is deduplicated on the component identity -- one lodash@4.17.20 entry, not six
 * -- and its locations come from the most recently created scan that contained it. Merging
 * every path instead was rejected: the cap would then silently truncate a list assembled
 * from applications that have nothing to do with each other, which is a location list that
 * points nowhere in particular.
 */
export class ExportService {
  constructor(private readonly deps: { db: Database; settings: SettingsService }) {}

  async forScan(
    scanId: string,
    flavour: ExportFlavour,
    access: ReadAccess,
  ): Promise<ExportDocument> {
    const { subject, scanIds } = await this.scanSubject(scanId, access);
    return this.assemble(subject, scanIds, flavour);
  }

  async forApplication(
    applicationId: string,
    flavour: ExportFlavour,
    access: ReadAccess,
  ): Promise<ExportDocument> {
    const { subject, scanIds } = await this.applicationSubject(applicationId, access);
    return this.assemble(subject, scanIds, flavour);
  }

  // --- VEX -----------------------------------------------------------------

  async vexForApplication(
    applicationId: string,
    access: ReadAccess,
  ): Promise<VexDocument> {
    const { subject, scanIds } = await this.applicationSubject(applicationId, access);
    return this.assembleVex(subject, scanIds);
  }

  async vexForScan(scanId: string, access: ReadAccess): Promise<VexDocument> {
    const { subject, scanIds } = await this.scanSubject(scanId, access);
    return this.assembleVex(subject, scanIds);
  }

  async vexForGroup(groupId: string, access: ReadAccess): Promise<VexDocument> {
    const { subject, scanIds } = await this.groupSubject(groupId, access);
    return this.assembleVex(subject, scanIds);
  }

  async forGroup(
    groupId: string,
    flavour: ExportFlavour,
    access: ReadAccess,
  ): Promise<ExportDocument> {
    const { subject, scanIds } = await this.groupSubject(groupId, access);
    return this.assemble(subject, scanIds, flavour);
  }

  // --- Subject resolution --------------------------------------------------
  //
  // Shared by the SBOM and VEX paths so the two documents always describe the same thing. If
  // each resolved its own subject, a VEX document could quietly cover a different set of
  // builds from the SBOM it was published beside, and its component references would dangle.

  private async applicationSubject(
    applicationId: string,
    access: ReadAccess,
  ): Promise<{ subject: ExportSubject; scanIds: string[] }> {
    const rows = rowsOf(
      await this.deps.db.execute<Row<{ id: string; name: string; latest_scan_id: string | null }>>(
        sql`SELECT id, name, latest_scan_id FROM application a WHERE a.id = ${applicationId}::uuid
             AND ${applicationReadableBy("a", access)}`,
      ),
    );
    const app = rows[0];
    if (!app) throw new NotFoundError("Application not found");

    /*
      An application with no build is not an error and must not be one. It is an application
      somebody registered before its pipeline ever ran, and the honest export is a valid,
      empty document that says so -- not a 404, which would claim it does not exist.
    */
    const scanIds = app.latest_scan_id ? [app.latest_scan_id] : [];
    return {
      subject: {
        kind: "application",
        id: app.id,
        name: app.name,
        sources: await this.sourcesForScans(scanIds, access),
      },
      scanIds,
    };
  }

  private async scanSubject(
    scanId: string,
    access: ReadAccess,
  ): Promise<{ subject: ExportSubject; scanIds: string[] }> {
    const sources = await this.sourcesForScans([scanId], access);
    if (sources.length === 0) throw new NotFoundError("Scan not found");
    const source = sources[0]!;
    return {
      subject: {
        kind: "scan",
        id: scanId,
        // A build is named by what it is a build *of*, plus enough to say which one.
        name: `${source.applicationName}-${source.buildNumber ?? source.createdAt.slice(0, 10)}`,
        sources,
      },
      scanIds: [scanId],
    };
  }

  private async groupSubject(
    groupId: string,
    access: ReadAccess,
  ): Promise<{ subject: ExportSubject; scanIds: string[] }> {
    const groups = rowsOf(
      await this.deps.db.execute<Row<{ id: string; name: string }>>(
        sql`SELECT id, name FROM application_group g WHERE g.id = ${groupId}::uuid
             AND ${groupReadableBy("g", access)}`,
      ),
    );
    const group = groups[0];
    if (!group) throw new NotFoundError("Group not found");

    /*
      Members with no current build contribute nothing and are skipped rather than failing
      the export. The provenance block lists only the builds actually represented, so a
      reader can see the group has eight members and this document covers six of them.
    */
    const members = rowsOf(
      await this.deps.db.execute<Row<{ latest_scan_id: string }>>(sql`
        SELECT a.latest_scan_id
        FROM application_group_member gm
        JOIN application a ON a.id = gm.application_id
        WHERE gm.group_id = ${groupId}::uuid AND a.latest_scan_id IS NOT NULL
      `),
    );
    const scanIds = members.map((m) => m.latest_scan_id);
    return {
      subject: {
        kind: "group",
        id: group.id,
        name: group.name,
        sources: await this.sourcesForScans(scanIds, access),
      },
      scanIds,
    };
  }

  // -------------------------------------------------------------------------

  /*
    Every export -- by scan, by application, by group -- resolves its builds here, which
    makes this the one place the estate has to be enforced for the whole module.
  */
  private async sourcesForScans(
    scanIds: string[],
    access: ReadAccess,
  ): Promise<ExportSource[]> {
    if (scanIds.length === 0) return [];
    const rows = rowsOf(
      await this.deps.db.execute<
        Row<{
          scan_id: string;
          application_id: string;
          application_name: string;
          created_at: Date | string;
          image_ref: string | null;
          commit_sha: string | null;
          build_number: string | null;
          branch: string | null;
          tool_name: string | null;
          tool_version: string | null;
        }>
      >(sql`
        SELECT s.id AS scan_id, s.application_id, a.name AS application_name, s.created_at,
               s.image_ref, s.commit_sha, s.build_number, s.branch, s.tool_name, s.tool_version
        FROM scan s
        JOIN application a ON a.id = s.application_id
        WHERE s.id = ANY(${sql.param(scanIds)}::uuid[])
          AND ${applicationReadableBy("a", access)}
        ORDER BY a.name ASC
      `),
    );
    return rows.map((r) => ({
      scanId: r.scan_id,
      applicationId: r.application_id,
      applicationName: r.application_name,
      createdAt: new Date(r.created_at).toISOString(),
      imageRef: r.image_ref,
      commitSha: r.commit_sha,
      buildNumber: r.build_number,
      branch: r.branch,
      toolName: r.tool_name,
      toolVersion: r.tool_version,
    }));
  }

  private async assemble(
    subject: ExportSubject,
    scanIds: string[],
    flavour: ExportFlavour,
  ): Promise<ExportDocument> {
    const [vulnerabilityScanning, maliciousDetection] = await Promise.all([
      this.deps.settings.vulnScanningEnabled(),
      this.maliciousEnabled(),
    ]);

    const base = {
      subject,
      flavour,
      generatedAt: new Date().toISOString(),
      assessment: { vulnerabilityScanning, maliciousDetection },
    };
    if (scanIds.length === 0) return { ...base, components: [] };

    const components = await this.components(scanIds);
    if (flavour === "inventory") return { ...base, components };

    /*
      Only queried when the feature is on. Querying anyway and finding nothing would build a
      document whose empty findings mean "switched off" while looking exactly like one whose
      empty findings mean "clean".
    */
    const [vulns, malicious] = await Promise.all([
      vulnerabilityScanning
        ? this.vulnerabilities(scanIds)
        : new Map<string, ExportVulnerability[]>(),
      maliciousDetection ? this.malicious(scanIds) : new Map<string, ExportMalicious[]>(),
    ]);

    return {
      ...base,
      components: components.map((c) => ({
        ...c,
        vulnerabilities: vulns.get(c.identityHash) ?? [],
        malicious: malicious.get(c.identityHash) ?? [],
      })),
    };
  }

  /**
   * Gathers the assessments that apply to this subject.
   *
   * Only suppressions that actually match a component present in the subject produce a
   * statement. An estate-wide suppression for a CVE nothing here carries is a real assessment
   * and still emits nothing, because a VEX statement about a package the recipient does not
   * have is noise they have to read and discard.
   */
  private async assembleVex(subject: ExportSubject, scanIds: string[]): Promise<VexDocument> {
    const generatedAt = new Date().toISOString();
    if (scanIds.length === 0) {
      return { subject, generatedAt, statements: [], readiness: { classified: 0, unclassified: 0 } };
    }

    const rows = rowsOf(
      await this.deps.db.execute<
        Row<{
          suppression_id: string;
          vulnerability_id: string;
          vex_status: VexStatus | null;
          vex_justification: VexJustification | null;
          reason: string;
          created_at: Date | string;
          created_by_email: string | null;
          identity_hash: string;
        }>
      >(sql`
        SELECT DISTINCT ON (sup.id, c.identity_hash)
               sup.id AS suppression_id, sup.vulnerability_id, sup.vex_status,
               sup.vex_justification, sup.reason, sup.created_at, sup.created_by_email,
               c.identity_hash
        FROM scan_component sc
        JOIN component c ON c.id = sc.component_id
        JOIN application a ON a.id = sc.application_id
        JOIN component_vulnerability cv ON cv.component_id = c.id
        JOIN vulnerability_suppression sup ON sup.vulnerability_id = cv.vulnerability_id
        WHERE sc.scan_id = ANY(${sql.param(scanIds)}::uuid[])
          /*
            The same widening-by-nullability rule the suppression predicate uses: both ids
            null means estate-wide, component_id narrows to one package version,
            application_id to one application. Written out rather than reusing NOT_SUPPRESSED
            because that fragment negates the match, and here the matches are the answer.
          */
          AND (sup.component_id IS NULL OR sup.component_id = c.id)
          AND (sup.application_id IS NULL OR sup.application_id = a.id)
          AND (sup.expires_at IS NULL OR sup.expires_at > now())
        ORDER BY sup.id, c.identity_hash
      `),
    );

    const bySuppression = new Map<string, VexStatement>();
    let unclassified = 0;
    const seenUnclassified = new Set<string>();

    for (const r of rows) {
      if (r.vex_status === null) {
        /*
          Counted, never emitted, and never defaulted. This is an assessment somebody made
          that cannot be expressed to a consumer, and the document reports how many there are
          so a partial set of statements is not mistaken for a complete one.
        */
        if (!seenUnclassified.has(r.suppression_id)) {
          seenUnclassified.add(r.suppression_id);
          unclassified += 1;
        }
        continue;
      }

      const existing = bySuppression.get(r.suppression_id);
      if (existing) {
        existing.affects.push(r.identity_hash);
        continue;
      }
      bySuppression.set(r.suppression_id, {
        suppressionId: r.suppression_id,
        vulnerabilityId: r.vulnerability_id,
        status: r.vex_status,
        justification: r.vex_justification,
        detail: r.reason,
        affects: [r.identity_hash],
        createdAt: new Date(r.created_at).toISOString(),
        createdByEmail: r.created_by_email,
      });
    }

    const statements = [...bySuppression.values()].sort((a, b) =>
      // Stable ordering so republishing an unchanged assessment set produces the same bytes.
      a.vulnerabilityId.localeCompare(b.vulnerabilityId) ||
      a.suppressionId.localeCompare(b.suppressionId),
    );

    return {
      subject,
      generatedAt,
      statements,
      readiness: { classified: statements.length, unclassified },
    };
  }

  private async maliciousEnabled(): Promise<boolean> {
    try {
      return (await this.deps.settings.getMaliciousSettings()).enabled;
    } catch {
      // Fails closed, exactly as vulnerability scanning does: an unreadable setting must
      // report "not assessed" rather than let a document imply the feed had been consulted.
      return false;
    }
  }

  private async components(scanIds: string[]): Promise<ExportComponent[]> {
    const rows = rowsOf(
      await this.deps.db.execute<
        Row<{
          identity_hash: string;
          name: string;
          version: string | null;
          ecosystem: string;
          kind: "library" | "os" | "runtime";
          purl: string | null;
          cpe: string | null;
          paths: string[] | null;
          path_count: number | string | null;
        }>
      >(sql`
        WITH picked AS (
          SELECT sc.component_id, sc.paths, sc.path_count,
                 row_number() OVER (
                   PARTITION BY sc.component_id ORDER BY sc.created_at DESC, sc.scan_id
                 ) AS rn
          FROM scan_component sc
          WHERE sc.scan_id = ANY(${sql.param(scanIds)}::uuid[])
        )
        SELECT c.identity_hash, c.name, c.version, c.ecosystem, c.kind, c.purl, c.cpe,
               p.paths, p.path_count
        FROM picked p
        JOIN component c ON c.id = p.component_id
        WHERE p.rn = 1
        ORDER BY lower(c.name) ASC, c.version ASC NULLS FIRST
      `),
    );

    return rows.map((r) => ({
      identityHash: r.identity_hash,
      name: r.name,
      version: r.version,
      ecosystem: r.ecosystem,
      kind: r.kind,
      purl: r.purl,
      cpe: r.cpe,
      origin: classifyComponentOrigin({ ecosystem: r.ecosystem, paths: r.paths, kind: r.kind }),
      paths: r.paths,
      pathCount: r.path_count === null ? null : Number(r.path_count),
      vulnerabilities: [],
      malicious: [],
    }));
  }

  private async vulnerabilities(scanIds: string[]): Promise<Map<string, ExportVulnerability[]>> {
    /*
      Suppressed findings are excluded, through the same predicate the dashboard and the
      sweep use. An export that disagreed with the screen it was downloaded from would send
      somebody chasing a discrepancy that is not one -- and the assessments behind those
      suppressions are exactly what the VEX document carries, in the form consumers read.
    */
    const rows = rowsOf(
      await this.deps.db.execute<
        Row<{
          identity_hash: string;
          id: string;
          severity: VulnSeverity;
          cvss_base_score: number | null;
          cvss_vector: string | null;
          epss_score: number | null;
          known_exploited: boolean;
          description: string | null;
          fix_state: string;
          fix_versions: string[] | null;
          urls: string[] | null;
          data_source: string | null;
        }>
      >(sql`
        SELECT DISTINCT ON (c.identity_hash, v.id)
               c.identity_hash, v.id, v.severity, v.cvss_base_score, v.cvss_vector,
               v.epss_score, v.known_exploited, v.description, v.data_source,
               cv.fix_state, cv.fix_versions, v.urls
        FROM scan_component sc
        JOIN component c ON c.id = sc.component_id
        JOIN application a ON a.id = sc.application_id
        JOIN component_vulnerability cv ON cv.component_id = c.id
        JOIN vulnerability v ON v.id = cv.vulnerability_id
        WHERE sc.scan_id = ANY(${sql.param(scanIds)}::uuid[])
          AND ${NOT_SUPPRESSED}
        ORDER BY c.identity_hash, v.id
      `),
    );

    const byComponent = new Map<string, ExportVulnerability[]>();
    for (const r of rows) {
      const list = byComponent.get(r.identity_hash) ?? [];
      list.push({
        id: r.id,
        severity: r.severity,
        cvssBaseScore: r.cvss_base_score,
        cvssVector: r.cvss_vector,
        epssScore: r.epss_score,
        knownExploited: r.known_exploited,
        description: r.description,
        fixState: r.fix_state,
        fixVersions: r.fix_versions ?? [],
        urls: r.urls ?? [],
        dataSource: r.data_source,
      });
      byComponent.set(r.identity_hash, list);
    }
    return byComponent;
  }

  private async malicious(scanIds: string[]): Promise<Map<string, ExportMalicious[]>> {
    const rows = rowsOf(
      await this.deps.db.execute<
        Row<{
          identity_hash: string;
          id: string;
          package_name: string;
          sources: string[] | null;
          match_mode: string;
        }>
      >(sql`
        SELECT DISTINCT ON (c.identity_hash, mp.id)
               c.identity_hash, mp.id, mp.package_name, mp.sources, cm.match_mode
        FROM scan_component sc
        JOIN component c ON c.id = sc.component_id
        JOIN component_malicious cm ON cm.component_id = c.id
        JOIN malicious_package mp ON mp.id = cm.malicious_package_id
        WHERE sc.scan_id = ANY(${sql.param(scanIds)}::uuid[])
        ORDER BY c.identity_hash, mp.id
      `),
    );

    const byComponent = new Map<string, ExportMalicious[]>();
    for (const r of rows) {
      const list = byComponent.get(r.identity_hash) ?? [];
      list.push({
        id: r.id,
        packageName: r.package_name,
        sources: r.sources ?? [],
        matchMode: r.match_mode,
      });
      byComponent.set(r.identity_hash, list);
    }
    return byComponent;
  }
}
