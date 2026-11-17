import { sql } from "drizzle-orm";
import type { FastifyInstance } from "fastify";
import {
  packageRefQuerySchema,
  versionCheckQuerySchema,
  type PackageRecommendation,
  type VersionCheck,
} from "@sbom/shared";
import { rowsOf, type Row } from "../../lib/rows.js";
import { parseOrThrow } from "../../lib/validate.js";
import { requireScope } from "../environments/scope.js";
import { chooseFix, withVersion } from "./fix-advisor.js";
import { packageKey, recommendedVersions } from "./recommend.js";

/**
 * A package URL for a package nobody here ships yet, so it can be put to the scanner.
 * Only the common ecosystems; null for the rest, which are then reported as not assessed.
 */
export function buildPurl(ecosystem: string, name: string, version: string): string | null {
  const v = encodeURIComponent(version);
  const eco = ecosystem.toLowerCase();
  switch (eco) {
    case "npm": {
      // @scope/name keeps its scope as the namespace, with the @ encoded.
      const scoped = /^@([^/]+)\/(.+)$/.exec(name);
      return scoped ? `pkg:npm/%40${scoped[1]}/${scoped[2]}@${v}` : `pkg:npm/${name}@${v}`;
    }
    case "maven": {
      const [group, artifact] = name.includes(":") ? name.split(":") : ["", name];
      return group ? `pkg:maven/${group}/${artifact}@${v}` : null;
    }
    case "pypi":
      return `pkg:pypi/${name.toLowerCase().replace(/[-_.]+/g, "-")}@${v}`;
    case "golang":
    case "go":
      return `pkg:golang/${name}@${version.startsWith("v") ? v : `v${v}`}`;
    case "nuget":
      return `pkg:nuget/${name}@${v}`;
    case "gem":
      return `pkg:gem/${name}@${v}`;
    case "cargo":
      return `pkg:cargo/${name}@${v}`;
    case "composer":
      return `pkg:composer/${name}@${v}`;
    default:
      return null;
  }
}

/**
 * The package page's vulnerability parts: the recommended version (the same one every action
 * plan uses), and "is this version safe to add?".
 */
export async function packageRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.addHook("preHandler", fastify.requireAuth);
  const { db, settings, fixAdvisor } = fastify.ctx;

  async function recommendation(environmentId: string, ecosystem: string, name: string) {
    const map = await recommendedVersions(db, environmentId, [{ ecosystem, name }], (p) => fixAdvisor.walkMany(p));
    return map.get(packageKey(ecosystem, name)) ?? null;
  }

  fastify.get("/packages/recommendation", async (request, reply) => {
    const { ecosystem, name } = parseOrThrow(packageRefQuerySchema, request.query, "Query");
    const scope = await requireScope(request);
    const rec = (await settings.vulnScanningEnabled()) ? await recommendation(scope.id, ecosystem, name) : null;
    const body: PackageRecommendation = {
      name,
      ecosystem,
      recommendedVersion: rec?.version ?? null,
      checked: rec?.checked ?? false,
      clears: rec?.clears ?? 0,
      withoutFix: rec?.withoutFix ?? 0,
    };
    return reply.send(body);
  });

  fastify.get(
    "/packages/check",
    // Can start the scanner, so it is bounded more tightly than an ordinary read.
    { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } },
    async (request, reply) => {
      const { ecosystem, name, version } = parseOrThrow(versionCheckQuerySchema, request.query, "Query");
      const scope = await requireScope(request);
      const base: Omit<VersionCheck, "status" | "advisories" | "message" | "databaseBuiltAt"> = {
        name,
        ecosystem,
        version,
        recommendedVersion: null,
      };
      if (!(await settings.vulnScanningEnabled())) {
        return reply.send({
          ...base,
          status: "unavailable",
          advisories: [],
          message: "Vulnerability scanning is switched off, so nothing can be checked.",
          databaseBuiltAt: null,
        } satisfies VersionCheck);
      }
      // The package's own purl from any build here, so the scanner sees it exactly as in an SBOM.
      const known = await db.execute<Row<{ purl: string }>>(sql`
        SELECT purl FROM component
         WHERE lower(ecosystem) = lower(${ecosystem}) AND lower(name) = lower(${name}) AND purl LIKE 'pkg:%'
         LIMIT 1
      `);
      const existing = rowsOf(known)[0]?.purl;
      const purl = existing ? withVersion(existing, version) : buildPurl(ecosystem, name, version);
      const recommendedVersion = (await recommendation(scope.id, ecosystem, name))?.version ?? null;
      if (!purl) {
        return reply.send({
          ...base,
          recommendedVersion,
          status: "not_assessed",
          advisories: [],
          message: `Packages of type "${ecosystem}" cannot be checked by name; check one that is in a build instead.`,
          databaseBuiltAt: null,
        } satisfies VersionCheck);
      }
      const result = await fixAdvisor.checkVersion({ name, ecosystem, version, purl });
      if (result.status !== "checked") {
        return reply.send({
          ...base,
          recommendedVersion,
          status: result.status,
          advisories: [],
          message: result.message,
          databaseBuiltAt: result.databaseBuiltAt,
        } satisfies VersionCheck);
      }
      const advisories = result.findings.map((f) => ({
        vulnerabilityId: f.vulnerabilityId,
        severity: f.severity,
        fixedIn: chooseFix(f.fixVersions, version),
      }));
      return reply.send({
        ...base,
        recommendedVersion,
        status: advisories.length === 0 ? "no_known" : "vulnerable",
        advisories,
        message: null,
        databaseBuiltAt: result.databaseBuiltAt,
      } satisfies VersionCheck);
    },
  );
}
