import {
  acknowledgeMaliciousRequestSchema,
  attributeDefinitionSchema,
  bulkSearchBodySchema,
  changePasswordRequestSchema,
  confirmApplicationRequestSchema,
  createApiTokenSchema,
  createApplicationRequestSchema,
  createGroupRequestSchema,
  createIngestTokenRequestSchema,
  createSuppressionSchema,
  createUserRequestSchema,
  loginRequestSchema,
  mergeApplicationRequestSchema,
  oidcConnectionInputSchema,
  previewUserApplicationAccessSchema,
  resetUserPasswordRequestSchema,
  resolveAccessRequestSchema,
  setGroupMembersRequestSchema,
  setSignInMethodSchema,
  setUserApplicationAccessSchema,
  setUserEnvironmentsRequestSchema,
  testOidcConnectionSchema,
  updateApplicationRequestSchema,
  updateAttributeDefinitionSchema,
  updateGroupRequestSchema,
  updateMaliciousSettingsSchema,
  updatePlatformSettingsSchema,
  updateUserRequestSchema,
  verifySmtpSchema,
  xrayConnectionInputSchema,
} from "@sbom/shared";
import type { ZodTypeAny } from "zod";

/**
 * What each endpoint is, in one line, plus who may call it.
 *
 * This is the only hand-maintained half of the OpenAPI document; the route list itself comes
 * from Fastify's own table. The split is deliberate, and it is what keeps the document honest:
 * coverage cannot drift, because the collector sees whatever was registered, and a route with
 * no entry here fails `openapi-coverage.test.ts`. So an endpoint can be neither undocumented
 * nor documented-but-absent.
 *
 * ## What `auth` means
 *
 * - `public`   — no credential. The sign-in endpoints and the health probes.
 * - `session`  — a signed-in account, but *not* gated on the forced-password-change flag.
 *                Exactly three routes need this, and they are the three that let somebody
 *                clear that flag.
 * - `user`     — any signed-in account, by session cookie or personal API token.
 * - `admin`    — an account whose role is `admin`.
 * - `ingest`   — a CI ingest token, which is a different credential from a personal one: it
 *                belongs to an environment rather than a person and may only submit scans.
 *
 * ## What is deliberately not here
 *
 * Response schemas. The responses are TypeScript interfaces rather than Zod, so there is
 * nothing to convert — hand-writing a hundred of them would produce a second description of
 * the same shapes, free to drift from the first, which is the problem this file exists to
 * avoid. Status codes and their meanings are documented per operation; the response bodies are
 * described by the types in `@sbom/shared`, which the UI is built against.
 */

export type RouteAuth = "public" | "session" | "user" | "admin" | "ingest";

export interface RouteMeta {
  summary: string;
  tag: string;
  auth: RouteAuth;
  /** Request body, as the Zod schema the server actually validates with. */
  body?: ZodTypeAny;
  /** Longer note, where one line cannot carry the thing a caller will get wrong. */
  notes?: string;
}

/**
 * Keyed `METHOD /full/path`, with `:param` placeholders exactly as Fastify holds them.
 *
 * Grouped by tag rather than sorted, because the groups are how a reader navigates and a
 * single alphabetical list of a hundred and forty-six lines is not readable by anybody.
 */
export const ROUTE_CATALOG: Record<string, RouteMeta> = {
  // --- health ---------------------------------------------------------------
  "GET /health": {
    summary: "Liveness probe. Answers 200 as soon as the process is serving.",
    tag: "Health",
    auth: "public",
  },
  "GET /health/ready": {
    summary: "Readiness probe. Answers 200 only once the database is reachable.",
    tag: "Health",
    auth: "public",
    notes:
      "Distinct from /health on purpose: a container that is up but cannot reach Postgres is " +
      "live and not ready, and conflating the two makes a rolling deploy send traffic to it.",
  },

  // --- the document itself ---------------------------------------------------
  "GET /api/v1/openapi.json": {
    summary: "This document, as OpenAPI 3.0 JSON.",
    tag: "Reference",
    auth: "public",
    notes:
      "Public deliberately: it describes the API's shape, not its contents, and a developer " +
      "who cannot read it before authenticating cannot work out how to authenticate. Generated " +
      "from the server's own route table, so it cannot omit an endpoint or invent one.",
  },
  "GET /api/v1/docs": {
    summary: "A browsable reference, rendered from this document.",
    tag: "Reference",
    auth: "public",
    notes:
      "Self-contained HTML with no external request, because the deployment this is built for " +
      "is air-gapped and a CDN-loaded viewer renders a blank page there.",
  },

  // --- sign-in --------------------------------------------------------------
  "POST /api/v1/auth/login": {
    summary: "Exchange an email and password for a session cookie.",
    tag: "Authentication",
    auth: "public",
    body: loginRequestSchema,
    notes:
      "For scripts, prefer a personal API token: this sets a cookie, and a wrong password and " +
      "an unknown account deliberately return the same 401 so the form cannot be used to " +
      "enumerate who works here.",
  },
  "POST /api/v1/auth/logout": {
    summary: "End the calling session. Idempotent — 204 whether or not one existed.",
    tag: "Authentication",
    auth: "public",
  },
  "POST /api/v1/auth/logout-all": {
    summary: "End every session for the calling account, including this one.",
    tag: "Authentication",
    auth: "session",
  },
  "GET /api/v1/auth/me": {
    summary: "The calling account: id, email, role and whether a password change is pending.",
    tag: "Authentication",
    auth: "session",
  },
  "POST /api/v1/auth/change-password": {
    summary: "Change your own password, which also ends your other sessions.",
    tag: "Authentication",
    auth: "session",
    body: changePasswordRequestSchema,
  },
  "GET /api/v1/auth/oidc/enabled": {
    summary: "Whether single sign-on is offered. A boolean and nothing else.",
    tag: "Authentication",
    auth: "public",
    notes:
      "Anonymous by necessity — the sign-in page renders before anybody is authenticated — so " +
      "it never reveals the issuer, the client id or anything else about the directory.",
  },
  "GET /api/v1/auth/oidc/start": {
    summary: "Begin a directory sign-in. Redirects the browser to the provider.",
    tag: "Authentication",
    auth: "public",
    notes: "A browser navigation, not an API call: an XHR here is blocked by the provider.",
  },
  "GET /api/v1/auth/oidc/callback": {
    summary: "Where the provider returns. Verifies the token and issues a session.",
    tag: "Authentication",
    auth: "public",
  },

  // --- API access -----------------------------------------------------------
  "GET /api/v1/auth/api-access": {
    summary: "The API's base URL, the spec's address, and how many live tokens you hold.",
    tag: "API tokens",
    auth: "user",
  },
  "GET /api/v1/auth/api-tokens": {
    summary: "Your own API tokens. Never the secrets — only hashes are stored.",
    tag: "API tokens",
    auth: "user",
  },
  "POST /api/v1/auth/api-tokens": {
    summary: "Mint a token for yourself. The secret is returned exactly once.",
    tag: "API tokens",
    auth: "user",
    body: createApiTokenSchema,
    notes:
      "A token acts as its owner, resolved per request, so it can never exceed what the " +
      "account may already do. `scope: read` is the default and refuses every write.",
  },
  "DELETE /api/v1/auth/api-tokens/:id": {
    summary: "Revoke one of your own tokens. Takes effect on the next request.",
    tag: "API tokens",
    auth: "user",
  },
  "GET /api/v1/admin/api-tokens": {
    summary: "Every API token on the platform, with its owner, scope and last use.",
    tag: "API tokens",
    auth: "admin",
  },
  "DELETE /api/v1/admin/api-tokens/:id": {
    summary: "Revoke anybody's API token.",
    tag: "API tokens",
    auth: "admin",
  },

  // --- applications ---------------------------------------------------------
  "GET /api/v1/applications": {
    summary: "Applications in the current environment, paginated, filterable and sortable.",
    tag: "Applications",
    auth: "user",
    notes:
      "Scoped to the caller's environments and application grants. `search` matches the name " +
      "case-insensitively; `status` may be repeated to include inactive and unconfirmed ones.",
  },
  "GET /api/v1/applications/:id": {
    summary: "One application, with its current build, platform and attributes.",
    tag: "Applications",
    auth: "user",
  },
  "GET /api/v1/applications/:id/components": {
    summary: "Packages in the application's current build.",
    tag: "Applications",
    auth: "user",
  },
  "GET /api/v1/applications/:id/ecosystems": {
    summary: "Package counts per ecosystem for the current build.",
    tag: "Applications",
    auth: "user",
  },
  "GET /api/v1/applications/:id/scans": {
    summary: "Build history, newest first, badged by source.",
    tag: "Applications",
    auth: "user",
  },
  "GET /api/v1/applications/:id/removed-components": {
    summary: "Packages the current build dropped relative to the previous one.",
    tag: "Applications",
    auth: "user",
  },
  "GET /api/v1/applications/:id/diff": {
    summary: "Added, removed and changed packages between two builds.",
    tag: "Applications",
    auth: "user",
  },
  "GET /api/v1/applications/:id/vulnerabilities": {
    summary: "Findings for one application, split into application and base-image sides.",
    tag: "Vulnerabilities",
    auth: "user",
    notes:
      "Refused with 409 `vuln_scanning_disabled` while scanning is off, rather than returning " +
      "an empty list — an empty list would read as a clean bill of health.",
  },
  "GET /api/v1/applications/attribute-values/:key": {
    summary: "Distinct values in use for one attribute, for building a filter.",
    tag: "Applications",
    auth: "user",
  },
  "POST /api/v1/applications/:id/scans": {
    summary: "Upload an SBOM for this application by hand.",
    tag: "Scans",
    auth: "user",
    notes:
      "multipart/form-data with an `sbom` file part. A byte-identical re-upload is refused " +
      "with 409 unless `allow_duplicate=true`; the CI endpoint accepts duplicates instead.",
  },

  // --- scans ----------------------------------------------------------------
  "POST /api/v1/scans": {
    summary: "The CI ingest endpoint. Submit a CycloneDX SBOM for a build.",
    tag: "Scans",
    auth: "ingest",
    notes:
      "Authenticated by a CI ingest token, not a personal one. multipart/form-data with an " +
      "`sbom` file part and `app_name`; an unknown name auto-creates an unconfirmed " +
      "application rather than dropping the upload. 201 means durably stored.",
  },
  "GET /api/v1/scans/recent": {
    summary: "The most recent builds across the estate.",
    tag: "Scans",
    auth: "user",
  },
  "GET /api/v1/scans/:id": {
    summary: "One build, with its provenance, platform and tooling.",
    tag: "Scans",
    auth: "user",
  },
  "GET /api/v1/scans/:id/components": {
    summary: "Packages in one build.",
    tag: "Scans",
    auth: "user",
  },
  "GET /api/v1/scans/:id/ecosystems": {
    summary: "Package counts per ecosystem for one build.",
    tag: "Scans",
    auth: "user",
  },
  "GET /api/v1/scans/:id/raw": {
    summary: "The original SBOM as submitted, decompressed.",
    tag: "Scans",
    auth: "user",
    notes: "The stored bytes, not a re-rendering — so it round-trips to what the tool produced.",
  },
  "GET /api/v1/scans/:id/vulnerabilities": {
    summary: "Findings for one build.",
    tag: "Vulnerabilities",
    auth: "user",
  },

  // --- components -----------------------------------------------------------
  "GET /api/v1/components/search": {
    summary: "Find a package across the estate, by exact name or substring.",
    tag: "Components",
    auth: "user",
    notes:
      "`match=exact` is the default; `match=substring` is the one that finds `react` inside " +
      "`react-dom`. `scope=current` searches current builds, `historical` searches every build.",
  },
  "GET /api/v1/components/suggest": {
    summary: "Name completions for a partial package name.",
    tag: "Components",
    auth: "user",
  },
  "GET /api/v1/components/ecosystems": {
    summary: "Ecosystems present in the estate, for filter options.",
    tag: "Components",
    auth: "user",
  },
  "GET /api/v1/components/versions": {
    summary: "Versions of one package, and which applications ship each.",
    tag: "Components",
    auth: "user",
  },
  "POST /api/v1/components/bulk-search": {
    summary: "Look up many packages at once from a pasted list or purl set.",
    tag: "Components",
    auth: "user",
    body: bulkSearchBodySchema,
    notes:
      "Allowed to read-only tokens, unlike other POSTs: it is a search, and this is the " +
      "endpoint most API callers actually want. It stores the query so the result has a " +
      "shareable address, which is why the method is POST.",
  },
  "GET /api/v1/components/bulk-search": {
    summary: "Recently submitted bulk searches, so one can be reopened.",
    tag: "Components",
    auth: "user",
  },
  "GET /api/v1/components/bulk-search/:id": {
    summary: "The results of a previously submitted bulk search.",
    tag: "Components",
    auth: "user",
  },
  "GET /api/v1/components/bulk-search/:id/export.xlsx": {
    summary: "A bulk search's results as an Excel workbook.",
    tag: "Components",
    auth: "user",
  },

  // --- groups ---------------------------------------------------------------
  "GET /api/v1/groups": {
    summary: "Application groups in the current environment.",
    tag: "Groups",
    auth: "user",
  },
  "GET /api/v1/groups/:id": {
    summary: "One group and its member applications.",
    tag: "Groups",
    auth: "user",
  },
  "GET /api/v1/groups/:id/advisories": {
    summary: "Distinct advisories affecting a group's members.",
    tag: "Groups",
    auth: "user",
  },

  // --- environments ---------------------------------------------------------
  "GET /api/v1/environments": {
    summary: "Environments this account may read.",
    tag: "Environments",
    auth: "user",
    notes:
      "Environments are a hard partition: an application name is unique per environment, so " +
      "the same service in two estates is two independent records with separate findings.",
  },
  "GET /api/v1/environments/:id": {
    summary: "One environment, by id or by name.",
    tag: "Environments",
    auth: "user",
  },
  "GET /api/v1/admin/environments/comparison": {
    summary: "Every estate's figures side by side. Never summed.",
    tag: "Environments",
    auth: "admin",
  },
  "POST /api/v1/admin/environments": {
    summary: "Create an environment.",
    tag: "Environments",
    auth: "admin",
  },
  "PATCH /api/v1/admin/environments/:id": {
    summary: "Rename an environment or change its description.",
    tag: "Environments",
    auth: "admin",
  },
  "DELETE /api/v1/admin/environments/:id": {
    summary: "Delete an empty environment.",
    tag: "Environments",
    auth: "admin",
  },

  // --- dashboard & analytics ------------------------------------------------
  "GET /api/v1/dashboard/stats": {
    summary: "Estate totals: applications, scans, packages and staleness.",
    tag: "Dashboard",
    auth: "user",
  },
  "GET /api/v1/dashboard/ecosystems": {
    summary: "Package counts per ecosystem across the estate.",
    tag: "Dashboard",
    auth: "user",
  },
  "GET /api/v1/dashboard/platforms": {
    summary: "Which OS and language runtime each application currently ships.",
    tag: "Dashboard",
    auth: "user",
    notes:
      "Detected at ingest from Syft's distro markers and binary classifier, so it is " +
      "independent of which vulnerability scanner is selected.",
  },
  "GET /api/v1/dashboard/top-components": {
    summary: "The most widely deployed packages.",
    tag: "Dashboard",
    auth: "user",
  },
  "GET /api/v1/dashboard/vulnerabilities": {
    summary: "Estate vulnerability figures, split application versus base image.",
    tag: "Dashboard",
    auth: "user",
    notes:
      "Returns `vulnerabilities: null` when scanning is off, and the base-image half is null " +
      "when the active scanner holds no data for OS ecosystems. Never zeros.",
  },
  "GET /api/v1/dashboard/malicious": {
    summary: "Malicious-package exposure across the estate.",
    tag: "Dashboard",
    auth: "user",
  },
  "GET /api/v1/analytics/report": {
    summary: "The full analytics report: inventory, coverage, churn and exposure.",
    tag: "Analytics",
    auth: "user",
  },
  "GET /api/v1/analytics/report.pdf": {
    summary: "The same report, rendered as a PDF.",
    tag: "Analytics",
    auth: "user",
  },
  "GET /api/v1/analytics/coverage": {
    summary: "Scan coverage on its own: which applications are current, stale or unscanned.",
    tag: "Analytics",
    auth: "user",
  },

  // --- exports --------------------------------------------------------------
  "GET /api/v1/exports/applications/:id": {
    summary: "An application's current inventory as CycloneDX JSON.",
    tag: "Exports",
    auth: "user",
    notes:
      "The inventory flavour carries no `vulnerabilities` array at all, rather than an empty " +
      "one — an empty array would claim the document had been checked.",
  },
  "GET /api/v1/exports/scans/:id": {
    summary: "One build's inventory as CycloneDX JSON.",
    tag: "Exports",
    auth: "user",
  },
  "GET /api/v1/exports/groups/:id": {
    summary: "A group's combined inventory as CycloneDX JSON.",
    tag: "Exports",
    auth: "user",
  },
  "GET /api/v1/exports/applications/:id/vex": {
    summary: "An application's findings as a CycloneDX VEX document.",
    tag: "Exports",
    auth: "user",
  },
  "GET /api/v1/exports/scans/:id/vex": {
    summary: "One build's findings as a CycloneDX VEX document.",
    tag: "Exports",
    auth: "user",
  },
  "GET /api/v1/exports/groups/:id/vex": {
    summary: "A group's findings as a CycloneDX VEX document.",
    tag: "Exports",
    auth: "user",
  },

  // --- vulnerabilities ------------------------------------------------------
  "GET /api/v1/vulnerabilities": {
    summary: "Advisories affecting the estate, filterable by severity and scope.",
    tag: "Vulnerabilities",
    auth: "user",
  },
  "GET /api/v1/vulnerabilities/:vulnerabilityId": {
    summary: "One advisory, and everywhere it lands.",
    tag: "Vulnerabilities",
    auth: "user",
  },
  "GET /api/v1/vuln-status": {
    summary: "Whether scanning is on, which provider is active, and how fresh its data is.",
    tag: "Vulnerabilities",
    auth: "user",
    notes:
      "Stays readable at 200 whatever the state, so a client can tell 'switched off' from " +
      "'broken' rather than inferring it from a refusal.",
  },
  "GET /api/v1/malicious": {
    summary: "Known-malicious packages matched against the estate.",
    tag: "Malicious packages",
    auth: "user",
  },
  "GET /api/v1/malicious/:id": {
    summary: "One malicious package, its corroboration and where it was found.",
    tag: "Malicious packages",
    auth: "user",
  },
  "GET /api/v1/malicious-status": {
    summary: "Whether malicious-package matching is on, and how fresh the feed is.",
    tag: "Malicious packages",
    auth: "user",
  },

  // --- attributes -----------------------------------------------------------
  "GET /api/v1/attribute-definitions": {
    summary: "The attribute keys applications can carry, and their types.",
    tag: "Attributes",
    auth: "user",
  },
  "POST /api/v1/admin/attribute-definitions": {
    summary: "Define a new application attribute.",
    tag: "Attributes",
    auth: "admin",
    body: attributeDefinitionSchema,
  },
  "PATCH /api/v1/admin/attribute-definitions/:id": {
    summary: "Change an attribute's label, type or select options.",
    tag: "Attributes",
    auth: "admin",
    body: updateAttributeDefinitionSchema,
  },
  "DELETE /api/v1/admin/attribute-definitions/:id": {
    summary: "Remove an attribute definition.",
    tag: "Attributes",
    auth: "admin",
  },

  // --- admin: applications --------------------------------------------------
  "POST /api/v1/admin/applications": {
    summary: "Register an application before any scan arrives.",
    tag: "Admin: applications",
    auth: "admin",
    body: createApplicationRequestSchema,
  },
  "PATCH /api/v1/admin/applications/:id": {
    summary: "Change an application's name, status or attributes.",
    tag: "Admin: applications",
    auth: "admin",
    body: updateApplicationRequestSchema,
  },
  "DELETE /api/v1/admin/applications/:id": {
    summary: "Delete an application and its scan history.",
    tag: "Admin: applications",
    auth: "admin",
  },
  "POST /api/v1/admin/applications/:id/confirm": {
    summary: "Accept an auto-created application, optionally renaming it.",
    tag: "Admin: applications",
    auth: "admin",
    body: confirmApplicationRequestSchema,
  },
  "POST /api/v1/admin/applications/:id/merge": {
    summary: "Merge this application into another, moving its scan history.",
    tag: "Admin: applications",
    auth: "admin",
    body: mergeApplicationRequestSchema,
    notes:
      "The motivating case for the audit trail: scans move and the source is deleted, so " +
      "without a record 'where did this app go' is unanswerable.",
  },
  "POST /api/v1/admin/applications/:id/aliases": {
    summary: "Add an alias, so a differently-named CI job lands here.",
    tag: "Admin: applications",
    auth: "admin",
  },
  "DELETE /api/v1/admin/applications/:id/aliases/:aliasName": {
    summary: "Remove an alias.",
    tag: "Admin: applications",
    auth: "admin",
  },
  "POST /api/v1/admin/scans/backfill-sbom": {
    summary: "Re-extract stored SBOMs to fill in data added after they were ingested.",
    tag: "Admin: applications",
    auth: "admin",
  },
  "GET /api/v1/admin/scans/backfill-sbom": {
    summary: "How much of the estate still needs that backfill.",
    tag: "Admin: applications",
    auth: "admin",
  },
  "DELETE /api/v1/admin/scans/:id": {
    summary: "Delete one build and its stored SBOM.",
    tag: "Admin: applications",
    auth: "admin",
  },

  // --- admin: groups --------------------------------------------------------
  "POST /api/v1/admin/groups": {
    summary: "Create an application group.",
    tag: "Admin: groups",
    auth: "admin",
    body: createGroupRequestSchema,
  },
  "PATCH /api/v1/admin/groups/:id": {
    summary: "Rename a group or change its description.",
    tag: "Admin: groups",
    auth: "admin",
    body: updateGroupRequestSchema,
  },
  "PUT /api/v1/admin/groups/:id/members": {
    summary: "Replace a group's membership wholesale.",
    tag: "Admin: groups",
    auth: "admin",
    body: setGroupMembersRequestSchema,
  },
  "DELETE /api/v1/admin/groups/:id": {
    summary: "Delete a group. Its members are untouched.",
    tag: "Admin: groups",
    auth: "admin",
  },

  // --- admin: users and access ----------------------------------------------
  "GET /api/v1/admin/users": {
    summary: "Accounts, paginated, with role, status and live session count.",
    tag: "Admin: users",
    auth: "admin",
  },
  "GET /api/v1/admin/users/:id": {
    summary: "One account.",
    tag: "Admin: users",
    auth: "admin",
  },
  "POST /api/v1/admin/users": {
    summary: "Create an account. Returns a one-time password unless it is directory-backed.",
    tag: "Admin: users",
    auth: "admin",
    body: createUserRequestSchema,
  },
  "PATCH /api/v1/admin/users/:id": {
    summary: "Change an account's role or active status.",
    tag: "Admin: users",
    auth: "admin",
    body: updateUserRequestSchema,
  },
  "DELETE /api/v1/admin/users/:id": {
    summary: "Delete an account and end its sessions. Audit entries are kept.",
    tag: "Admin: users",
    auth: "admin",
  },
  "POST /api/v1/admin/users/:id/reset-password": {
    summary: "Issue a new password and end every session for that account.",
    tag: "Admin: users",
    auth: "admin",
    body: resetUserPasswordRequestSchema,
  },
  "POST /api/v1/admin/users/:id/sign-in-method": {
    summary: "Convert an account between a local password and the directory.",
    tag: "Admin: users",
    auth: "admin",
    body: setSignInMethodSchema,
    notes:
      "Refused for the last administrator who can sign in with a password: an outage at the " +
      "directory would otherwise lock everybody out of the page that explains the outage.",
  },
  "GET /api/v1/admin/users/:id/environments": {
    summary: "Which estates an account may read.",
    tag: "Admin: users",
    auth: "admin",
  },
  "PUT /api/v1/admin/users/:id/environments": {
    summary: "Replace an account's environment grants.",
    tag: "Admin: users",
    auth: "admin",
    body: setUserEnvironmentsRequestSchema,
  },
  "GET /api/v1/admin/users/:id/application-access": {
    summary: "Which groups and applications an account is narrowed to.",
    tag: "Admin: users",
    auth: "admin",
  },
  "PUT /api/v1/admin/users/:id/application-access": {
    summary: "Replace an account's group and application grants.",
    tag: "Admin: users",
    auth: "admin",
    body: setUserApplicationAccessSchema,
    notes:
      "The two axes compose by intersection: an application is visible when its estate is " +
      "granted AND a group or direct grant names it.",
  },
  "POST /api/v1/admin/users/:id/application-access/preview": {
    summary: "Score a candidate grant set without saving it.",
    tag: "Admin: users",
    auth: "admin",
    body: previewUserApplicationAccessSchema,
    notes:
      "Allowed to read-only tokens: it stores nothing. Returns the reachable applications with " +
      "the reason each is reachable, plus any held back by the environment axis.",
  },
  "GET /api/v1/admin/access-requests": {
    summary: "People the directory authenticated who have no account here.",
    tag: "Admin: users",
    auth: "admin",
    notes:
      "Carries `signOnEnabled`, because an empty queue means 'nobody was refused' only when " +
      "sign-on is on — with it off, nothing can ever arrive.",
  },
  "POST /api/v1/admin/access-requests/:id/resolve": {
    summary: "Mark a request dealt with, naming the account created for it.",
    tag: "Admin: users",
    auth: "admin",
    body: resolveAccessRequestSchema,
  },
  "POST /api/v1/admin/access-requests/:id/dismiss": {
    summary: "Set a request aside without creating anything.",
    tag: "Admin: users",
    auth: "admin",
  },

  // --- admin: platform ------------------------------------------------------
  "GET /api/v1/admin/settings": {
    summary: "Platform settings: the staleness threshold and related values.",
    tag: "Admin: platform",
    auth: "admin",
  },
  "PATCH /api/v1/admin/settings": {
    summary: "Change platform settings.",
    tag: "Admin: platform",
    auth: "admin",
    body: updatePlatformSettingsSchema,
  },
  "GET /api/v1/admin/audit-log": {
    summary: "The append-only record of admin writes, filterable by actor, action and target.",
    tag: "Admin: platform",
    auth: "admin",
    notes:
      "A write made with a personal API token records the token's name, so it is " +
      "distinguishable from one its owner made in the browser.",
  },
  "GET /api/v1/admin/errors": {
    summary: "Recent API failures, with the request shape but never its body.",
    tag: "Admin: platform",
    auth: "admin",
  },
  "GET /api/v1/admin/errors/summary": {
    summary: "Failure counts grouped by route and status.",
    tag: "Admin: platform",
    auth: "admin",
  },
  "DELETE /api/v1/admin/errors": {
    summary: "Clear the error log.",
    tag: "Admin: platform",
    auth: "admin",
  },
  "GET /api/v1/admin/ingest-tokens": {
    summary: "CI ingest tokens, with their estate and last use.",
    tag: "Admin: platform",
    auth: "admin",
  },
  "POST /api/v1/admin/ingest-tokens": {
    summary: "Mint a CI ingest token. The secret is returned once.",
    tag: "Admin: platform",
    auth: "admin",
    body: createIngestTokenRequestSchema,
    notes:
      "Bind it to an environment: a bound token cannot write into another estate, which makes " +
      "the pipeline unable to put a test build into production's inventory.",
  },
  "DELETE /api/v1/admin/ingest-tokens/:id": {
    summary: "Revoke a CI ingest token.",
    tag: "Admin: platform",
    auth: "admin",
  },
  "GET /api/v1/admin/auth/oidc": {
    summary: "The single sign-on connection. Never the client secret.",
    tag: "Admin: platform",
    auth: "admin",
  },
  "PUT /api/v1/admin/auth/oidc": {
    summary: "Save the single sign-on connection.",
    tag: "Admin: platform",
    auth: "admin",
    body: oidcConnectionInputSchema,
    notes: "Omit `clientSecret` to keep the stored one; it is never returned by any endpoint.",
  },
  "POST /api/v1/admin/auth/oidc/test": {
    summary: "Probe the provider and report which of the failures happened.",
    tag: "Admin: platform",
    auth: "admin",
    body: testOidcConnectionSchema,
  },

  // --- admin: scanning ------------------------------------------------------
  "GET /api/v1/admin/vuln/status": {
    summary: "Scanner state, database age, sweep progress and ecosystem coverage.",
    tag: "Admin: scanning",
    auth: "admin",
  },
  "GET /api/v1/admin/vuln/storage": {
    summary: "How much disk the vulnerability database occupies.",
    tag: "Admin: scanning",
    auth: "admin",
  },
  "GET /api/v1/admin/vuln/history": {
    summary: "Past database updates and their outcomes.",
    tag: "Admin: scanning",
    auth: "admin",
  },
  "PATCH /api/v1/admin/vuln/settings": {
    summary: "Turn scanning on or off, and set the update interval.",
    tag: "Admin: scanning",
    auth: "admin",
  },
  "POST /api/v1/admin/vuln/update": {
    summary: "Fetch the vulnerability database now.",
    tag: "Admin: scanning",
    auth: "admin",
  },
  "POST /api/v1/admin/vuln/import": {
    summary: "Install a vulnerability database from an uploaded archive, for an air-gapped host.",
    tag: "Admin: scanning",
    auth: "admin",
  },
  "POST /api/v1/admin/vuln/sweep": {
    summary: "Re-match every current build against the database now.",
    tag: "Admin: scanning",
    auth: "admin",
  },
  "GET /api/v1/admin/vuln/suppressions": {
    summary: "Accepted risks, and what each one covers.",
    tag: "Admin: scanning",
    auth: "admin",
  },
  "POST /api/v1/admin/vuln/suppressions": {
    summary: "Accept a risk, estate-wide or for one application or package version.",
    tag: "Admin: scanning",
    auth: "admin",
    body: createSuppressionSchema,
  },
  "PATCH /api/v1/admin/vuln/suppressions/:id": {
    summary: "Change a suppression's reason or expiry.",
    tag: "Admin: scanning",
    auth: "admin",
  },
  "DELETE /api/v1/admin/vuln/suppressions/:id": {
    summary: "Withdraw a suppression, so its findings count again.",
    tag: "Admin: scanning",
    auth: "admin",
  },
  "GET /api/v1/admin/vuln/provider": {
    summary: "Which scanner is active, and how to reach it. Never the token.",
    tag: "Admin: scanning",
    auth: "admin",
  },
  "PUT /api/v1/admin/vuln/provider": {
    summary: "Select the active scanner.",
    tag: "Admin: scanning",
    auth: "admin",
  },
  "PUT /api/v1/admin/vuln/provider/xray": {
    summary: "Save the JFrog Xray connection.",
    tag: "Admin: scanning",
    auth: "admin",
    body: xrayConnectionInputSchema,
  },
  "POST /api/v1/admin/vuln/provider/xray/test": {
    summary: "Probe Xray, and measure which ecosystems it actually covers.",
    tag: "Admin: scanning",
    auth: "admin",
    notes:
      "The coverage probe matters: Xray answers an ecosystem it holds no data for exactly as " +
      "it answers a clean package, so coverage is measured with known-vulnerable canaries " +
      "rather than assumed.",
  },
  "GET /api/v1/admin/malicious/settings": {
    summary: "Malicious-package feed settings.",
    tag: "Admin: scanning",
    auth: "admin",
  },
  "PATCH /api/v1/admin/malicious/settings": {
    summary: "Change the malicious-package feed settings.",
    tag: "Admin: scanning",
    auth: "admin",
    body: updateMaliciousSettingsSchema,
  },
  "GET /api/v1/admin/malicious/history": {
    summary: "Past feed updates and their outcomes.",
    tag: "Admin: scanning",
    auth: "admin",
  },
  "POST /api/v1/admin/malicious/update": {
    summary: "Fetch the malicious-package feed now.",
    tag: "Admin: scanning",
    auth: "admin",
  },
  "POST /api/v1/admin/malicious/acknowledgements": {
    summary: "Acknowledge a malicious-package match, with a reason.",
    tag: "Admin: scanning",
    auth: "admin",
    body: acknowledgeMaliciousRequestSchema,
  },
  "DELETE /api/v1/admin/malicious/acknowledgements/:id": {
    summary: "Withdraw an acknowledgement.",
    tag: "Admin: scanning",
    auth: "admin",
  },

  // --- admin: monthly report ------------------------------------------------
  "GET /api/v1/admin/reports/settings": {
    summary: "Monthly report settings: schedule, recipients and relay.",
    tag: "Admin: reports",
    auth: "admin",
    notes: "Recipients are returned as addresses here; the audit trail records only counts.",
  },
  "PUT /api/v1/admin/reports/settings": {
    summary: "Change the monthly report settings.",
    tag: "Admin: reports",
    auth: "admin",
  },
  "POST /api/v1/admin/reports/settings/verify": {
    summary: "Check the mail relay answers, without sending anything.",
    tag: "Admin: reports",
    auth: "admin",
    body: verifySmtpSchema,
  },
  "POST /api/v1/admin/reports/settings/test": {
    summary: "Send a test email now.",
    tag: "Admin: reports",
    auth: "admin",
  },
  "GET /api/v1/admin/reports": {
    summary: "Past report runs, with their period and delivery outcome.",
    tag: "Admin: reports",
    auth: "admin",
  },
  "GET /api/v1/admin/reports/:id": {
    summary: "One report run.",
    tag: "Admin: reports",
    auth: "admin",
  },
  "GET /api/v1/admin/reports/:id.pdf": {
    summary: "A report run's PDF.",
    tag: "Admin: reports",
    auth: "admin",
  },
  "POST /api/v1/admin/reports": {
    summary: "Generate a report for a period, or return the existing run for it.",
    tag: "Admin: reports",
    auth: "admin",
    notes:
      "Records whether a run already existed, so a scheduler retry in the trail does not read " +
      "as a second report to management.",
  },
  "POST /api/v1/admin/reports/:id/send": {
    summary: "Send a generated report to its distribution list.",
    tag: "Admin: reports",
    auth: "admin",
    notes: "A relay failure is 502, not 500: the platform worked and the relay did not.",
  },
};
