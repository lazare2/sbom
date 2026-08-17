import { chromium } from "playwright";
import { mkdirSync } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

/**
 * Drives the real UI in a headless browser and screenshots each view.
 *
 * Complements the smoke test rather than duplicating it: that one proves the API
 * contracts, this one proves the pages actually render them — a route that
 * returns perfect JSON to a component that crashes on it is still broken.
 *
 * Every console error, page error, failed request and 5xx is collected as a
 * problem, so a silent regression in a panel nobody looked at still fails.
 */

/*
 * Screenshot directory, resolved against the repo rather than the working directory.
 *
 * The default used to be `.`, which meant a bare `node scripts/ui-drive.mjs` scattered
 * fifty PNGs across whatever directory it was launched from — usually the repo root, where
 * they are untracked clutter that is easy to commit by accident. Defaulting to a path under
 * `var/` makes the harmless invocation the harmless one; an explicit argument still wins.
 */
const OUT =
  process.argv[2] ?? path.join(path.dirname(new URL(import.meta.url).pathname.slice(1)), "..", "var", "ui-shots");
const BASE = "http://127.0.0.1:5173";
const EMAIL = "admin@sbom.local";
const PASSWORD = "jTzq7I-Al4E96PmO";

// Suffixed so a re-run never collides with data a previous run left behind.
const SUFFIX = Math.random().toString(36).slice(2, 8);
const TEST_APP = `ui-drive-app-${SUFFIX}`;
const TEST_USER = `ui-drive-user-${SUFFIX}@sbom.local`;

mkdirSync(OUT, { recursive: true });

const problems = [];

function log(msg) {
  console.log(msg);
}

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: 1500, height: 950 },
  deviceScaleFactor: 1,
  // The analytics page's report link is a plain anchor with `download`, so the
  // browser has to be allowed to accept it — without this Playwright cancels the
  // transfer and the download event never carries a body.
  acceptDownloads: true,
});
const page = await context.newPage();

function watch(target, prefix = "") {
  // Requests that already received a response, so a later `requestfailed` on the
  // same request can be recognised as a teardown artifact rather than a failure.
  const answered = new WeakSet();

  target.on("console", (msg) => {
    if (msg.type() !== "error") return;
    // The unauthenticated /auth/me probe legitimately 401s before login, and the
    // browser logs that as a console error even though it is the expected answer.
    if (/401/.test(msg.text())) return;
    // Likewise the deliberate 403 while a temp-password session is gated.
    if (/403/.test(msg.text())) return;
    /*
     * The duplicate-SBOM 409 is driven on purpose in step 15c.
     *
     * Matched on the request URL rather than on the status alone: a blanket /409/
     * filter would also swallow a genuine conflict from anywhere else in the app,
     * and 409 is the status this codebase uses for real, reportable collisions
     * (duplicate application name, duplicate attribute key).
     */
    if (/409/.test(msg.text()) && /\/applications\/[0-9a-f-]+\/scans$/.test(msg.location()?.url ?? "")) {
      return;
    }
    problems.push(`${prefix}console.error: ${msg.text()}`);
  });

  target.on("pageerror", (err) => problems.push(`${prefix}pageerror: ${err.message}`));

  target.on("response", (res) => {
    answered.add(res.request());
    if (res.status() >= 500) problems.push(`${prefix}http ${res.status()}: ${res.url()}`);
  });

  target.on("requestfailed", (req) => {
    /**
     * Ignore a failure on a request that already got its response.
     *
     * Verified with a standalone probe: a `204 No Content` proxied by the Vite
     * dev server is delivered to `fetch()` intact and *then* reported as
     * ERR_ABORTED, because the proxy ends the connection in a way Chromium logs
     * as an abort. One request, one 204, one spurious failure. Flagging it would
     * mean every successful delete looks like a bug — the real defect this hook
     * exists to catch is a request that never completes at all.
     */
    if (answered.has(req)) return;
    problems.push(`${prefix}requestfailed: ${req.method()} ${req.url()} — ${req.failure()?.errorText}`);
  });
}
watch(page);

let shotIndex = 0;
async function shot(name) {
  shotIndex += 1;
  const file = path.join(OUT, `${String(shotIndex).padStart(2, "0")}-${name}.png`);
  await page.screenshot({ path: file, fullPage: false });
  log(`  screenshot -> ${path.basename(file)}`);
}

/**
 * `shot()` for the dark-mode pass, which runs on its own page object.
 *
 * Shares the one counter so the dark screenshots always sort after the light ones.
 * They used to be hardcoded as 24/25/26, which silently started colliding as soon
 * as a step was added earlier in the run.
 */
async function darkShot(target, name, options = {}) {
  shotIndex += 1;
  const file = path.join(OUT, `${String(shotIndex).padStart(2, "0")}-${name}.png`);
  await target.screenshot({ path: file, ...options });
  log(`  screenshot -> ${path.basename(file)}`);
}

async function expectText(text, label) {
  try {
    await page.getByText(text, { exact: false }).first().waitFor({ timeout: 8000 });
    log(`  OK   sees "${label ?? text}"`);
  } catch {
    problems.push(`missing expected text: "${text}"`);
    log(`  FAIL does not see "${label ?? text}"`);
  }
}

async function expectHidden(selectorText, label) {
  const count = await page.getByText(selectorText, { exact: false }).count();
  if (count > 0) {
    problems.push(`expected NOT to see: "${selectorText}"`);
    log(`  FAIL unexpectedly sees "${label ?? selectorText}"`);
  } else {
    log(`  OK   does not see "${label ?? selectorText}"`);
  }
}

async function login(target, email, password) {
  await target.getByLabel("Email").fill(email);
  await target.getByLabel("Password", { exact: true }).fill(password);
  await target.getByRole("button", { name: "Sign in" }).click();
}

// --- 1. login page ---------------------------------------------------------
log("1. login page");
await page.goto(`${BASE}/applications`, { waitUntil: "networkidle" });
if (!page.url().includes("/login")) problems.push(`expected redirect to /login, got ${page.url()}`);
else log(`  OK   redirected to ${page.url().replace(BASE, "")}`);
await expectText("Sign in");
await expectHidden("Forgot your password", "a forgot-password link that no longer exists");
await shot("login");

// --- 2. wrong password ------------------------------------------------------
log("2. wrong password shows a generic error");
await login(page, EMAIL, "wrong-password-here");
await expectText("Invalid email or password", "generic auth error");
await shot("login-error");

// --- 3. real login ---------------------------------------------------------
log("3. sign in");
await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
await page.getByRole("button", { name: "Sign in" }).click();
await page.waitForURL(/\/applications/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("payments-api");
await expectText("Unconfirmed", "unconfirmed status badge");
await expectText("Stale", "stale badge");
await shot("applications-list");

// --- 4. dashboard ----------------------------------------------------------
log("4. dashboard overview");
await page.getByRole("link", { name: "Overview" }).click();
await page.waitForURL(`${BASE}/`, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("Applications");
await expectText("Most widely deployed packages");
await expectText("Ecosystem mix");
await expectText("Recent scans");
await expectText("Awaiting confirmation");
await shot("dashboard");

log("5. a dashboard tile links into a filtered list");
await page.getByRole("link", { name: /Stale/ }).first().click();
await page.waitForURL(/staleOnly=true/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("notification-relay", "the stale application");
await shot("dashboard-stale-drilldown");

// --- 6. filters ------------------------------------------------------------
log("6. filter and search on the applications list");
await page.goto(`${BASE}/applications`, { waitUntil: "networkidle" });
await page.getByLabel("Search by name").fill("payments");
await page.waitForTimeout(700);
await page.waitForLoadState("networkidle");
await expectText("payments-worker");
await shot("applications-search");

// --- 7. application detail -------------------------------------------------
log("7. application detail");
await page.getByRole("link", { name: "payments-api" }).first().click();
await page.waitForURL(/\/applications\/[0-9a-f-]+/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("Attributes");
await expectText("Current components");
await expectText("log4j-core");
await expectText("critical", "severity attribute value");
await expectText("Edit application", "admin-only edit affordance");
await shot("application-detail");

// --- 8. what changed in the latest build -----------------------------------
log("8. latest build changes (diff)");
await page.getByRole("tab", { name: "Latest build changes" }).click();
await page.waitForLoadState("networkidle");
await page.waitForTimeout(500);
await expectText("Comparing builds");
await expectText("unchanged");
await shot("application-diff");

// --- 9. packages no longer used --------------------------------------------
log("9. packages no longer in the current build");
await page.getByRole("tab", { name: "No longer used" }).click();
await page.waitForLoadState("networkidle");
await page.waitForTimeout(500);
await expectText("Packages no longer in the current build");
// The demo data upgrades log4j-core 2.14.1 -> 2.24.1, so the old version must
// appear here with the build it was last seen in. This is the whole reason the
// platform retains scan history.
await expectText("2.14.1", "the dropped log4j version");
await expectText("build", "the last-seen build reference");
await shot("application-removed");

log("10. hiding version upgrades narrows the list");
await page.getByLabel("Hide version upgrades").click();
await page.waitForURL(/ignoreVersion=true/, { timeout: 5000 });
await page.waitForLoadState("networkidle");
await page.waitForTimeout(500);
await expectText("Showing only packages with no remaining version");
await shot("application-removed-ignore-version");

// --- 11. scan history + detail ---------------------------------------------
log("11. scan history and a historical build");
await page.getByRole("tab", { name: /Scan history/ }).click();
await page.waitForLoadState("networkidle");
await page.waitForTimeout(400);
await expectText("Retained permanently", "retention note");
await expectText("Upload SBOM", "the manual upload affordance");
await shot("scan-history");

// The modal is opened and screenshotted here but deliberately NOT submitted:
// payments-api's current build is what steps 7-10 above asserted against, and a
// real upload would replace it. The full upload flow runs later against the
// application created in the admin section, which starts with no scans at all.
log("11b. the manual upload dialog");
await page.getByRole("button", { name: "Upload SBOM" }).click();
await page.waitForTimeout(400);
await expectText("it becomes the current build", "the warning that this replaces current state");
await expectText("CycloneDX JSON file");
await expectText("Why is this being uploaded by hand?");
await shot("scan-upload-dialog");
await page.getByRole("button", { name: "Cancel" }).click();
await page.waitForTimeout(300);

const scanLinks = page.locator('a[href^="/scans/"]');
const scanCount = await scanLinks.count();
log(`  found ${scanCount} scan links`);
await scanLinks.nth(scanCount - 1).click();
await page.waitForURL(/\/scans\/[0-9a-f-]+/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("Build provenance");
await expectText("SBOM SHA-256");
await expectText("Components in this build");
await shot("scan-detail");

// --- 12. compare two arbitrary builds --------------------------------------
log("12. compare-builds page");
const compare = page.getByRole("button", { name: "Compare with previous" });
if ((await compare.count()) > 0) {
  await compare.click();
  await page.waitForURL(/\/diff\?/, { timeout: 10000 });
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(500);
  await expectText("Compare builds");
  await expectText("From (earlier build)");
  await shot("scan-compare");
} else {
  log("  skip  this scan is the first build, so there is nothing to compare");
}

// --- 13. global package search ---------------------------------------------
log("13. global search, previously-used scope");
await page.getByRole("link", { name: "Package search" }).click();
await page.waitForURL(/\/search/, { timeout: 10000 });
await page.getByLabel("Package name").fill("log4j-core");
await page.waitForTimeout(800);
await page.waitForLoadState("networkidle");
await page.getByRole("radio", { name: "Previously used, not now" }).click();
await page.waitForTimeout(800);
await page.waitForLoadState("networkidle");
await expectText("removed", "removed badge");
await expectText("2.14.1", "the dropped version");
await shot("search-historical");

// --- 13b. analytics --------------------------------------------------------
log("13b. analytics page");
await page.getByRole("link", { name: "Analytics" }).click();
await page.waitForURL(/\/analytics/, { timeout: 15000 });
await page.waitForLoadState("networkidle");
await expectText("scan coverage", "the coverage qualifier above the totals");
await expectText("Top 10 most widely deployed packages");
await expectText("applications by package count");
await expectText("Dependency churn, last 30 days");
await expectText("Version fragmentation");
await expectText("New to the estate, last 30 days");
await expectText("Coverage gaps");
await expectText("Language runtimes");
await expectText("How to read this page");
// The one claim the page must make about itself.
/*
 * Asserted on a claim that holds in both states.
 *
 * The first methodology item tracks the feature flag — it says "no vulnerability data"
 * when scanning is off and describes the Grype source when it is on — and this step runs
 * before step 22 enables it. Pinning either wording here would make the assertion depend
 * on the order of the run, and on whatever the previous run happened to leave behind.
 */
await expectText("most recent scan", "the current-build definition in the methodology");
await shot("analytics");

log("13c. the reporting window is URL state, and churn responds to it");
await page.getByRole("button", { name: "7 days" }).click();
await page.waitForURL(/periodDays=7/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("Dependency churn, last 7 days");
await shot("analytics-7-days");

log("13d. an analytics row drills into a filtered list");
// Scroll it into view first: the platform tables are below the fold, and a
// click on an off-screen row is not the interaction a reader would have.
const nodeRow = page.getByRole("link", { name: "Node.js" }).first();
await nodeRow.scrollIntoViewIfNeeded();
await nodeRow.click();
await page.waitForURL(/runtime=node/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("Runs on", "the platform column on the filtered list");
await shot("analytics-runtime-drilldown");

log("13e. the PDF report downloads");
await page.goBack();
await page.waitForLoadState("networkidle");
const download = await Promise.all([
  page.waitForEvent("download", { timeout: 30000 }),
  page.getByRole("link", { name: "Download PDF" }).click(),
]).then(([d]) => d);
const pdfPath = path.join(OUT, "estate-report.pdf");
await download.saveAs(pdfPath);
const pdfBytes = await fs.readFile(pdfPath);
if (!pdfBytes.subarray(0, 5).toString().startsWith("%PDF-")) {
  problems.push(`downloaded report is not a PDF (${pdfBytes.length} bytes)`);
  log("  FAIL downloaded file is not a PDF");
} else {
  log(`  OK   downloaded ${download.suggestedFilename()} (${pdfBytes.length} bytes)`);
}
if (!/^sbom-estate-report-\d{4}-\d{2}-\d{2}\.pdf$/.test(download.suggestedFilename())) {
  problems.push(`unexpected download filename: ${download.suggestedFilename()}`);
}

// --- 13f. bulk package list search ------------------------------------------
/*
 * Reached from the package search tab's own mode toggle rather than from a shortcut on the
 * analytics page. The shortcut was removed: a list check answers "are we exposed to these
 * specific things", which belongs with search, not with estate reporting.
 */
log("13f. the package list search is reachable from the search tab");
await page.getByRole("link", { name: "Package search" }).click();
await page.waitForURL(/\/search/, { timeout: 10000 });
await page.getByRole("button", { name: "A list" }).click();
await page.waitForURL(/mode=list/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("Paste a package list");
await expectText("Search a list of packages", "the empty state before anything is pasted");
await shot("bulk-empty");

log("13g. searching a mixed-format list");
// Every accepted input form, plus deliberate misses. The seeded estate has
// express, lodash and log4j-core; the rest should come back as not found.
const BULK_LIST = [
  "# advisory batch",
  "express",
  "express@0.0.0-never-shipped",
  "lodash",
  "log4j-core",
  "django>=4.2",
  "pkg:npm/lodash@4.17.21",
  "@wb-track/shared-front",
  "logaas",
  "cnapp-ui",
  "keyv@6.0.0",
  "this is not a package at all",
].join("\n");

await page.locator("#bulk-input").fill(BULK_LIST);
await page.getByRole("button", { name: "Search list" }).click();
// Submitting registers the list and navigates to its shareable address.
await page.waitForURL(/\/search\/list\/[0-9a-f-]{36}/, { timeout: 15000 });
await page.waitForLoadState("networkidle");
const listUrl = page.url();
log(`  OK   navigated to a shareable list URL`);

await expectText("Packages searched");
await expectText("in use", "the in-use verdict");
await expectText("not found", "the not-found verdict");
// The distinction the feature exists for: present, but not at the version asked.
await expectText("other version", "the wrong-version verdict");
// A line that could not be parsed must be reported, not silently dropped.
await expectText("not understood", "the unparsed-line warning");
await expectText("matched across all versions", "the dropped-range notice");
await shot("bulk-results");

log("13h. the flat by-application view");
await page.getByRole("button", { name: "By application" }).click();
await page.waitForURL(/view=matches/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("Last seen in", "the shared hits table");
await shot("bulk-matches");

log("13i. the list URL is shareable");
// Reload from the bare URL: a colleague opening this link must get the results
// and the original text back, not an empty box.
await page.goto(listUrl, { waitUntil: "networkidle" });
const restored = await page.locator("#bulk-input").inputValue();
if (!restored.includes("@wb-track/shared-front")) {
  problems.push("a shared list URL did not repopulate the input");
  log("  FAIL shared URL lost the pasted list");
} else {
  log("  OK   shared URL restored the pasted list");
}

log("13j. the Excel export downloads");
const xlsx = await Promise.all([
  page.waitForEvent("download", { timeout: 30000 }),
  page.getByRole("link", { name: "Download Excel" }).click(),
]).then(([d]) => d);
const xlsxPath = path.join(OUT, "package-list.xlsx");
await xlsx.saveAs(xlsxPath);
const xlsxBytes = await fs.readFile(xlsxPath);
// A real workbook is a ZIP container, not a CSV wearing an .xlsx name.
if (xlsxBytes[0] !== 0x50 || xlsxBytes[1] !== 0x4b) {
  problems.push(`downloaded workbook is not a zip container (${xlsxBytes.length} bytes)`);
  log("  FAIL downloaded file is not a real .xlsx");
} else {
  log(`  OK   downloaded ${xlsx.suggestedFilename()} (${xlsxBytes.length} bytes)`);
}
if (!/^package-list-\d{4}-\d{2}-\d{2}\.xlsx$/.test(xlsx.suggestedFilename())) {
  problems.push(`unexpected workbook filename: ${xlsx.suggestedFilename()}`);
}

log("13k. recent lists are offered on a fresh list search");
await page.goto(`${BASE}/search?mode=list`, { waitUntil: "networkidle" });
await expectText("Recent lists");
await shot("bulk-recent-lists");

log("13l. switching back to single-package mode");
await page.getByRole("button", { name: "One package" }).click();
await page.waitForLoadState("networkidle");
await expectText("Package name", "the single-search form");
// Mode is not carried in the URL once single is selected, and the list state must
// not leak across.
await expectHidden("Paste a package list", "the list form after switching away");

// --- 14. admin: applications ------------------------------------------------
log("14. admin panel, applications");
await page.getByRole("link", { name: "Admin", exact: true }).click();
await page.waitForURL(/\/admin\/applications/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("Administration");
await expectText("Register application");
await shot("admin-applications");

log("15. register an application");
await page.getByRole("button", { name: "Register application" }).click();
await page.getByLabel("Name", { exact: true }).fill(TEST_APP);
// Attribute inputs are rendered from the definitions, not hardcoded — filling
// one proves that indirection actually works end to end.
await page.getByLabel("Squad").fill("platform");
await page.getByLabel("Severity").selectOption("high");
await shot("admin-create-application");
await page.getByRole("button", { name: "Create application" }).click();
await page.waitForTimeout(1200);
await page.waitForLoadState("networkidle");
/*
 * Filtered to the new application before asserting it exists.
 *
 * The admin list is paginated and sorted, so whether a freshly created record
 * lands on the first page depends on its random name suffix. Asserting against the
 * unfiltered list passed for a long time and then started failing — not because
 * creation broke, but because that run drew a suffix that sorted onto page two.
 */
await page.getByLabel("Search applications").fill(TEST_APP);
await page.waitForTimeout(900);
await page.waitForLoadState("networkidle");
await expectText(TEST_APP, "the newly registered application");
await shot("admin-application-created");

// --- 15b. manual SBOM upload, end to end ------------------------------------
/*
 * Driven against the application just registered rather than a demo one, because
 * it has no scans yet. That covers the case the feature most has to work for — an
 * application whose pipeline is not wired up — and it exercises the empty-history
 * state, the first-build path, and the duplicate guard without disturbing any
 * demo data the earlier assertions depend on.
 */
log("15b. upload an SBOM by hand for the new application");
// In the OS temp dir, not OUT: a run that dies mid-flight would otherwise leave a
// JSON file sitting in the screenshots folder looking like output.
const uploadFixture = path.join(os.tmpdir(), `ui-drive-upload-${SUFFIX}.cdx.json`);
await fs.writeFile(
  uploadFixture,
  JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      tools: { components: [{ type: "application", name: "syft", version: "1.18.1" }] },
      component: { type: "container", name: `local/${TEST_APP}:1.0.0` },
    },
    components: [
      {
        type: "operating-system",
        name: "alpine",
        version: "3.20.3",
        properties: [
          { name: "syft:distro:id", value: "alpine" },
          { name: "syft:distro:versionID", value: "3.20.3" },
        ],
      },
      { type: "library", name: "express", version: "4.19.2", purl: "pkg:npm/express@4.19.2" },
      { type: "library", name: "lodash", version: "4.17.21", purl: "pkg:npm/lodash@4.17.21" },
    ],
  }),
  "utf8",
);

// The list is already filtered to TEST_APP by the step above, so this row lookup is
// deterministic rather than dependent on where the record sorted.
await page
  .locator("tbody tr", { hasText: TEST_APP })
  .locator('a[href^="/applications/"]')
  .first()
  .click();
await page.waitForURL(/\/applications\/[0-9a-f-]+/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await page.getByRole("tab", { name: /Scan history/ }).click();
await page.waitForLoadState("networkidle");
await page.waitForTimeout(400);
await expectText("No scans recorded", "the empty-history state");
await expectText("you can upload one now", "the empty state pointing at the upload button");

await page.getByRole("button", { name: "Upload SBOM" }).click();
await page.waitForTimeout(400);
await page.setInputFiles("#sbom-file", uploadFixture);
await page.getByLabel("Build number").fill("manual-1");
await page.getByLabel("Branch").fill("main");
await page
  .getByLabel("Why is this being uploaded by hand?")
  .fill("pipeline not wired up yet; scanned the release image locally");
await shot("scan-upload-filled");

// Scoped to the dialog: the card header's opener button carries the same label,
// and an unscoped locator would be a strict-mode violation while the modal is up.
await page.locator("dialog").getByRole("button", { name: "Upload SBOM" }).click();
await page.waitForTimeout(1500);
await expectText("SBOM uploaded", "the upload receipt");
await expectText("Yes — this scan", "confirmation that it became the current build");
await expectText("View the scan", "the link to the stored scan");
await shot("scan-upload-receipt");
await page.getByRole("button", { name: "Done" }).click();
await page.waitForTimeout(1200);
await page.waitForLoadState("networkidle");

// The history table must now show the build, badged as a manual upload.
await expectText("manual-1", "the uploaded build number");
await expectText("current", "the new scan marked as the current build");
// Located by the badge's own tooltip rather than by the word "manual", which the
// build number "manual-1" would satisfy on its own — a match that would pass even
// if the badge were missing entirely.
const manualBadge = page.locator('[title^="Uploaded manually"]');
if ((await manualBadge.count()) === 0) {
  problems.push("scan history does not badge the manually uploaded scan");
  log("  FAIL no manual-source badge in the scan history");
} else {
  log("  OK   sees the manual-source badge");
}
await shot("scan-history-after-upload");

log("15c. the duplicate guard refuses the same file twice");
await page.getByRole("button", { name: "Upload SBOM" }).click();
await page.waitForTimeout(400);
await page.setInputFiles("#sbom-file", uploadFixture);
await page.locator("dialog").getByRole("button", { name: "Upload SBOM" }).click();
await page.waitForTimeout(1500);
await expectText("already has this exact SBOM", "the duplicate warning");
await expectText("Upload anyway", "the explicit override");
await shot("scan-upload-duplicate");
await page.getByRole("button", { name: "Cancel" }).click();
await page.waitForTimeout(300);

// Not left behind in the screenshots directory, where it would look like output.
await fs.unlink(uploadFixture);

log("15d. the uploaded scan reads as a normal build");
await page.locator('a[href^="/scans/"]').first().click();
await page.waitForURL(/\/scans\/[0-9a-f-]+/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("Build provenance");
await expectText("Uploaded by", "the uploader field replacing the ingest token");
await expectText(EMAIL, "the uploader's identity");
await expectText("Reason given for the manual upload");
await expectText("Components in this build");
await expectText("lodash", "a package from the uploaded SBOM");
await shot("scan-detail-manual");

// Back to the admin panel for the remaining steps.
await page.getByRole("link", { name: "Admin", exact: true }).click();
await page.waitForURL(/\/admin\/applications/, { timeout: 10000 });
await page.waitForLoadState("networkidle");

// --- 16. admin: attributes --------------------------------------------------
log("16. admin panel, attributes");
await page.getByRole("link", { name: "Attributes" }).click();
await page.waitForURL(/\/admin\/attributes/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("Application attributes");
await expectText("squad");
await expectText("Choice from a list", "the severity attribute's type");
await shot("admin-attributes");

// --- 17. admin: users -------------------------------------------------------
log("17. admin panel, users");
await page.getByRole("link", { name: "Users" }).click();
await page.waitForURL(/\/admin\/users/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("Accounts");
await expectText(EMAIL);
await expectText("you", "the self badge");
await shot("admin-users");

log("18. create an account and reveal its one-time password");
await page.getByRole("button", { name: "New account" }).click();
await page.getByLabel("Sign-in identifier").fill(TEST_USER);
await page.getByRole("button", { name: "Create account" }).click();
await page.waitForTimeout(1200);
await expectText("Shown once and never again", "the one-time-password warning");
await expectText(`Password for ${TEST_USER}`);
await shot("admin-user-created");
await page.getByRole("button", { name: "Done" }).click();
await page.waitForTimeout(800);
await page.waitForLoadState("networkidle");
await expectText("temp password", "the must-change-password badge");
await shot("admin-users-after-create");

// --- 19. admin: pending queue ----------------------------------------------
log("19. admin panel, pending confirmation queue");
await page.getByRole("link", { name: /Awaiting confirmation/ }).click();
await page.waitForURL(/\/admin\/pending/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("Applications awaiting confirmation");
await expectText("risk-scoring-svc", "the seeded unconfirmed application");
await shot("admin-pending");

log("20. the merge dialog offers once vs. always");
await page.getByRole("button", { name: "Merge" }).first().click();
await page.waitForTimeout(500);
await expectText("Always merge");
await expectText("Just this once");
await expectText("Records a permanent alias");
await shot("admin-merge-dialog");
await page.getByRole("button", { name: "Cancel" }).click();
await page.waitForTimeout(400);

// --- 21. admin: CI tokens ---------------------------------------------------
log("21. admin panel, CI tokens");
await page.getByRole("link", { name: "CI tokens" }).click();
await page.waitForURL(/\/admin\/tokens/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("CI ingest tokens");
// Env-configured tokens must be listed, or an operator is told "no tokens" on a
// deployment where CI is authenticating perfectly well.
await expectText("environment", "the env-sourced token badge");
await shot("admin-tokens");

// --- 22. admin: audit log ---------------------------------------------------
log("22. admin panel, audit log");
await page.getByRole("link", { name: "Audit log" }).click();
await page.waitForURL(/\/admin\/audit/, { timeout: 10000 });
await page.waitForLoadState("networkidle");
await expectText("Audit log");
await expectText("Registered application", "the create entry from step 15");
await expectText("Created account", "the create entry from step 18");
await expectText(EMAIL, "the actor");
await shot("admin-audit");

// --- 22b. vulnerability scanning ---------------------------------------------
/*
 * Drives the feature through the real UI, including the state that matters most: with
 * scanning off there must be NO vulnerability nav item and no cards, because an empty
 * vulnerability panel reads as "no vulnerabilities" for an estate nobody assessed.
 *
 * The run leaves the flag exactly as it found it.
 */
log("22b. vulnerability scanning admin panel");
await page.goto(`${BASE}/admin/vulnerabilities`, { waitUntil: "networkidle" });
await page.waitForTimeout(1200);
await expectText("Vulnerability scanning");
await expectText("Scanner", "the binary status card");
await expectText("Vulnerability database");
await expectText("Match coverage");
await expectText("Update history");
await expectText("Accepted risks");
// The panel must say where the binary was found, or where it looked if it was not.
await expectText("Update source", "the exact listing URL");
await shot("admin-vuln-scanning");

const enableBox = page.getByLabel("Enable Grype scan");
const wasEnabled = (await enableBox.count()) === 0;
log(`  scanning was ${wasEnabled ? "already enabled" : "disabled"}`);

if (!wasEnabled) {
  // With it off, the nav must not offer a Vulnerabilities link at all.
  await page.goto(`${BASE}/`, { waitUntil: "networkidle" });
  await page.waitForTimeout(600);
  const navWhenOff = await page.getByRole("link", { name: "Vulnerabilities" }).count();
  if (navWhenOff !== 0) {
    problems.push("the Vulnerabilities nav item is shown while scanning is disabled");
    log("  FAIL nav item present while disabled");
  } else {
    log("  OK   no vulnerability nav item while disabled");
  }

  // And the page itself must explain rather than show zeros.
  await page.goto(`${BASE}/vulnerabilities`, { waitUntil: "networkidle" });
  await page.waitForTimeout(600);
  await expectText("are not available", "the not-assessed notice");
  await expectText("not a clean result", "the explicit disclaimer");
  await shot("vuln-disabled-notice");

  log("22c. enable scanning and wait for the sweep");
  await page.goto(`${BASE}/admin/vulnerabilities`, { waitUntil: "networkidle" });
  await page.getByLabel("Enable Grype scan").click();
  await page.waitForTimeout(2500);
}

// Wait for coverage to reach 100% (or give up and report, rather than hanging).
let swept = false;
for (let attempt = 0; attempt < 25; attempt += 1) {
  await page.goto(`${BASE}/admin/vulnerabilities`, { waitUntil: "networkidle" });
  await page.waitForTimeout(1000);
  const body = await page.locator("body").innerText();
  if (/\(100%\)/.test(body)) {
    swept = true;
    break;
  }
  await page.waitForTimeout(3000);
}
log(`  sweep complete: ${swept}`);

if (swept) {
  await page.goto(`${BASE}/vulnerabilities`, { waitUntil: "networkidle" });
  await page.waitForTimeout(1200);
  await expectText("advisories", "the advisory count");
  await shot("vuln-search");

  // The CVE-by-alias path: grype reports log4shell under a GHSA id.
  log("22d. search by CVE number");
  // log4j 2.14.1 was upgraded away in the demo estate, so it is only reachable with
  // dropped packages included — which is also the realistic shape of this question when
  // someone checks historical exposure to an old CVE.
  await page.getByLabel("Include dropped packages").click();
  await page.waitForTimeout(600);
  await page.getByLabel("Search advisories").fill("CVE-2021-44228");
  await page.waitForTimeout(1800);
  await page.waitForLoadState("networkidle");
  const advisoryLink = page.locator('a[href^="/vulnerabilities/"]').first();
  if ((await advisoryLink.count()) > 0) {
    await advisoryLink.click();
    await page.waitForURL(/\/vulnerabilities\/.+/, { timeout: 10000 });
    await page.waitForLoadState("networkidle");
    await expectText("Advisory");
    await expectText("Also known as", "the alias field that makes CVE search work");
    await shot("vuln-advisory-detail");
  } else {
    log("  note: no advisory matched CVE-2021-44228 in this estate");
  }

  log("22e. overview and analytics carry the vulnerability sections");
  await page.goto(`${BASE}/`, { waitUntil: "networkidle" });
  await page.waitForTimeout(1200);
  await expectText("Most vulnerable applications");
  await expectText("Most vulnerable packages in use");
  // The combined total, then the split that explains it. All three have to be present:
  // the total alone would be a base-image-age figure wearing a dependency label.
  await expectText("vulnerability findings in total");
  await expectText("Application dependencies");
  await expectText("Base image and runtimes");
  // The merged column, so the pair reads as a pair rather than two addable numbers.
  await expectText("Findings (app / base image)");
  await shot("overview-with-vulnerabilities");

  await page.goto(`${BASE}/analytics`, { waitUntil: "networkidle" });
  await page.waitForTimeout(2000);
  await expectText("Base image exposure");
  await expectText("vulnerability findings in total");
  await shot("analytics-with-vulnerabilities");

  // --- 22e-2. the dashboard filter ------------------------------------------
  /*
   * The filter is the part with the most ways to mislead, so it is driven rather than just
   * rendered. Three properties are checked: the URL carries it (a filtered dashboard has to
   * survive being pasted into a ticket), the page says it is filtered, and an excluded
   * scope reads as excluded rather than as zero findings.
   */
  log("22e-2. filtering by severity");
  await page.getByRole("group", { name: "Severity" }).getByRole("button", { name: "High" }).click();
  await page.waitForURL(/severity=high/, { timeout: 10000 });
  await page.waitForTimeout(1800);
  await expectText("Filtered:", "the banner naming the active filter");
  await expectText("Unfiltered, for reference", "what the figures were narrowed from");
  await shot("analytics-filtered-severity");

  log("22e-3. filtering to application dependencies only");
  await page.getByRole("group", { name: "Package scope" }).getByRole("button", { name: "App deps" }).click();
  await page.waitForURL(/scope=app/, { timeout: 10000 });
  await page.waitForTimeout(1800);
  // Excluded, not zero. This is the invariant the whole feature is built around, one level
  // down from the feature flag.
  await expectText("Excluded by the current filter", "the base-image panel under an app-only filter");
  if (await page.getByText("Base image exposure").isVisible().catch(() => false)) {
    problems.push("base image exposure card rendered while excluded by the scope filter");
  } else {
    log("  OK   base-image exposure card dropped rather than shown empty");
  }
  await shot("analytics-filtered-scope");

  log("22e-4. clearing the filter");
  await page.getByRole("button", { name: "Clear filter" }).click();
  await page.waitForTimeout(1800);
  if (/severity=|scope=/.test(new URL(page.url()).search)) {
    problems.push(`clearing the filter left it in the URL: ${page.url()}`);
  }
  const clearedText = await page.locator("body").innerText();
  if (clearedText.includes("Filtered:")) {
    problems.push("the filter banner survived clearing the filter");
  } else {
    log("  OK   filter cleared from the URL and the page");
  }

  log("22f. per-application findings tab");
  await page.goto(`${BASE}/applications`, { waitUntil: "networkidle" });
  await page.getByRole("link", { name: "payments-api" }).first().click();
  await page.waitForURL(/\/applications\/[0-9a-f-]+/, { timeout: 10000 });
  await page.getByRole("tab", { name: "Vulnerabilities" }).click();
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(1200);
  // Asserted on copy unique to the tiles: the filter dropdown carries the same two
  // labels as <option> elements, and an unselected option is not visible, so a plain
  // text match resolves to the hidden one and times out.
  await expectText("Fixed by rebuilding on a newer base image", "the base-image tile");
  await expectText("across", "the affected-package count on the app tile");
  await shot("application-vulnerabilities");

  // --- 22g. accepting a risk ------------------------------------------------
  /*
   * Driven because this dialog had a real bug: it is the only modal in the app that mounts
   * already open, so StrictMode's double-invoked mount effect ran the cleanup while the
   * element was still connected, and the queued `close` event tore down the state that had
   * just opened it. The dialog appeared and vanished in the same frame.
   *
   * The waits are the point of the test. Asserting visibility immediately after the click
   * would pass even with the bug present, because the teardown arrives a task later — so
   * this settles first, then checks the dialog is still there.
   */
  log("22g. accepting a risk keeps its dialog open");
  const acceptButton = page.getByRole("button", { name: "Accept risk" }).first();
  if ((await acceptButton.count()) === 0) {
    log("  note: no unsuppressed finding on this application to accept");
  } else {
    await acceptButton.click();
    await page.waitForTimeout(900);
    const dialog = page.locator("dialog[open]");
    if ((await dialog.count()) === 0) {
      problems.push("the accept-risk dialog closed immediately after opening");
    } else {
      await expectText("Why is this risk accepted?", "the required-reason field");
      await expectText("It is hidden, not deleted", "the wording that makes the decision auditable");
      // The submit button must stay disabled until a reason is given: an unexplained
      // suppression is indistinguishable from a mistake six months later.
      const submit = dialog.getByRole("button", { name: "Accept risk" });
      if (await submit.isEnabled()) {
        problems.push("accept-risk submit was enabled with no reason entered");
      } else {
        log("  OK   dialog stayed open and requires a reason");
      }
      await shot("accept-risk-modal");
      await dialog.getByRole("button", { name: "Cancel" }).click();
      await page.waitForTimeout(600);
      if ((await page.locator("dialog[open]").count()) > 0) {
        problems.push("the accept-risk dialog did not close on Cancel");
      }
    }
  }
}

// Restore the flag so a rerun starts from the same place.
if (!wasEnabled) {
  await page.goto(`${BASE}/admin/vulnerabilities`, { waitUntil: "networkidle" });
  const box = page.getByLabel(/Enabled . packages are matched|Enable Grype scan/);
  if ((await box.count()) > 0) {
    await box.first().click();
    await page.waitForTimeout(1500);
    log("  restored scanning to disabled");
  }
}

// --- 23. clean up the records this run created ------------------------------
log("23. clean up");
// Navigated by URL rather than by link text. "Applications" and "Users" each
// appear twice — once in the main nav, once as an admin tab — and a name-based
// locator resolves to the main-nav one, which leaves the admin panel entirely.
await page.goto(`${BASE}/admin/users`, { waitUntil: "networkidle" });

/*
 * Loops over every `ui-drive-user` account, not just this run's.
 *
 * A run that crashes partway through leaves its account behind, and the next run's search
 * then matches two rows. Taking `.first()` clicked whichever sorted first — often the stale
 * one — and the confirmation dialog then asked for a name this run had never generated, so
 * cleanup hung waiting for a label that would never appear. The failure looked like a
 * broken dialog and was really an accumulated fixture, so this drains them all, exactly as
 * the application cleanup below already does.
 */
let usersDeleted = 0;
for (let attempt = 0; attempt < 10; attempt += 1) {
  await page.getByLabel("Search accounts").fill("ui-drive-user");
  await page.waitForTimeout(900);
  await page.waitForLoadState("networkidle");

  const deleteButtons = page.getByRole("button", { name: "Delete" });
  if ((await deleteButtons.count()) === 0) break;

  await deleteButtons.first().click();
  await page.waitForTimeout(400);

  const dialog = page.locator("dialog[open]");
  // The dialog names its own target, so the confirmation text is read from it rather than
  // assumed — that is what makes deleting an account this run did not create still work.
  const prompt = await dialog.locator("label").first().innerText();
  const target = prompt.replace(/^Type\s+/, "").replace(/\s+to confirm$/, "").trim();
  await dialog.getByLabel(prompt).fill(target);

  // Waits for the actual response rather than sleeping. A fixed delay that ends
  // while the request is still in flight makes the next navigation abort it, which
  // shows up as a spurious `requestfailed` and looks like an application bug.
  const userDeleted = page.waitForResponse(
    (res) => res.request().method() === "DELETE" && /\/admin\/users\//.test(res.url()),
    { timeout: 10000 },
  );
  await dialog.getByRole("button", { name: "Delete", exact: true }).click();
  const userDeleteRes = await userDeleted;
  if (userDeleteRes.status() !== 204) {
    problems.push(`user delete returned ${userDeleteRes.status()}, expected 204`);
    break;
  }
  usersDeleted += 1;
  if (target !== TEST_USER) log(`  note: also removed a leftover account (${target})`);
  await page.waitForTimeout(500);
}
if (usersDeleted === 0) {
  problems.push("cleanup found no ui-drive account to remove");
} else {
  log(`  OK   removed ${usersDeleted} test account(s)`);
}

await page.goto(`${BASE}/admin/applications`, { waitUntil: "networkidle" });
await page.getByLabel("Search applications").fill("ui-drive-app");
await page.waitForTimeout(900);
await page.waitForLoadState("networkidle");

// Loops rather than deleting one, so a run that crashed partway through does
// not leave its application behind for every subsequent run to accumulate.
for (let attempt = 0; attempt < 10; attempt += 1) {
  const rows = page.locator('tbody tr a[href^="/applications/"]');
  if ((await rows.count()) === 0) break;

  const name = (await rows.first().innerText()).trim();
  await page.getByRole("button", { name: "Delete" }).first().click();
  await page.waitForTimeout(400);
  // The confirm word is the application's own name, so it has to be read from
  // the row rather than assumed to be this run's.
  await page.getByLabel(`Type ${name} to confirm`).fill(name);
  const appDeleted = page.waitForResponse(
    (res) => res.request().method() === "DELETE" && /\/admin\/applications\//.test(res.url()),
    { timeout: 10000 },
  );
  await page.getByRole("button", { name: "Delete", exact: true }).last().click();
  const appDeleteRes = await appDeleted;
  if (appDeleteRes.status() !== 200) {
    problems.push(`application delete returned ${appDeleteRes.status()}, expected 200`);
  }
  await page.waitForTimeout(600);
  await page.waitForLoadState("networkidle");
  log(`  OK   removed ${name}`);
}

await expectHidden(TEST_APP, "the deleted test application");
await shot("admin-after-cleanup");

// --- 24. dark mode ---------------------------------------------------------
log("24. dark colour scheme");
await context.close();
const darkContext = await browser.newContext({
  viewport: { width: 1500, height: 950 },
  colorScheme: "dark",
});
const darkPage = await darkContext.newPage();
watch(darkPage, "dark ");
await darkPage.goto(`${BASE}/login`, { waitUntil: "networkidle" });
await login(darkPage, EMAIL, PASSWORD);
await darkPage.waitForURL(`${BASE}/`, { timeout: 10000 });
await darkPage.waitForLoadState("networkidle");
// Wait for real content, not just a quiet network: otherwise the shot can catch
// the loading state and tell us nothing about how the page looks.
await darkPage.getByText("Most widely deployed packages").waitFor({ timeout: 10000 });
// Numbered off the same counter as `shot()`, so adding a step earlier in the run
// no longer makes the dark screenshots collide with light ones.
await darkShot(darkPage, "dark-dashboard");

await darkPage.goto(`${BASE}/analytics`, { waitUntil: "networkidle" });
// `.first()`: "scan coverage" appears both in the banner and as a tile label.
await darkPage.getByText("scan coverage").first().waitFor({ timeout: 15000 });
await darkShot(darkPage, "dark-analytics", { fullPage: true });

await darkPage.goto(`${BASE}/admin/users`, { waitUntil: "networkidle" });
await darkPage.locator("tbody tr").first().waitFor({ timeout: 10000 });
await darkShot(darkPage, "dark-admin-users");

const bg = await darkPage.evaluate(() => getComputedStyle(document.body).backgroundColor);
log(`  body background in dark mode: ${bg}`);
if (bg === "rgba(0, 0, 0, 0)" || bg === "transparent") {
  problems.push("body has no explicit background in dark mode");
}

// --- 25. horizontal overflow ------------------------------------------------
// `/analytics` and a bulk result carry the widest tables in the app — seven
// columns including version lists and platform summaries — so they are the routes
// most likely to push the body sideways.
const OVERFLOW_ROUTES = [
  "/",
  "/applications",
  "/search",
  "/analytics",
  // The saved list from step 13g, so the check covers a populated rollup table
  // rather than the empty state.
  listUrl.replace(BASE, ""),
  "/admin/audit",
];
for (const route of OVERFLOW_ROUTES) {
  await darkPage.goto(`${BASE}${route}`, { waitUntil: "networkidle" });
  await darkPage.waitForTimeout(600);
  const overflow = await darkPage.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  if (overflow) problems.push(`page body scrolls horizontally at ${route}`);
}
log(`  OK   checked horizontal overflow on ${OVERFLOW_ROUTES.length} routes`);

await darkContext.close();
await browser.close();

// --- report ----------------------------------------------------------------
console.log("\n" + "=".repeat(64));
if (problems.length === 0) {
  console.log("UI drive: no problems detected");
  process.exit(0);
} else {
  console.log(`UI drive: ${problems.length} problem(s)`);
  for (const p of problems) console.log(`  - ${p}`);
  process.exit(1);
}
