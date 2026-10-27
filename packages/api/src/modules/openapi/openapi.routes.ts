import type { FastifyInstance } from "fastify";
import { buildOpenApiDocument } from "./openapi.service.js";

/**
 * Serves the OpenAPI document and a reference page.
 *
 * ## Why the reference page is hand-rendered
 *
 * The obvious move is Swagger UI from a CDN, and it is the wrong one here: this platform's
 * target deployment is an air-gapped host behind a proxy that blocks outbound traffic, so a
 * CDN-loaded viewer renders a blank page with a console error nobody sees. Bundling Swagger UI
 * instead would add several megabytes of JavaScript to the image to display a document that is
 * mostly prose.
 *
 * So the page below is generated from the document, server-side, as self-contained HTML with no
 * script and no external request. It is less capable than Swagger UI - there is no "try it"
 * button - and it works on the machine this is actually installed on, which is the trade worth
 * making. The document itself is served as JSON for anyone who wants to point a real tool at it.
 *
 * ## Both are public
 *
 * Deliberately. The document describes the shape of the API, not its contents: there is no
 * estate data in it, every operation is marked with the credential it needs, and a developer
 * who cannot read it before authenticating cannot work out how to authenticate. Keeping it
 * behind a session would also make it unreadable to exactly the tooling that consumes it.
 */
export async function openapiRoutes(fastify: FastifyInstance): Promise<void> {
  const { config } = fastify.ctx;

  const baseUrl = `${config.PUBLIC_URL.replace(/\/+$/, "")}/api/v1`;

  /*
    Built once, on the first request, and then reused.

    The route table cannot change after the server is ready, so there is nothing to invalidate
    - and building it per request would mean running every Zod schema through a JSON Schema
    conversion on a public endpoint, which is a free denial of service.
  */
  let cached: Record<string, unknown> | null = null;
  const document = (): Record<string, unknown> => {
    cached ??= buildOpenApiDocument(fastify.routeTable.list(), {
      baseUrl,
      /*
        Taken from the environment, defaulting to "dev". Not read out of package.json: the
        compiled server runs from `dist` where that file's location differs between the
        container and a local run, and a version string is not worth a filesystem lookup that
        can fail at startup. The deploy sets it alongside the image tag.
      */
      version: process.env.APP_VERSION ?? "dev",
    });
    return cached;
  };

  fastify.get("/openapi.json", async (_request, reply) => {
    return reply.type("application/json").send(document());
  });

  fastify.get("/docs", async (_request, reply) => {
    return reply.type("text/html; charset=utf-8").send(renderReference(document()));
  });
}

/** Minimal HTML escaping for text interpolated into the page. */
function esc(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Renders the document as a single self-contained page.
 *
 * Markdown in the descriptions is not parsed - only the two things that actually appear are
 * handled: fenced code blocks and `inline code`. A full Markdown renderer here would be a
 * dependency and an injection surface for the sake of prose this file also writes.
 */
function miniMarkdown(text: string): string {
  const parts = esc(text).split(/```/);
  return parts
    .map((part, index) =>
      index % 2 === 1
        ? `<pre>${part.trim()}</pre>`
        : part
            .replace(/`([^`]+)`/g, "<code>$1</code>")
            .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
            .replace(/^## (.+)$/gm, "<h3>$1</h3>")
            .split(/\n{2,}/)
            .map((para) => (para.trim() === "" ? "" : `<p>${para.trim()}</p>`))
            .join(""),
    )
    .join("");
}

const METHOD_COLOURS: Record<string, string> = {
  GET: "#2563eb",
  POST: "#16a34a",
  PUT: "#ca8a04",
  PATCH: "#ca8a04",
  DELETE: "#dc2626",
};

function renderReference(doc: Record<string, unknown>): string {
  const info = doc.info as { title: string; version: string; description: string };
  const paths = doc.paths as Record<string, Record<string, Record<string, unknown>>>;
  const servers = doc.servers as { url: string }[];

  /** tag -> operations, so the page reads by area rather than alphabetically by path. */
  const byTag = new Map<string, { method: string; path: string; op: Record<string, unknown> }[]>();
  for (const [path, methods] of Object.entries(paths)) {
    for (const [method, op] of Object.entries(methods)) {
      const tag = ((op.tags as string[] | undefined) ?? ["Other"])[0] ?? "Other";
      const list = byTag.get(tag) ?? [];
      list.push({ method: method.toUpperCase(), path, op });
      byTag.set(tag, list);
    }
  }
  const tags = [...byTag.keys()].sort();
  for (const list of byTag.values()) {
    list.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
  }

  const total = [...byTag.values()].reduce((sum, list) => sum + list.length, 0);

  const operations = tags
    .map((tag) => {
      const rows = byTag
        .get(tag)!
        .map(({ method, path, op }) => {
          const params = (op.parameters as { name: string }[] | undefined) ?? [];
          const body = op.requestBody as
            | { content: { "application/json": { schema: unknown } } }
            | undefined;
          return `
        <details class="op">
          <summary>
            <span class="m" style="background:${METHOD_COLOURS[method] ?? "#64748b"}">${esc(method)}</span>
            <code class="p">${esc(path)}</code>
            <span class="s">${esc(op.summary)}</span>
          </summary>
          <div class="body">
            ${miniMarkdown(String(op.description ?? ""))}
            ${
              params.length > 0
                ? `<h4>Path parameters</h4><ul>${params
                    .map((p) => `<li><code>${esc(p.name)}</code></li>`)
                    .join("")}</ul>`
                : ""
            }
            ${
              body
                ? `<h4>Request body <span class="muted">application/json</span></h4><pre>${esc(
                    JSON.stringify(body.content["application/json"].schema, null, 2),
                  )}</pre>`
                : ""
            }
            <h4>Responses</h4>
            <ul>${Object.entries(op.responses as Record<string, { description: string }>)
              .map(([code, r]) => `<li><code>${esc(code)}</code> - ${esc(r.description)}</li>`)
              .join("")}</ul>
          </div>
        </details>`;
        })
        .join("");
      return `<section><h2 id="${esc(tag.replace(/\W+/g, "-"))}">${esc(tag)} <span class="muted">${
        byTag.get(tag)!.length
      }</span></h2>${rows}</section>`;
    })
    .join("");

  const toc = tags
    .map(
      (tag) =>
        `<a href="#${esc(tag.replace(/\W+/g, "-"))}">${esc(tag)} <span class="muted">${byTag.get(tag)!.length}</span></a>`,
    )
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(info.title)} - reference</title>
<style>
  /* Self-contained on purpose: this has to render on an air-gapped host. */
  :root { color-scheme: light dark;
    --bg:#ffffff; --fg:#18181b; --muted:#71717a; --line:#e4e4e7; --card:#fafafa; --code:#f4f4f5; --accent:#2563eb; }
  @media (prefers-color-scheme: dark) { :root {
    --bg:#0b0b0e; --fg:#e4e4e7; --muted:#a1a1aa; --line:#27272a; --card:#131317; --code:#1c1c21; --accent:#60a5fa; } }
  * { box-sizing:border-box }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.6 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif }
  .wrap { max-width:1100px; margin:0 auto; padding:32px 20px 80px }
  h1 { font-size:24px; margin:0 0 4px }
  h2 { font-size:15px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin:32px 0 10px; padding-bottom:6px; border-bottom:1px solid var(--line) }
  h3 { font-size:14px; margin:18px 0 6px }
  h4 { font-size:12px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); margin:14px 0 4px }
  p { margin:8px 0 }
  a { color:var(--accent) }
  code { background:var(--code); padding:1px 5px; border-radius:4px; font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace }
  pre { background:var(--code); padding:12px; border-radius:6px; overflow-x:auto; font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace; white-space:pre-wrap }
  .muted { color:var(--muted); font-weight:400 }
  .lede { color:var(--muted); margin-bottom:18px }
  .toc { display:flex; flex-wrap:wrap; gap:6px; margin:16px 0 8px }
  .toc a { background:var(--card); border:1px solid var(--line); border-radius:999px; padding:4px 11px; font-size:12.5px; text-decoration:none }
  .op { border:1px solid var(--line); border-radius:6px; margin-bottom:6px; background:var(--card) }
  .op > summary { cursor:pointer; padding:9px 12px; display:flex; gap:10px; align-items:baseline; flex-wrap:wrap; list-style:none }
  .op > summary::-webkit-details-marker { display:none }
  .op[open] > summary { border-bottom:1px solid var(--line) }
  .m { color:#fff; font:600 10.5px/1 ui-monospace,monospace; padding:4px 6px; border-radius:3px; letter-spacing:.04em; min-width:52px; text-align:center }
  .p { background:transparent; padding:0; font-size:13px }
  .s { color:var(--muted); font-size:13px }
  .body { padding:4px 14px 14px }
  .body > p:first-child { margin-top:10px }
  ul { margin:6px 0; padding-left:20px } li { margin:2px 0 }
</style>
</head>
<body>
<div class="wrap">
  <h1>${esc(info.title)}</h1>
  <p class="lede">Version ${esc(info.version)} · ${total} endpoints · base URL <code>${esc(servers[0]?.url)}</code></p>
  ${miniMarkdown(info.description)}
  <h2>Contents</h2>
  <nav class="toc">${toc}</nav>
  ${operations}
  <h2>Machine-readable</h2>
  <p>The same thing as an OpenAPI 3.0 document: <a href="openapi.json">openapi.json</a>. Point a client generator at it, or import it into whatever you already use.</p>
</div>
</body>
</html>`;
}
