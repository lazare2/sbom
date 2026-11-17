// A logging, allow-list forward proxy for scripts/egress-test.ps1. Test tooling only: it is
// never part of the product or the bundle.
//
// The platform under test sits on a Docker network with no route out, so this proxy is the
// only way to the internet. Every attempt is written to $LOG as one JSON line, allowed or not,
// which is what the test reads to prove the platform contacts nothing but the documented
// update addresses.
//
// ALLOW is a comma-separated host list; "*.example.com" matches subdomains.

import fs from "node:fs";
import http from "node:http";
import net from "node:net";

const allow = (process.env.ALLOW ?? "").split(",").map((h) => h.trim().toLowerCase()).filter(Boolean);
const logFile = process.env.LOG ?? "/egress/egress.jsonl";

function allowed(host) {
  const h = host.toLowerCase().replace(/\.$/, "");
  return allow.some((a) => (a.startsWith("*.") ? h.endsWith(a.slice(1)) : h === a));
}

function record(entry) {
  fs.appendFileSync(logFile, JSON.stringify({ time: new Date().toISOString(), ...entry }) + "\n");
}

// Plain-HTTP requests arrive with an absolute URL.
const server = http.createServer((req, res) => {
  let url;
  try {
    url = new URL(req.url);
  } catch {
    res.writeHead(400).end();
    return;
  }
  const ok = allowed(url.hostname);
  record({ method: req.method, host: url.hostname, port: Number(url.port || 80), allowed: ok });
  if (!ok) {
    res.writeHead(403).end("blocked by the egress test\n");
    return;
  }
  const upstream = http.request(
    { host: url.hostname, port: url.port || 80, path: url.pathname + url.search, method: req.method, headers: req.headers },
    (r) => {
      res.writeHead(r.statusCode ?? 502, r.headers);
      r.pipe(res);
    },
  );
  upstream.on("error", (e) => res.writeHead(502).end(String(e)));
  req.pipe(upstream);
});

// HTTPS goes through CONNECT: the host is visible, the content is not, which is all the
// test needs.
server.on("connect", (req, socket, head) => {
  const idx = req.url.lastIndexOf(":");
  const host = idx > 0 ? req.url.slice(0, idx).replace(/^\[|\]$/g, "") : req.url;
  const port = idx > 0 ? Number(req.url.slice(idx + 1)) : 443;
  const ok = allowed(host);
  record({ method: "CONNECT", host, port, allowed: ok });
  if (!ok) {
    socket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
    return;
  }
  const upstream = net.connect(port, host, () => {
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head.length) upstream.write(head);
    upstream.pipe(socket);
    socket.pipe(upstream);
  });
  upstream.on("error", (e) => {
    // An allowed address that cannot be reached is the network's fault, not the platform's:
    // recorded so a failed run says which it was.
    record({ method: "CONNECT", host, port, allowed: true, upstreamError: e.code ?? e.message });
    socket.destroy();
  });
  socket.on("error", () => upstream.destroy());
});

server.listen(3128, "0.0.0.0", () => console.log(`egress proxy on :3128, allowing ${allow.join(", ")}`));
