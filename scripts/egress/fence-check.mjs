// Fence checks for scripts/egress-test.ps1, run inside the network under test.
//   node fence-check.mjs direct   exit 0 if https://registry.npmjs.org is reachable WITHOUT the proxy
//   node fence-check.mjs proxy    exit 0 if the proxy lets a CONNECT to it through
// The test passes when both exit non-zero.

import net from "node:net";
import tls from "node:tls";

const target = "registry.npmjs.org";
const mode = process.argv[2];

function done(code, text) {
  console.log(text);
  process.exit(code);
}
setTimeout(() => done(2, "timed out"), 8000);

if (mode === "direct") {
  // A raw TLS connection: no fetch, so no proxy setting can intervene.
  const s = tls.connect({ host: target, port: 443, servername: target }, () => done(0, "connected directly"));
  s.on("error", (e) => done(1, `no direct route: ${e.code ?? e.message}`));
} else if (mode === "proxy") {
  const s = net.connect(3128, "egress-proxy", () =>
    s.write(`CONNECT ${target}:443 HTTP/1.1\r\nHost: ${target}:443\r\n\r\n`),
  );
  s.on("data", (d) => {
    const line = String(d).split("\r\n")[0];
    done(/ 200 /.test(line) ? 0 : 1, `proxy answered: ${line}`);
  });
  s.on("error", (e) => done(3, `proxy unreachable: ${e.code ?? e.message}`));
} else {
  done(4, "usage: fence-check.mjs direct|proxy");
}
