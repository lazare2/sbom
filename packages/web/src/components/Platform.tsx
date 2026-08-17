import { Link } from "react-router";
import type { ScanPlatform } from "@sbom/shared";

/**
 * Renders what an image is built on: OS distribution plus language runtimes.
 *
 * Three empty states, kept distinct because they mean different things and a
 * single "—" would conflate them:
 *
 *   platform === null      the application has never been scanned
 *   summary === null       it was scanned and nothing was found (scratch,
 *                          distroless, or an SBOM from a tool that does not
 *                          catalogue an OS)
 *   partial                an OS but no runtime, or the reverse — shown as
 *                          whatever was actually detected
 */

/** Colour per OS family, so a mixed estate is scannable at a glance. */
const OS_TONE: Record<string, string> = {
  alpine: "bg-info-subtle text-info",
  debian: "bg-danger-subtle text-danger",
  ubuntu: "bg-warn-subtle text-warn",
  wolfi: "bg-ok-subtle text-ok",
  chainguard: "bg-ok-subtle text-ok",
};

const OS_LABELS: Record<string, string> = {
  alpine: "Alpine",
  debian: "Debian",
  ubuntu: "Ubuntu",
  rhel: "RHEL",
  centos: "CentOS",
  fedora: "Fedora",
  rocky: "Rocky",
  almalinux: "AlmaLinux",
  amzn: "Amazon Linux",
  sles: "SLES",
  opensuse: "openSUSE",
  arch: "Arch",
  wolfi: "Wolfi",
  chainguard: "Chainguard",
  photon: "Photon",
  busybox: "BusyBox",
  windows: "Windows",
};

const RUNTIME_LABELS: Record<string, string> = {
  node: "Node.js",
  bun: "Bun",
  deno: "Deno",
  python: "Python",
  pypy: "PyPy",
  java: "Java",
  ruby: "Ruby",
  php: "PHP",
  perl: "Perl",
  go: "Go",
  rust: "Rust",
  dotnet: ".NET",
  erlang: "Erlang",
  elixir: "Elixir",
  haskell: "Haskell",
  lua: "Lua",
  swift: "Swift",
  dart: "Dart",
  nginx: "nginx",
  "apache-httpd": "Apache httpd",
  tomcat: "Tomcat",
  caddy: "Caddy",
  haproxy: "HAProxy",
};

export function osLabel(name: string | null): string | null {
  if (!name) return null;
  return OS_LABELS[name.toLowerCase()] ?? name;
}

export function runtimeLabel(name: string): string {
  return RUNTIME_LABELS[name] ?? name;
}

function Chip({
  children,
  tone,
  title,
  to,
}: {
  children: React.ReactNode;
  tone: string;
  title?: string;
  to?: string;
}) {
  const className = `inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap ${tone}`;
  // Linked chips filter the applications list, which is what turns a label into
  // an answer: "Debian 11" becomes "show me everything still on Debian 11".
  if (to) {
    return (
      <Link to={to} title={title} className={`${className} hover:underline`}>
        {children}
      </Link>
    );
  }
  return (
    <span title={title} className={className}>
      {children}
    </span>
  );
}

export function PlatformChips({
  platform,
  linkFilters = false,
  emptyLabel,
}: {
  platform: ScanPlatform | null;
  /** Make each chip a link into the filtered applications list. */
  linkFilters?: boolean;
  emptyLabel?: string;
}) {
  if (!platform) {
    return <span className="text-text-faint">{emptyLabel ?? "Not scanned"}</span>;
  }

  const os = osLabel(platform.osName);
  const hasAnything = os !== null || platform.runtimes.length > 0;

  if (!hasAnything) {
    return (
      <span
        className="text-text-faint"
        title="The SBOM contained no OS release information and no runtime binary. Normal for a scratch or distroless image."
      >
        No OS or runtime detected
      </span>
    );
  }

  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {os ? (
        <Chip
          tone={OS_TONE[platform.osName?.toLowerCase() ?? ""] ?? "bg-neutral-subtle text-text-muted"}
          title={platform.osPretty ?? undefined}
          to={
            linkFilters && platform.osName
              ? `/applications?os=${encodeURIComponent(platform.osName)}`
              : undefined
          }
        >
          {os}
          {platform.osVersion ? <span className="nums font-normal">{platform.osVersion}</span> : null}
        </Chip>
      ) : null}

      {platform.runtimes.map((runtime) => (
        <Chip
          key={runtime.name}
          tone="bg-accent-subtle text-accent"
          to={linkFilters ? `/applications?runtime=${encodeURIComponent(runtime.name)}` : undefined}
        >
          {runtimeLabel(runtime.name)}
          {runtime.version ? <span className="nums font-normal">{runtime.version}</span> : null}
        </Chip>
      ))}
    </span>
  );
}

/**
 * Single-line text form, for dense table cells where chips would be too heavy.
 * Uses the summary the API already rendered, so the wording cannot drift
 * between the two representations.
 */
export function PlatformText({ platform }: { platform: ScanPlatform | null }) {
  if (!platform) return <span className="text-text-faint">—</span>;
  if (!platform.summary) {
    return (
      <span className="text-text-faint" title="Scratch or distroless image, or a non-Syft SBOM">
        none detected
      </span>
    );
  }
  return (
    <span className="text-text-muted" title={platform.osPretty ?? platform.summary}>
      {platform.summary}
    </span>
  );
}
