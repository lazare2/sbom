import { Readable } from "node:stream";
import { createGunzip } from "node:zlib";

/**
 * Just enough tar to read the malicious-package feed.
 *
 * A dependency was the obvious alternative and was rejected for the reason the rest of this
 * codebase avoids them: the feed is fetched by deployments that are air-gapped and
 * conservative about their supply chain, and pulling an archive-extraction library into the
 * server that exists to police supply chains is a poor trade for 150 lines.
 *
 * What that costs is the obligation to handle the awkward parts of the format properly rather
 * than the happy path, because the failure mode is silent. A reader that mishandles an entry
 * does not crash -- it skips a report, and the platform then says nothing about a package it
 * was supposed to catch. Three cases matter here and all three are handled below:
 *
 *  - **`prefix`.** The classic header holds only 100 bytes of name, with 155 more in a
 *    separate field that a naive reader ignores. Paths in this feed run to
 *    `.../osv/malicious/npm/<package name>/MAL-2024-1677.json`, and typosquat names are
 *    routinely long enough to cross that boundary -- so the entries most likely to be
 *    dropped are exactly the ones the feed exists to report.
 *  - **GNU long names** (`typeflag` `L`), where the path arrives as the body of a pseudo
 *    entry that describes the next one.
 *  - **PAX extended headers** (`typeflag` `x`), which carry the same thing as a `path=`
 *    record in a length-prefixed key/value body.
 *
 * Streaming rather than buffering: the archive is ~41 MB compressed and several hundred
 * megabytes expanded, which is not something to hold in memory on a server whose real job is
 * answering queries.
 */

const BLOCK = 512;

/** Where each field sits in the 512-byte header. Offsets are from the POSIX ustar layout. */
const FIELD = {
  name: { off: 0, len: 100 },
  size: { off: 124, len: 12 },
  typeflag: { off: 156, len: 1 },
  prefix: { off: 345, len: 155 },
} as const;

function readString(block: Buffer, field: { off: number; len: number }): string {
  const raw = block.subarray(field.off, field.off + field.len);
  const end = raw.indexOf(0);
  return raw.subarray(0, end === -1 ? raw.length : end).toString("utf8");
}

/**
 * The size field, which is octal text in the common case.
 *
 * GNU switches to base-256 for sizes that do not fit, flagged by the high bit of the first
 * byte. No entry in this feed is remotely large enough to need it, but a reader that
 * misreads a size does not skip one entry -- it loses its place in the stream and every
 * entry after it. Handling it is cheaper than relying on that never happening.
 */
function readSize(block: Buffer): number {
  const raw = block.subarray(FIELD.size.off, FIELD.size.off + FIELD.size.len);
  if (raw[0] !== undefined && (raw[0] & 0x80) !== 0) {
    let value = 0;
    for (let i = 1; i < raw.length; i += 1) value = value * 256 + (raw[i] ?? 0);
    return value;
  }
  const text = raw.toString("ascii").replace(/\0.*$/, "").trim();
  if (text === "") return 0;
  const parsed = Number.parseInt(text, 8);
  return Number.isFinite(parsed) ? parsed : 0;
}

/** `path=` out of a PAX body, whose records are `"<len> <key>=<value>\n"`. */
function paxPath(body: Buffer): string | null {
  let offset = 0;
  const text = body.toString("utf8");
  while (offset < text.length) {
    const space = text.indexOf(" ", offset);
    if (space === -1) break;
    const length = Number.parseInt(text.slice(offset, space), 10);
    if (!Number.isFinite(length) || length <= 0) break;
    const record = text.slice(space + 1, offset + length).replace(/\n$/, "");
    const eq = record.indexOf("=");
    if (eq !== -1 && record.slice(0, eq) === "path") return record.slice(eq + 1);
    offset += length;
  }
  return null;
}

export interface TarEntry {
  path: string;
  content: Buffer;
}

/**
 * Yields every regular file in a gzipped tar, in archive order.
 *
 * Directories, symlinks and the pseudo-entries carrying long names are consumed and not
 * yielded -- the caller sees only files, with their full paths already resolved.
 */
export async function* readTarGz(source: Readable): AsyncGenerator<TarEntry> {
  const gunzip = createGunzip();
  source.pipe(gunzip);

  let buffer: Buffer = Buffer.alloc(0);
  /** Set by an `L` or `x` pseudo-entry, and consumed by the entry that follows it. */
  let pendingPath: string | null = null;

  for await (const chunk of gunzip) {
    const next = Buffer.from(chunk as Uint8Array);
    buffer = buffer.length === 0 ? next : Buffer.concat([buffer, next]);

    for (;;) {
      if (buffer.length < BLOCK) break;

      const header = buffer.subarray(0, BLOCK);
      // Two zero blocks mark the end, but a single one is enough to stop on: nothing
      // meaningful follows, and the trailing padding is not worth parsing.
      if (header.every((b) => b === 0)) return;

      const size = readSize(header);
      const padded = Math.ceil(size / BLOCK) * BLOCK;
      if (buffer.length < BLOCK + padded) break;

      const body = buffer.subarray(BLOCK, BLOCK + size);
      const typeflag = readString(header, FIELD.typeflag);

      if (typeflag === "L") {
        // GNU long name: the body IS the next entry's path.
        pendingPath = body.toString("utf8").replace(/\0+$/, "");
      } else if (typeflag === "x") {
        pendingPath = paxPath(body) ?? pendingPath;
      } else if (typeflag === "g") {
        // Global PAX header: applies to the whole archive and carries nothing we read.
      } else if (typeflag === "" || typeflag === "0") {
        const name = readString(header, FIELD.name);
        const prefix = readString(header, FIELD.prefix);
        const path = pendingPath ?? (prefix === "" ? name : `${prefix}/${name}`);
        pendingPath = null;
        // Copied, not referenced: `body` is a view over a buffer this loop is about to
        // discard, and a consumer holding it would read whatever lands there next.
        yield { path, content: Buffer.from(body) };
      } else {
        // Directory, symlink, hard link, device. Nothing to yield, and a pending long name
        // belonged to this entry rather than the next one.
        pendingPath = null;
      }

      buffer = buffer.subarray(BLOCK + padded);
    }
  }
}
