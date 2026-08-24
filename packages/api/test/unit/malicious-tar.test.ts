import { describe, expect, it } from "vitest";
import { Readable } from "node:stream";
import { gzipSync } from "node:zlib";
import { readTarGz } from "../../src/modules/malicious/tar.js";

/**
 * The tar reader that unpacks the malicious-package feed.
 *
 * Written here rather than pulled from a library, so the obligation is to prove it handles the
 * awkward parts of the format and not merely the happy path. The failure mode is what makes
 * that worth a test file: a reader that mishandles an entry does not throw. It skips a report,
 * and the platform then says nothing about a package it was supposed to catch -- a silence
 * indistinguishable from a clean estate.
 *
 * The case that matters most is the long path. A tar header holds 100 bytes of name, and the
 * feed stores each report at
 * `malicious-packages-main/osv/malicious/npm/<package name>/MAL-….json`. Typosquat names are
 * routinely long enough to cross that boundary -- the real archive contains one 274 characters
 * long -- so the entries most likely to be dropped by a naive reader are precisely the ones the
 * feed exists to report.
 */

/**
 * Builds a POSIX ustar archive in memory, the way real tar does.
 *
 * Including the fallback that matters: ustar splits a long path across `prefix` (155 bytes)
 * and `name` (100), but a single path COMPONENT longer than 100 bytes cannot be represented
 * that way at all. Real tar emits a GNU long-name pseudo-entry instead, and so does this --
 * otherwise the fixture would be testing an encoding the feed never produces.
 */
function tar(entries: Array<{ path: string; body: string; typeflag?: string }>): Buffer {
  const blocks: Buffer[] = [];

  const expanded: Array<{ path: string; body: string; typeflag?: string }> = [];
  for (const entry of entries) {
    if (entry.typeflag === undefined && !ustarRepresentable(entry.path)) {
      expanded.push({ path: "././@LongLink", body: entry.path, typeflag: "L" });
      expanded.push({ ...entry, path: entry.path.slice(-99) });
    } else {
      expanded.push(entry);
    }
  }

  for (const entry of expanded) {
    const header = Buffer.alloc(512);
    const content = Buffer.from(entry.body, "utf8");

    let name = entry.path;
    let prefix = "";
    if (Buffer.byteLength(name) > 100) {
      const cut = name.lastIndexOf("/", 100);
      if (cut > 0) {
        prefix = name.slice(0, cut);
        name = name.slice(cut + 1);
      }
    }

    header.write(name.slice(0, 100), 0, "utf8");
    header.write("000644 \0", 100, "ascii");
    header.write("000000 \0", 108, "ascii");
    header.write("000000 \0", 116, "ascii");
    header.write(content.length.toString(8).padStart(11, "0") + " ", 124, "ascii");
    header.write("00000000000 ", 136, "ascii");
    header.write(entry.typeflag ?? "0", 156, "ascii");
    header.write("ustar\0", 257, "ascii");
    header.write("00", 263, "ascii");
    header.write(prefix.slice(0, 155), 345, "utf8");

    // Checksum is computed with the field itself read as spaces, then written back.
    header.write("        ", 148, "ascii");
    let sum = 0;
    for (const byte of header) sum += byte;
    header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "ascii");

    blocks.push(header);
    const padded = Buffer.alloc(Math.ceil(content.length / 512) * 512);
    content.copy(padded);
    blocks.push(padded);
  }

  // Two zero blocks terminate the archive.
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

/** Whether ustar's prefix/name split can carry this path without a long-name entry. */
function ustarRepresentable(path: string): boolean {
  if (Buffer.byteLength(path) <= 100) return true;
  const cut = path.lastIndexOf("/", 100);
  return cut > 0 && Buffer.byteLength(path.slice(cut + 1)) <= 100 && cut <= 155;
}

async function read(archive: Buffer): Promise<Array<{ path: string; body: string }>> {
  const out: Array<{ path: string; body: string }> = [];
  for await (const entry of readTarGz(Readable.from(archive))) {
    out.push({ path: entry.path, body: entry.content.toString("utf8") });
  }
  return out;
}

describe("reading the feed archive", () => {
  it("yields regular files with their contents", async () => {
    const entries = await read(
      tar([
        { path: "root/osv/malicious/npm/a/MAL-1.json", body: '{"id":"MAL-1"}' },
        { path: "root/osv/malicious/npm/b/MAL-2.json", body: '{"id":"MAL-2"}' },
      ]),
    );
    expect(entries.map((e) => e.path)).toEqual([
      "root/osv/malicious/npm/a/MAL-1.json",
      "root/osv/malicious/npm/b/MAL-2.json",
    ]);
    expect(entries[0]!.body).toBe('{"id":"MAL-1"}');
  });

  it("reassembles a path split across the prefix and name fields", async () => {
    /*
      The case that silently drops reports. A reader that ignores `prefix` returns only the
      tail of the path -- which still ends in `.json` and still parses -- so nothing looks
      wrong until somebody asks why a package known to be malicious was never reported.
    */
    // Over 100 bytes overall, but with a "/" positioned so the tail still fits `name` --
    // which is exactly when tar uses the prefix field rather than a long-name entry.
    const dir = "malicious-packages-main/osv/malicious/npm";
    const pkg = "a-package-name-long-enough-to-push-this-path-past-one-hundred-bytes";
    const path = `${dir}/${pkg}/MAL-2024-7773.json`;
    expect(path.length).toBeGreaterThan(100);
    expect(ustarRepresentable(path)).toBe(true);

    const entries = await read(tar([{ path, body: '{"id":"MAL-2024-7773"}' }]));
    expect(entries).toHaveLength(1);
    expect(entries[0]!.path).toBe(path);
  });

  it("reassembles a single path component too long for ustar at all", async () => {
    /*
      The real archive contains a package whose name alone is 220 characters, giving a 274-byte
      path. No prefix/name split can carry that, so tar falls back to a long-name entry -- and
      these are exactly the entries worth catching, because an absurdly long name is a typosquat
      tell rather than an accident.
    */
    const path = `malicious-packages-main/osv/malicious/npm/${"l".repeat(220)}/MAL-2024-7773.json`;
    // The real archive tops out at 274 bytes; anything past the 155+100 ustar ceiling needs
    // the same fallback, so the exact figure is not what is being pinned.
    expect(path.length).toBeGreaterThan(255);
    expect(ustarRepresentable(path)).toBe(false);

    const entries = await read(tar([{ path, body: '{"id":"MAL-2024-7773"}' }]));
    expect(entries).toHaveLength(1);
    expect(entries[0]!.path).toBe(path);
  });

  it("resolves a GNU long name from its pseudo-entry", async () => {
    // The other way a long path arrives: as the BODY of an `L` entry describing the next one.
    const path = "root/osv/malicious/npm/" + "x".repeat(200) + "/MAL-3.json";
    const entries = await read(
      tar([
        { path: "././@LongLink", body: path, typeflag: "L" },
        { path: "ignored-short-name", body: '{"id":"MAL-3"}' },
      ]),
    );
    expect(entries).toHaveLength(1);
    expect(entries[0]!.path).toBe(path);
    expect(entries[0]!.body).toBe('{"id":"MAL-3"}');
  });

  it("resolves a PAX path record", async () => {
    const path = "root/osv/malicious/pypi/" + "y".repeat(150) + "/MAL-4.json";
    const record = `path=${path}\n`;
    // PAX records are "<total length> <key>=<value>\n", where the length counts itself.
    const size = String(record.length + 1 + String(record.length + 1).length);
    const entries = await read(
      tar([
        { path: "PaxHeader", body: `${size} ${record}`, typeflag: "x" },
        { path: "ignored", body: '{"id":"MAL-4"}' },
      ]),
    );
    expect(entries).toHaveLength(1);
    expect(entries[0]!.path).toBe(path);
  });

  it("skips directories and anything that is not a regular file", async () => {
    const entries = await read(
      tar([
        { path: "root/osv/", body: "", typeflag: "5" },
        { path: "root/link", body: "", typeflag: "2" },
        { path: "root/osv/malicious/npm/a/MAL-5.json", body: "{}" },
      ]),
    );
    expect(entries.map((e) => e.path)).toEqual(["root/osv/malicious/npm/a/MAL-5.json"]);
  });

  it("reads a file whose length is not a multiple of the block size", async () => {
    // Every real entry is like this; getting the padding wrong loses the reader's place in the
    // stream and drops every entry after it, not just the one.
    const body = "x".repeat(513);
    const entries = await read(
      tar([
        { path: "root/osv/malicious/npm/a/MAL-6.json", body },
        { path: "root/osv/malicious/npm/b/MAL-7.json", body: "after" },
      ]),
    );
    expect(entries).toHaveLength(2);
    expect(entries[0]!.body).toHaveLength(513);
    expect(entries[1]!.body).toBe("after");
  });

  it("survives an archive split across arbitrary chunk boundaries", async () => {
    /*
      A network stream arrives in whatever sizes the socket produces, never in 512-byte blocks.
      Feeding it one byte at a time is the harshest version of that and proves the reader
      buffers across boundaries rather than assuming a chunk holds a whole header.
    */
    const archive = tar([
      { path: "root/osv/malicious/npm/a/MAL-8.json", body: '{"id":"MAL-8"}' },
      { path: "root/osv/malicious/npm/b/MAL-9.json", body: '{"id":"MAL-9"}' },
    ]);
    const oneByteAtATime = Readable.from(
      (function* () {
        for (const byte of archive) yield Buffer.from([byte]);
      })(),
    );

    const out: string[] = [];
    for await (const entry of readTarGz(oneByteAtATime)) out.push(entry.path);
    expect(out).toEqual([
      "root/osv/malicious/npm/a/MAL-8.json",
      "root/osv/malicious/npm/b/MAL-9.json",
    ]);
  });

  it("stops cleanly at the end-of-archive marker", async () => {
    const entries = await read(tar([{ path: "root/a.json", body: "{}" }]));
    expect(entries).toHaveLength(1);
  });
});
