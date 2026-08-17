import { describe, expect, it } from "vitest";
import { normalizePurl, purlType } from "../../src/modules/ingestion/purl.js";

describe("purlType", () => {
  it("extracts the type from a namespaced purl", () => {
    expect(purlType("pkg:deb/debian/libc6@2.36?arch=amd64")).toBe("deb");
    expect(purlType("pkg:npm/%40scope/pkg@1.0.0")).toBe("npm");
    expect(purlType("pkg:golang/github.com/gin-gonic/gin@v1.10.0")).toBe("golang");
  });

  it("lowercases the type, which the spec defines as case-insensitive", () => {
    expect(purlType("pkg:NPM/express@4.19.2")).toBe("npm");
  });

  it("returns null for values that are not purls", () => {
    expect(purlType("not-a-purl")).toBeNull();
    expect(purlType("")).toBeNull();
    // No namespace/name segment after the type.
    expect(purlType("pkg:npm")).toBeNull();
  });
});

describe("normalizePurl", () => {
  it("sorts qualifiers so a Syft version change cannot fork a package identity", () => {
    const a = normalizePurl("pkg:deb/debian/libc6@2.36?distro=debian-12&arch=amd64");
    const b = normalizePurl("pkg:deb/debian/libc6@2.36?arch=amd64&distro=debian-12");
    expect(a).toBe(b);
    expect(a).toBe("pkg:deb/debian/libc6@2.36?arch=amd64&distro=debian-12");
  });

  it("leaves a purl with no qualifiers untouched", () => {
    expect(normalizePurl("pkg:npm/express@4.19.2")).toBe("pkg:npm/express@4.19.2");
  });

  it("lowercases qualifier keys but preserves qualifier values", () => {
    expect(normalizePurl("pkg:deb/debian/x@1?ARCH=AMD64")).toBe("pkg:deb/debian/x@1?arch=AMD64");
  });

  it("preserves case in the namespace, name, and version", () => {
    // maven groupIds and golang module paths are case-sensitive; lowercasing
    // them would merge genuinely different packages.
    expect(normalizePurl("pkg:maven/com.Example/MyLib@1.0.0")).toBe("pkg:maven/com.Example/MyLib@1.0.0");
  });

  it("drops empty qualifier values, which the spec treats as absent", () => {
    expect(normalizePurl("pkg:deb/debian/x@1?arch=&distro=debian-12")).toBe(
      "pkg:deb/debian/x@1?distro=debian-12",
    );
  });

  it("keeps the subpath after the qualifiers", () => {
    expect(normalizePurl("pkg:golang/example.com/m@v1?b=2&a=1#sub/dir")).toBe(
      "pkg:golang/example.com/m@v1?a=1&b=2#sub/dir",
    );
  });

  it("handles a purl whose only qualifier is empty", () => {
    expect(normalizePurl("pkg:npm/x@1?arch=")).toBe("pkg:npm/x@1");
  });

  it("returns an empty string unchanged", () => {
    expect(normalizePurl("   ")).toBe("");
  });
});
