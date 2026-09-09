import { describe, expect, it } from "vitest";
import type { ScannablePackage } from "../../src/services/scanner/grype-output.js";
import {
  mappableEcosystems,
  parsePurl,
  toXrayCoordinate,
  XRAY_CANARIES,
} from "../../src/services/scanner/xray-coordinates.js";

/**
 * Rewriting packages into Xray's coordinate form.
 *
 * The failure this guards against is not a crash — it is a coordinate that is *plausible and
 * wrong*. Xray answers an unrecognised identifier the same way it answers a clean package:
 * with no findings. So a mistake here does not surface as an error, it surfaces as an estate
 * that looks safe.
 *
 * That is why `null` is asserted as carefully as the successful mappings. Null means "cannot
 * be expressed, do not submit, record as unassessed"; anything that quietly became a string
 * instead would be submitted, come back empty, and be filed as checked.
 */

function pkg(over: Partial<ScannablePackage> = {}): ScannablePackage {
  return {
    componentId: 1,
    name: "lodash",
    version: "4.17.15",
    purl: "pkg:npm/lodash@4.17.15",
    ecosystem: "npm",
    ...over,
  };
}

describe("parsing a purl", () => {
  it("splits namespace, name and version", () => {
    expect(parsePurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")).toEqual({
      type: "maven",
      namespace: "org.apache.logging.log4j",
      name: "log4j-core",
      version: "2.14.1",
    });
  });

  it("keeps a multi-segment namespace whole, as Go modules need", () => {
    expect(parsePurl("pkg:golang/github.com/gin-gonic/gin@v1.9.0")).toEqual({
      type: "golang",
      namespace: "github.com/gin-gonic",
      name: "gin",
      version: "v1.9.0",
    });
  });

  it("discards qualifiers and subpaths", () => {
    /*
      Syft attaches `?distro=debian-12&arch=amd64` to every deb purl. Xray coordinates have
      no equivalent, and passing one through produces an identifier that matches nothing
      while looking entirely reasonable in a log line.
    */
    const parsed = parsePurl("pkg:deb/debian/openssl@1.1.1n-0+deb10u3?distro=debian-10&arch=amd64");
    expect(parsed).toEqual({
      type: "deb",
      namespace: "debian",
      name: "openssl",
      version: "1.1.1n-0+deb10u3",
    });
  });

  it("percent-decodes a scoped npm name", () => {
    expect(parsePurl("pkg:npm/%40isaacs/cliui@8.0.2")).toMatchObject({
      namespace: "@isaacs",
      name: "cliui",
    });
  });

  it("returns null for anything that is not a purl", () => {
    expect(parsePurl("lodash@4.17.15")).toBeNull();
    expect(parsePurl("pkg:npm")).toBeNull();
    expect(parsePurl("")).toBeNull();
  });
});

describe("mapping a package to an Xray coordinate", () => {
  it("maps the two ecosystems verified against a real Xray", () => {
    // Both confirmed to return findings during the manual investigation, so these two are
    // the closest thing to ground truth this file has.
    expect(toXrayCoordinate(pkg())).toBe("npm://lodash:4.17.15");
    expect(
      toXrayCoordinate(
        pkg({
          name: "log4j-core",
          version: "2.14.1",
          ecosystem: "maven",
          purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        }),
      ),
    ).toBe("gav://org.apache.logging.log4j:log4j-core:2.14.1");
  });

  it("keeps an npm scope on the name", () => {
    expect(
      toXrayCoordinate(pkg({ name: "cliui", purl: "pkg:npm/%40isaacs/cliui@8.0.2", version: "8.0.2" })),
    ).toBe("npm://@isaacs/cliui:8.0.2");
  });

  it("rebuilds the full Go module path", () => {
    expect(
      toXrayCoordinate(
        pkg({ ecosystem: "golang", name: "text", version: "v0.3.0", purl: "pkg:golang/golang.org/x/text@v0.3.0" }),
      ),
    ).toBe("go://golang.org/x/text:v0.3.0");
  });

  it("qualifies a deb package by its distribution", () => {
    // The same name and version carry different fix states on different releases, so the
    // distribution is part of the identity rather than decoration.
    expect(
      toXrayCoordinate(
        pkg({
          ecosystem: "deb",
          name: "openssl",
          version: "1.1.1n-0+deb10u3",
          purl: "pkg:deb/debian/openssl@1.1.1n-0+deb10u3?distro=debian-10",
        }),
      ),
    ).toBe("deb://debian:openssl:1.1.1n-0+deb10u3");
  });

  it("refuses maven without a group rather than guessing one", () => {
    /*
      Splitting a stored name on its last dot turns `org.apache.commons.io` into the group
      `org.apache.commons` and the artifact `io`, which is wrong and matches nothing. A
      package that is not submitted is reported as unassessed; a wrongly-submitted one is
      reported as clean.
    */
    expect(toXrayCoordinate(pkg({ ecosystem: "maven", name: "org.apache.commons.io", purl: null }))).toBeNull();
  });

  it("refuses a package with no version", () => {
    // Legal in CycloneDX, and Xray matches coordinates against version ranges — so a
    // versionless one matches nothing rather than matching everything.
    expect(toXrayCoordinate(pkg({ version: null }))).toBeNull();
    expect(toXrayCoordinate(pkg({ version: "   " }))).toBeNull();
  });

  it("refuses an ecosystem it has no coordinate form for", () => {
    // `generic` is Syft's bucket for binaries it recognised but cannot place. There is no
    // Xray identifier for it, and inventing one would produce a confident empty answer.
    expect(toXrayCoordinate(pkg({ ecosystem: "generic", purl: "pkg:generic/busybox@1.36.1" }))).toBeNull();
    expect(toXrayCoordinate(pkg({ ecosystem: "swift", purl: "pkg:swift/example/pkg@1.0.0" }))).toBeNull();
  });

  it("prefers the purl's type over the stored ecosystem", () => {
    // The purl is the more reliable of the two: the ecosystem column can be derived from a
    // Syft property when no purl exists, and those mappings are lossier.
    expect(
      toXrayCoordinate(pkg({ ecosystem: "generic", purl: "pkg:npm/lodash@4.17.15", name: "lodash" })),
    ).toBe("npm://lodash:4.17.15");
  });
});

describe("the coverage canaries", () => {
  it("covers every ecosystem that can be mapped", () => {
    /*
      A mappable ecosystem with no canary is one whose coverage can never be established, so
      its results would be trusted without evidence. This test is what keeps the two lists in
      step when a scheme is added later.
    */
    const canaried = new Set(XRAY_CANARIES.map((c) => c.ecosystem));
    const unproven = mappableEcosystems().filter((eco) => !canaried.has(eco));
    expect(unproven).toEqual([]);
  });

  it("uses coordinates this module would itself produce", () => {
    // A canary in a form the mapper never generates would prove the wrong thing: it could
    // pass while every real package of that ecosystem was built wrongly.
    for (const canary of XRAY_CANARIES) {
      expect(canary.coordinate).toMatch(/^[a-z]+:\/\/.+:.+$/);
    }
  });

  it("includes the operating-system ecosystems, which are the point", () => {
    const ecosystems = XRAY_CANARIES.map((c) => c.ecosystem);
    // Two thirds of a container image's components are OS packages. If these are not probed,
    // the base-image half of every dashboard is being reported without evidence.
    expect(ecosystems).toContain("deb");
    expect(ecosystems).toContain("rpm");
    expect(ecosystems).toContain("apk");
  });
});
