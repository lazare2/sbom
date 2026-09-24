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
      qualifiers: {},
    });
  });

  it("keeps a multi-segment namespace whole, as Go modules need", () => {
    expect(parsePurl("pkg:golang/github.com/gin-gonic/gin@v1.9.0")).toEqual({
      type: "golang",
      namespace: "github.com/gin-gonic",
      name: "gin",
      version: "v1.9.0",
      qualifiers: {},
    });
  });

  it("keeps qualifiers, because deb and rpm identifiers need the architecture", () => {
    const parsed = parsePurl("pkg:deb/debian/openssl@1.1.1n-0+deb10u3?distro=debian-10&arch=amd64");
    expect(parsed).toEqual({
      type: "deb",
      namespace: "debian",
      name: "openssl",
      version: "1.1.1n-0+deb10u3",
      qualifiers: { distro: "debian-10", arch: "amd64" },
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

  it("puts the architecture in a deb identifier, and leaves the distribution out", () => {
    /*
      JFrog's form is `deb://[dist:]<arch>:<name>:<version>`. The dist segment is optional and
      is omitted deliberately: their examples use release codenames (`lucid`), while Syft
      supplies `debian-10`. Those are different vocabularies, and a wrong dist matches nothing
      while reading perfectly well in a log.
    */
    expect(
      toXrayCoordinate(
        pkg({
          ecosystem: "deb",
          name: "openssl",
          version: "1.1.1n-0+deb10u3",
          purl: "pkg:deb/debian/openssl@1.1.1n-0+deb10u3?distro=debian-10&arch=amd64",
        }),
      ),
    ).toBe("deb://amd64:openssl:1.1.1n-0+deb10u3");
  });

  it("refuses an OS package with no architecture rather than guessing one", () => {
    // An OS package assessed against the wrong architecture is worse than one honestly
    // reported as unassessed: the fix state genuinely differs between builds.
    expect(
      toXrayCoordinate(
        pkg({ ecosystem: "deb", name: "openssl", version: "1.1.1n", purl: "pkg:deb/debian/openssl@1.1.1n" }),
      ),
    ).toBeNull();
  });

  it("uses pip, not pypi, for Python packages", () => {
    // Corrected against JFrog's published examples after being written from memory the other
    // way round. `pip://` is also the form the original manual investigation used.
    expect(
      toXrayCoordinate(
        pkg({ ecosystem: "pypi", name: "django", version: "2.2.0", purl: "pkg:pypi/django@2.2.0" }),
      ),
    ).toBe("pip://django:2.2.0");
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

describe("Alpine packages, against identifiers a real Xray produced", () => {
  /*
    Every expectation here is copied from a live server rather than from documentation.

    An SBOM this platform exported was enriched by an organisation's own Xray, and the file
    came back listing that server's identifiers for the packages it recognised. Those strings
    are the only direct evidence this repository has of what Xray actually matches on, and
    they disagreed with what this module was generating.

    The bug they exposed is the one the whole module is written to prevent. `alpine` had been
    inferred from the single-segment pattern the other ecosystems use, so every apk package on
    every image was submitted as `alpine://<name>:<version>`, matched nothing, and came back
    indistinguishable from a package that had been checked and found clean. On an Alpine image
    that is most of the component list.
  */

  function apk(name: string, version: string, purl: string): ScannablePackage {
    return pkg({ ecosystem: "apk", name, version, purl });
  }

  it("carries the release, which is what the server keys on", () => {
    expect(
      toXrayCoordinate(
        apk("libssl3", "3.1.4-r5", "pkg:apk/alpine/libssl3@3.1.4-r5?arch=x86_64&distro=alpine-3.18.6"),
      ),
    ).toBe("alpine://3.18:libssl3:3.1.4-r5");
  });

  it("shortens the release to two components, as the server does", () => {
    // Syft records `alpine-3.18.6`; the identifier that came back said `3.18`. Submitting the
    // patch version is submitting a release Xray has no index for.
    expect(
      toXrayCoordinate(
        apk("musl", "1.2.4-r2", "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=alpine-3.18.6"),
      ),
    ).toBe("alpine://3.18:musl:1.2.4-r2");
  });

  it("decodes a percent-encoded name", () => {
    // `libstdc++` travels through a purl as `libstdc%2B%2B` and came back from the server
    // decoded. A coordinate still carrying the escapes is a different string entirely.
    expect(
      toXrayCoordinate(
        apk(
          "libstdc++",
          "12.2.1_git20220924-r10",
          "pkg:apk/alpine/libstdc%2B%2B@12.2.1_git20220924-r10?arch=x86_64&distro=alpine-3.18.6",
        ),
      ),
    ).toBe("alpine://3.18:libstdc++:12.2.1_git20220924-r10");
  });

  it("keeps a name that already contains a dash", () => {
    expect(
      toXrayCoordinate(
        apk(
          "busybox-binsh",
          "1.36.1-r5",
          "pkg:apk/alpine/busybox-binsh@1.36.1-r5?arch=x86_64&distro=alpine-3.18.6&upstream=busybox",
        ),
      ),
    ).toBe("alpine://3.18:busybox-binsh:1.36.1-r5");
  });

  it("carries no architecture, unlike deb and rpm", () => {
    // The purl has `arch=x86_64` and the server's identifier does not mention it. Assuming
    // the OS ecosystems share one shape is what produced the original mistake.
    const coordinate = toXrayCoordinate(
      apk("apk-tools", "2.14.0-r2", "pkg:apk/alpine/apk-tools@2.14.0-r2?arch=x86_64&distro=alpine-3.18.6"),
    );
    expect(coordinate).not.toContain("x86_64");
  });

  it("refuses a package whose release cannot be read", () => {
    /*
      Null, not a best guess. A rolling release has no number to submit, and a package with no
      distro qualifier gives nothing to derive one from — in both cases the coordinate would
      match nothing while reporting as assessed.
    */
    expect(
      toXrayCoordinate(apk("musl", "1.2.4-r2", "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=alpine-edge")),
    ).toBeNull();
    expect(toXrayCoordinate(apk("musl", "1.2.4-r2", "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64"))).toBeNull();
  });

  it("accepts a release with no distribution name in front of it", () => {
    // Not every producer writes `alpine-`; a bare version is still a release.
    expect(
      toXrayCoordinate(apk("musl", "1.2.4-r2", "pkg:apk/alpine/musl@1.2.4-r2?distro=3.18.6")),
    ).toBe("alpine://3.18:musl:1.2.4-r2");
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
    /*
      This assertion used to be `/^[a-z]+:\/\/.+:.+$/`, and the broken Alpine canary passed
      it: `alpine://openssl:1.1.1k-r0` is well formed, just in a different ecosystem's shape.
      So the probe reported Alpine as uncovered, which read as a fact about the server rather
      than a bug here, and every apk package went unassessed behind a plausible explanation.

      Checking each canary against a coordinate the mapper genuinely builds is what turns this
      from a spelling check into a proof that the probe tests what the sweep submits.
    */
    const samples: Record<string, ScannablePackage> = {
      npm: pkg({ purl: "pkg:npm/axios@0.21.4", name: "axios", version: "0.21.4" }),
      apk: pkg({
        ecosystem: "apk",
        name: "libssl3",
        version: "3.1.4-r5",
        purl: "pkg:apk/alpine/libssl3@3.1.4-r5?arch=x86_64&distro=alpine-3.18.6",
      }),
      deb: pkg({
        ecosystem: "deb",
        name: "openssl",
        version: "1.1.1n-0+deb10u3",
        purl: "pkg:deb/debian/openssl@1.1.1n-0%2Bdeb10u3?arch=amd64",
      }),
      rpm: pkg({
        ecosystem: "rpm",
        name: "openssl",
        version: "1.1.1k-4.el8",
        purl: "pkg:rpm/rhel/openssl@1.1.1k-4.el8?arch=x86_64",
      }),
      maven: pkg({
        ecosystem: "maven",
        name: "log4j-core",
        version: "2.14.1",
        purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      }),
    };

    /** How many colon-separated fields follow the scheme — the part that differs per shape. */
    const fields = (coordinate: string) =>
      coordinate.slice(coordinate.indexOf("://") + 3).split(":").length;

    const wrongShape = Object.entries(samples)
      .filter(([ecosystem, sample]) => {
        const produced = toXrayCoordinate(sample);
        const canary = XRAY_CANARIES.find((c) => c.ecosystem === ecosystem)!;
        return produced === null || fields(produced) !== fields(canary.coordinate);
      })
      .map(([ecosystem]) => ecosystem);

    expect(wrongShape).toEqual([]);
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
