import { describe, expect, it } from "vitest";
import {
  createGroupRequestSchema,
  groupAdvisorySort,
  groupSort,
  listGroupsQuerySchema,
  setGroupMembersRequestSchema,
  updateGroupRequestSchema,
} from "@sbom/shared";

/**
 * The contracts around application groups.
 *
 * The aggregation itself needs a database and is verified against one; what is pinned here is
 * the shape of the requests, because every one of these is a place where a group could quietly
 * mean something other than the admin intended:
 *
 *   - membership arrives as a complete set, so a request that looked like a delta would
 *     replace the whole group with two applications instead of adding two;
 *   - an update that omits a field must leave it alone, while one that sends an empty
 *     description must clear it — collapsing those makes a description unremovable;
 *   - a name is trimmed and rejected when blank, or the group list grows an unclickable row
 *     with no visible name.
 */

describe("creating a group", () => {
  it("accepts a name alone", () => {
    // The common case: create it, then fill it from the member editor.
    const parsed = createGroupRequestSchema.parse({ name: "Checkout Platform" });
    expect(parsed.name).toBe("Checkout Platform");
    expect(parsed.applicationIds).toBeUndefined();
  });

  it("accepts initial membership, so creating and filling is one action", () => {
    const parsed = createGroupRequestSchema.parse({
      name: "Public Facing",
      applicationIds: ["3f1c2b4a-5d6e-4f70-8192-a3b4c5d6e7f8"],
    });
    expect(parsed.applicationIds).toHaveLength(1);
  });

  it("trims the name and rejects one that is only whitespace", () => {
    // A blank name renders as an empty cell that is still a link. Rejecting it here is the
    // only place that can be prevented without a database constraint on trimmed text.
    expect(createGroupRequestSchema.parse({ name: "  Payments  " }).name).toBe("Payments");
    expect(() => createGroupRequestSchema.parse({ name: "   " })).toThrow();
    expect(() => createGroupRequestSchema.parse({ name: "" })).toThrow();
  });

  it("rejects control characters in a name", () => {
    // They render as nothing, so two groups whose names differ only by one would look
    // identical in every list while being separate rows with separate membership.
    expect(() => createGroupRequestSchema.parse({ name: "Check\u0000out" })).toThrow();
  });

  it("rejects an application id that is not a uuid", () => {
    expect(() =>
      createGroupRequestSchema.parse({ name: "X", applicationIds: ["not-a-uuid"] }),
    ).toThrow();
  });
});

describe("updating a group", () => {
  it("requires at least one field", () => {
    // An empty PATCH would write an audit entry recording a change that never happened.
    expect(() => updateGroupRequestSchema.parse({})).toThrow();
  });

  it("distinguishes clearing a description from leaving it alone", () => {
    /*
      The distinction the service depends on. `undefined` means "not mentioned" and must
      preserve the stored value; `null` means "remove it". Collapsing them either makes a
      description impossible to delete, or wipes it on every rename.
    */
    const cleared = updateGroupRequestSchema.parse({ description: null });
    expect(cleared.description).toBeNull();

    const renamed = updateGroupRequestSchema.parse({ name: "Renamed" });
    expect("description" in renamed && renamed.description !== undefined).toBe(false);
  });
});

describe("setting membership", () => {
  it("accepts an empty list, which empties the group", () => {
    /*
      Deliberately legal. Removing the last member is a normal thing to do — a product
      retired, a trait no longer tracked — and rejecting it would leave the only way to empty
      a group being to delete and recreate it, losing its name and description.
    */
    expect(setGroupMembersRequestSchema.parse({ applicationIds: [] }).applicationIds).toEqual([]);
  });

  it("rejects a list large enough to be a mistake", () => {
    const tooMany = Array.from({ length: 501 }, () => "3f1c2b4a-5d6e-4f70-8192-a3b4c5d6e7f8");
    expect(() => setGroupMembersRequestSchema.parse({ applicationIds: tooMany })).toThrow();
  });
});

describe("list and sort contracts", () => {
  it("defaults to name order", () => {
    // A group list is read to find one by name, not to rank them.
    const query = listGroupsQuerySchema.parse({});
    expect(query.sortBy).toBe("name");
    expect(query.sortDir).toBe("asc");
  });

  it("rejects a sort column the query cannot serve", () => {
    // sortBy is interpolated into an ORDER BY, so an unvalidated value is an injection. The
    // shared table is what keeps the clickable headers and the accepted values in step.
    expect(() => listGroupsQuerySchema.parse({ sortBy: "; DROP TABLE" })).toThrow();
    expect(() => listGroupsQuerySchema.parse({ sortBy: "advisories" })).toThrow();
  });

  it("ranks a group's advisories by reach before anything else", () => {
    /*
      The default that makes the page worth opening. An advisory in eight of eight members is
      a base image nobody has updated; the same advisory in one of eight is a single rebuild.
      Sorting by severity first would interleave those and lose the distinction the column
      exists to show.
    */
    expect(groupAdvisorySort.defaultField).toBe("affectedMembers");
    expect(groupAdvisorySort.defaultDirection).toBe("desc");
  });

  it("offers a first click on each column that lands on the useful end", () => {
    // Names read A→Z; counts are asked about from the top.
    expect(groupSort.firstDirectionFor("name")).toBe("asc");
    expect(groupSort.firstDirectionFor("applicationCount")).toBe("desc");
    expect(groupSort.firstDirectionFor("createdAt")).toBe("desc");
  });
});
