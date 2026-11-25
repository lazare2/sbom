import type { DirectoryDiagnosis, DirectoryGroup, DirectoryPerson } from "@sbom/shared";

/**
 * One kind of directory, as the rest of the platform sees it.
 *
 * Everything above this interface - linking squads to groups, the sync, sign-in membership -
 * asks these few questions and never learns which directory answered. A new kind of directory
 * (Entra ID through Microsoft Graph, say) is one more implementation of this, nothing else.
 *
 * Read only. No method changes anything in the directory.
 */
export interface DirectoryConnector {
  /** Connects, signs in, finds the base and runs one sample search. Never throws. */
  test(): Promise<DirectoryDiagnosis>;
  /** Groups whose name contains `query`, at most `limit`. */
  findGroups(query: string, limit?: number): Promise<DirectoryGroup[]>;
  /** One group by its permanent id, or null when it no longer exists. */
  group(id: string): Promise<DirectoryGroup | null>;
  /** Everyone in the group, including through groups nested inside it. */
  members(groupId: string): Promise<DirectoryPerson[]>;
  /** A person by email address (the attribute the connection names), or null. */
  personByEmail(email: string): Promise<DirectoryPerson | null>;
  /** Ids of every group the person is in, directly or through nested groups. */
  groupsOf(personId: string): Promise<string[]>;
}

/** Raised for a failure the screen can explain; `code` says which step failed. */
export class DirectoryError extends Error {
  constructor(
    readonly code: DirectoryDiagnosis["code"],
    message: string,
    readonly detail: string | null = null,
  ) {
    super(message);
  }
}
