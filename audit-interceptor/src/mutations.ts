/**
 * Classification of GraphQL mutation operation names that the interceptor
 * recognizes for audit purposes. Any mutation not listed here is still audited
 * as a generic admin.unknown event with the raw variables.
 */

export type TargetKind = "user" | "group" | "membership" | "attribute" | "unknown";

export interface MutationSpec {
  eventType: string;
  targetKind: TargetKind;
  /** JSON path (dot notation) inside variables that resolves to the target id */
  idPath: string | null;
  /** Fetch entity state before forwarding the mutation */
  needsPreImage: boolean;
  /** Fetch entity state after forwarding the mutation */
  needsPostImage: boolean;
  /** Second target id path for membership operations (groupId) */
  secondaryIdPath?: string | null;
}

export const MUTATIONS: Record<string, MutationSpec> = {
  // Users
  CreateUser: {
    eventType: "admin.user.create",
    targetKind: "user",
    idPath: "user.id",
    needsPreImage: false,
    needsPostImage: true,
  },
  UpdateUser: {
    eventType: "admin.user.update",
    targetKind: "user",
    idPath: "user.id",
    needsPreImage: true,
    needsPostImage: true,
  },
  DeleteUser: {
    eventType: "admin.user.delete",
    targetKind: "user",
    idPath: "userId",
    needsPreImage: true,
    needsPostImage: false,
  },
  DeleteUserQuery: {
    eventType: "admin.user.delete",
    targetKind: "user",
    idPath: "userId",
    needsPreImage: true,
    needsPostImage: false,
  },

  // Groups
  CreateGroup: {
    eventType: "admin.group.create",
    targetKind: "group",
    idPath: "name",
    needsPreImage: false,
    needsPostImage: true,
  },
  UpdateGroup: {
    eventType: "admin.group.update",
    targetKind: "group",
    idPath: "group.id",
    needsPreImage: true,
    needsPostImage: true,
  },
  DeleteGroup: {
    eventType: "admin.group.delete",
    targetKind: "group",
    idPath: "groupId",
    needsPreImage: true,
    needsPostImage: false,
  },
  DeleteGroupQuery: {
    eventType: "admin.group.delete",
    targetKind: "group",
    idPath: "groupId",
    needsPreImage: true,
    needsPostImage: false,
  },

  // Memberships
  AddUserToGroup: {
    eventType: "admin.group.member.add",
    targetKind: "membership",
    idPath: "user",
    secondaryIdPath: "group",
    needsPreImage: false,
    needsPostImage: false,
  },
  RemoveUserFromGroup: {
    eventType: "admin.group.member.remove",
    targetKind: "membership",
    idPath: "user",
    secondaryIdPath: "group",
    needsPreImage: false,
    needsPostImage: false,
  },

  // Attributes / schema (audit but do not fetch entity images)
  AddUserAttribute: {
    eventType: "admin.schema.user-attribute.add",
    targetKind: "attribute",
    idPath: "name",
    needsPreImage: false,
    needsPostImage: false,
  },
  DeleteUserAttribute: {
    eventType: "admin.schema.user-attribute.delete",
    targetKind: "attribute",
    idPath: "name",
    needsPreImage: false,
    needsPostImage: false,
  },
  AddGroupAttribute: {
    eventType: "admin.schema.group-attribute.add",
    targetKind: "attribute",
    idPath: "name",
    needsPreImage: false,
    needsPostImage: false,
  },
  DeleteGroupAttribute: {
    eventType: "admin.schema.group-attribute.delete",
    targetKind: "attribute",
    idPath: "name",
    needsPreImage: false,
    needsPostImage: false,
  },
};

export function resolvePath(obj: unknown, path: string | null | undefined): string | null {
  if (!path) return null;
  const parts = path.split(".");
  let cur: unknown = obj;
  for (const p of parts) {
    if (cur && typeof cur === "object" && p in (cur as Record<string, unknown>)) {
      cur = (cur as Record<string, unknown>)[p];
    } else {
      return null;
    }
  }
  return typeof cur === "string" || typeof cur === "number" ? String(cur) : null;
}

const MUTATION_REGEX = /^\s*mutation\b/i;

/** Best-effort check: does the raw GraphQL query text start with `mutation`? */
export function looksLikeMutation(query: string | undefined): boolean {
  if (!query) return false;
  return MUTATION_REGEX.test(query);
}
