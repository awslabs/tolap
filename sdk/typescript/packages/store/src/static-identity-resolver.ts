/**
 * TOLAP Static Identity Resolver
 *
 * A simple identity resolver backed by static Maps, useful for testing.
 */

import type { IdentityResolver } from "./types.js";

export class StaticIdentityResolver implements IdentityResolver {
  private groups = new Map<string, string[]>();
  private roles = new Map<string, string[]>();

  /** Set groups for a user. */
  setGroups(userId: string, groupIds: string[]): void {
    this.groups.set(userId, groupIds);
  }

  /** Set roles for a user. */
  setRoles(userId: string, roleIds: string[]): void {
    this.roles.set(userId, roleIds);
  }

  async getGroups(userId: string): Promise<string[]> {
    return this.groups.get(userId) ?? [];
  }

  async getRoles(userId: string): Promise<string[]> {
    return this.roles.get(userId) ?? [];
  }
}
