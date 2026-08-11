/**
 * Group and role membership for policy resolution.
 *
 * Resolution needs to know which groups and roles a user belongs to, because an
 * assignment can be attached to a group or a role rather than to a person. Without
 * this, a group-scoped assignment resolves to nothing and the access an
 * administrator granted silently does not exist.
 *
 * ## Why the server has to ask Cognito
 *
 * `/v1/resolve` is called by a remote *install* on behalf of a user named in the
 * query string. The bearer credential belongs to the install, so there is no user
 * token to read `cognito:groups` from -- the claim is only available on the admin
 * surface, where the human is the caller. So membership is looked up against the
 * user pool with `AdminListGroupsForUser`.
 *
 * ## Fail closed, and say why
 *
 * A Cognito outage must not silently empty everyone's group list. That would not
 * *look* like a failure: resolution would succeed, return a narrower policy, and
 * every group-scoped grant would quietly stop applying. Since merge is
 * most-restrictive-wins, the result is denial rather than disclosure -- safe, but
 * invisible, and an operator debugging "why did access disappear" has nothing to go
 * on.
 *
 * So a lookup failure **throws**, and `/v1/resolve` turns it into a 503. A denial an
 * operator can see beats a denial they cannot.
 *
 * ## Groups versus roles
 *
 * TOLAP distinguishes them (`AssigneeType.group` and `AssigneeType.role`), Cognito
 * does not -- it has one flat namespace. A configurable prefix separates them:
 * groups named `role:analyst` resolve as the role `analyst`, everything else is a
 * group. A deployment that does not want the distinction leaves the prefix unset and
 * gets groups only.
 */

import {
  AdminListGroupsForUserCommand,
  CognitoIdentityProviderClient,
  UserNotFoundException,
} from "@aws-sdk/client-cognito-identity-provider";

/** What the store needs. Matches `IdentityResolver` in `@aws/tolap-store`. */
export interface IdentitySource {
  getGroups(userId: string): Promise<string[]>;
  getRoles(userId: string): Promise<string[]>;
}

export class IdentityLookupError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "IdentityLookupError";
  }
}

export interface CognitoIdentityOptions {
  readonly userPoolId: string;
  /** Cognito group names starting with this resolve as TOLAP roles. */
  readonly rolePrefix?: string;
  /** How long a lookup is reused. Default 300s. */
  readonly cacheTtlSeconds?: number;
  /** Injectable for tests. */
  readonly client?: Pick<CognitoIdentityProviderClient, "send">;
}

interface CacheEntry {
  readonly groups: string[];
  readonly roles: string[];
  readonly at: number;
}

/**
 * Membership from a Cognito user pool.
 *
 * Requires `cognito-idp:AdminListGroupsForUser` on the pool. That is a read-only
 * permission and the only one this server needs -- it never creates, modifies or
 * deletes anything in the pool.
 */
export class CognitoIdentitySource implements IdentitySource {
  private readonly client: Pick<CognitoIdentityProviderClient, "send">;
  private readonly userPoolId: string;
  private readonly rolePrefix: string | undefined;
  private readonly ttlMs: number;
  private readonly cache = new Map<string, CacheEntry>();
  private readonly inFlight = new Map<string, Promise<CacheEntry>>();

  constructor(options: CognitoIdentityOptions) {
    this.userPoolId = options.userPoolId;
    this.rolePrefix = options.rolePrefix;
    this.ttlMs = (options.cacheTtlSeconds ?? 300) * 1000;
    this.client =
      options.client ?? new CognitoIdentityProviderClient({});
  }

  private async lookup(userId: string): Promise<CacheEntry> {
    const cached = this.cache.get(userId);
    if (cached && Date.now() - cached.at < this.ttlMs) return cached;

    // Collapse concurrent lookups for one user: a burst of resolve calls for the
    // same principal would otherwise each hit the Cognito API and share its
    // throttle budget.
    const existing = this.inFlight.get(userId);
    if (existing) return existing;

    const pending = (async () => {
      try {
        const names: string[] = [];
        let nextToken: string | undefined;

        // Paginate. A user in more groups than one page holds would otherwise get a
        // silently truncated list -- which reads as "not in that group" and denies
        // access the administrator granted.
        do {
          const response = await this.client.send(
            new AdminListGroupsForUserCommand({
              UserPoolId: this.userPoolId,
              Username: userId,
              Limit: 60,
              NextToken: nextToken,
            }),
          );
          for (const group of response.Groups ?? []) {
            if (group.GroupName) names.push(group.GroupName);
          }
          nextToken = response.NextToken;
        } while (nextToken);

        const groups: string[] = [];
        const roles: string[] = [];
        for (const name of names) {
          if (this.rolePrefix !== undefined && name.startsWith(this.rolePrefix)) {
            roles.push(name.slice(this.rolePrefix.length));
          } else {
            groups.push(name);
          }
        }

        const entry: CacheEntry = { groups, roles, at: Date.now() };
        this.cache.set(userId, entry);
        return entry;
      } catch (error) {
        if (error instanceof UserNotFoundException) {
          // A genuine, authoritative answer: this user has no groups because the
          // pool has no such user. Cached like any other result, so a service
          // account that resolves policy but is not a pool member does not
          // re-query on every call.
          const entry: CacheEntry = { groups: [], roles: [], at: Date.now() };
          this.cache.set(userId, entry);
          return entry;
        }
        // Everything else -- throttling, credentials, network, a misconfigured pool
        // id -- is a failure to *know*, not an answer. Returning [] here would
        // silently drop every group-scoped grant.
        throw new IdentityLookupError(
          `could not read group membership for '${userId}' from user pool ${this.userPoolId}`,
          { cause: error },
        );
      } finally {
        this.inFlight.delete(userId);
      }
    })();

    this.inFlight.set(userId, pending);
    return pending;
  }

  async getGroups(userId: string): Promise<string[]> {
    return (await this.lookup(userId)).groups;
  }

  async getRoles(userId: string): Promise<string[]> {
    return (await this.lookup(userId)).roles;
  }

  /** Drop a cached lookup, so a membership change takes effect immediately. */
  invalidate(userId?: string): void {
    if (userId === undefined) this.cache.clear();
    else this.cache.delete(userId);
  }
}

/**
 * Membership from static configuration.
 *
 * For deployments whose groups come from somewhere other than Cognito, and for
 * local development without a pool. Configured as
 * `alice=analysts,clinicians;bob=analysts`.
 */
export class StaticIdentitySource implements IdentitySource {
  private readonly groups: Map<string, string[]>;
  private readonly roles: Map<string, string[]>;

  constructor(
    groups: Record<string, string[]> = {},
    roles: Record<string, string[]> = {},
  ) {
    this.groups = new Map(Object.entries(groups));
    this.roles = new Map(Object.entries(roles));
  }

  static parse(spec: string): StaticIdentitySource {
    const groups: Record<string, string[]> = {};
    for (const entry of spec.split(";")) {
      const trimmed = entry.trim();
      if (trimmed === "") continue;
      const separator = trimmed.indexOf("=");
      if (separator <= 0) {
        throw new Error(
          `invalid group mapping ${JSON.stringify(trimmed)}: expected 'user=group,group'`,
        );
      }
      groups[trimmed.slice(0, separator).trim()] = trimmed
        .slice(separator + 1)
        .split(",")
        .map((name) => name.trim())
        .filter((name) => name !== "");
    }
    return new StaticIdentitySource(groups);
  }

  async getGroups(userId: string): Promise<string[]> {
    return this.groups.get(userId) ?? [];
  }

  async getRoles(userId: string): Promise<string[]> {
    return this.roles.get(userId) ?? [];
  }
}

/**
 * An identity source that knows nothing.
 *
 * Only for a deployment that uses no group- or role-scoped assignments at all.
 * Distinct from a *failing* source: this one is a truthful "no membership", which
 * is why it is a named class rather than an empty-object default nobody notices.
 */
export class NoIdentitySource implements IdentitySource {
  async getGroups(): Promise<string[]> {
    return [];
  }

  async getRoles(): Promise<string[]> {
    return [];
  }
}
