/**
 * Group and role membership.
 *
 * The behavior that matters most is the failure mode. If a Cognito outage produced
 * an empty group list, resolution would succeed and return a *narrower* policy --
 * every group-scoped grant silently gone. Merge is most-restrictive-wins, so the
 * outcome is denial rather than disclosure, which is safe but invisible: nothing in
 * the response, the policy, or the audit log would say the server had guessed.
 *
 * So a lookup failure throws. Those tests are the point of this file; the caching
 * ones exist because a per-request Cognito call would be throttled in production.
 */

import { describe, expect, it, vi } from "vitest";
import {
  AdminListGroupsForUserCommand,
  UserNotFoundException,
} from "@aws-sdk/client-cognito-identity-provider";
import {
  CognitoIdentitySource,
  IdentityLookupError,
  NoIdentitySource,
  StaticIdentitySource,
} from "../src/auth/identity-source.ts";

/** A stub Cognito client returning fixed pages. */
function client(
  pages: Array<{ Groups?: Array<{ GroupName?: string }>; NextToken?: string }>,
) {
  const send = vi.fn();
  for (const page of pages) send.mockResolvedValueOnce(page);
  return { send: send as never, calls: send };
}

const source = (
  stub: { send: never },
  options: { rolePrefix?: string; cacheTtlSeconds?: number } = {},
) =>
  new CognitoIdentitySource({
    userPoolId: "us-east-1_test",
    client: stub,
    ...options,
  });

describe("CognitoIdentitySource", () => {
  it("returns the user's Cognito groups", async () => {
    const stub = client([
      { Groups: [{ GroupName: "analysts" }, { GroupName: "clinicians" }] },
    ]);
    expect(await source(stub).getGroups("alice")).toEqual([
      "analysts",
      "clinicians",
    ]);
  });

  it("queries the configured pool for the named user", async () => {
    // The install's credential authenticates the *call*; the policy resolves for
    // whoever the query string named, so that is who gets looked up.
    const stub = client([{ Groups: [] }]);
    await source(stub).getGroups("alice");

    const command = stub.calls.mock.calls[0]![0] as AdminListGroupsForUserCommand;
    expect(command).toBeInstanceOf(AdminListGroupsForUserCommand);
    expect(command.input.Username).toBe("alice");
    expect(command.input.UserPoolId).toBe("us-east-1_test");
  });

  it("follows pagination", async () => {
    // A truncated list reads as "not in that group" and denies access the
    // administrator granted, so every page has to be read.
    const stub = client([
      { Groups: [{ GroupName: "g1" }], NextToken: "page2" },
      { Groups: [{ GroupName: "g2" }], NextToken: "page3" },
      { Groups: [{ GroupName: "g3" }] },
    ]);
    expect(await source(stub).getGroups("alice")).toEqual(["g1", "g2", "g3"]);
    expect(stub.calls).toHaveBeenCalledTimes(3);
  });

  it("splits roles from groups by prefix", async () => {
    // Cognito has one flat namespace; TOLAP distinguishes group from role.
    const stub = client([
      {
        Groups: [
          { GroupName: "analysts" },
          { GroupName: "role:clinician" },
          { GroupName: "role:auditor" },
        ],
      },
    ]);
    const identity = source(stub, { rolePrefix: "role:" });
    expect(await identity.getGroups("alice")).toEqual(["analysts"]);
    expect(await identity.getRoles("alice")).toEqual(["clinician", "auditor"]);
  });

  it("treats everything as a group when no prefix is configured", async () => {
    const stub = client([
      { Groups: [{ GroupName: "analysts" }, { GroupName: "role:clinician" }] },
    ]);
    const identity = source(stub);
    expect(await identity.getGroups("alice")).toEqual([
      "analysts",
      "role:clinician",
    ]);
    expect(await identity.getRoles("alice")).toEqual([]);
  });

  it("ignores groups with no name", async () => {
    const stub = client([{ Groups: [{ GroupName: "ok" }, {}] }]);
    expect(await source(stub).getGroups("alice")).toEqual(["ok"]);
  });

  describe("failure handling", () => {
    it("throws rather than returning an empty list", async () => {
      // The core assertion. An empty list here would look exactly like "this user
      // is in no groups", and every group-scoped grant would vanish silently.
      const send = vi.fn().mockRejectedValue(new Error("ThrottlingException"));
      const identity = source({ send } as never);

      await expect(identity.getGroups("alice")).rejects.toThrow(
        IdentityLookupError,
      );
      await expect(identity.getGroups("alice")).rejects.toThrow(/alice/);
    });

    it("names the pool in the error, for a misconfigured pool id", async () => {
      const send = vi.fn().mockRejectedValue(new Error("ResourceNotFoundException"));
      await expect(source({ send } as never).getRoles("alice")).rejects.toThrow(
        /us-east-1_test/,
      );
    });

    it("preserves the underlying cause", async () => {
      const cause = new Error("ThrottlingException");
      const send = vi.fn().mockRejectedValue(cause);
      await expect(source({ send } as never).getGroups("alice")).rejects.toThrow(
        expect.objectContaining({ cause }),
      );
    });

    it("treats an unknown user as an authoritative empty result", async () => {
      // Distinct from a failure: the pool answered, and the answer is that there is
      // no such user. A service account resolving policy without being a pool
      // member is a normal case, not an outage.
      const send = vi.fn().mockRejectedValue(
        new UserNotFoundException({ message: "User does not exist", $metadata: {} }),
      );
      const identity = source({ send } as never);

      expect(await identity.getGroups("service-account-1")).toEqual([]);
      // Cached, so it does not re-query on every resolve.
      await identity.getGroups("service-account-1");
      expect(send).toHaveBeenCalledTimes(1);
    });

    it("does not cache a failure", async () => {
      // A throttle must not pin an empty answer for the cache lifetime.
      const send = vi
        .fn()
        .mockRejectedValueOnce(new Error("ThrottlingException"))
        .mockResolvedValueOnce({ Groups: [{ GroupName: "analysts" }] });
      const identity = source({ send } as never);

      await expect(identity.getGroups("alice")).rejects.toThrow(
        IdentityLookupError,
      );
      expect(await identity.getGroups("alice")).toEqual(["analysts"]);
    });
  });

  describe("caching", () => {
    it("reuses a lookup for both groups and roles", async () => {
      const stub = client([{ Groups: [{ GroupName: "analysts" }] }]);
      const identity = source(stub, { rolePrefix: "role:" });

      await identity.getGroups("alice");
      await identity.getRoles("alice");
      await identity.getGroups("alice");
      // One lookup answers both questions; three calls must not be three round
      // trips to Cognito.
      expect(stub.calls).toHaveBeenCalledTimes(1);
    });

    it("collapses concurrent lookups for the same user", async () => {
      let resolvePage: (value: unknown) => void = () => {};
      const send = vi.fn().mockImplementation(
        () => new Promise((resolve) => (resolvePage = resolve)),
      );
      const identity = source({ send } as never);

      const both = Promise.all([
        identity.getGroups("alice"),
        identity.getRoles("alice"),
      ]);
      resolvePage({ Groups: [{ GroupName: "analysts" }] });
      await both;

      // A burst of resolve calls for one principal shares one API call rather than
      // each consuming throttle budget.
      expect(send).toHaveBeenCalledTimes(1);
    });

    it("keeps separate entries per user", async () => {
      const stub = client([
        { Groups: [{ GroupName: "analysts" }] },
        { Groups: [{ GroupName: "clinicians" }] },
      ]);
      const identity = source(stub);
      expect(await identity.getGroups("alice")).toEqual(["analysts"]);
      expect(await identity.getGroups("bob")).toEqual(["clinicians"]);
    });

    it("re-queries after the TTL expires", async () => {
      const stub = client([
        { Groups: [{ GroupName: "analysts" }] },
        { Groups: [{ GroupName: "analysts" }, { GroupName: "new-group" }] },
      ]);
      const identity = source(stub, { cacheTtlSeconds: 0 });

      expect(await identity.getGroups("alice")).toEqual(["analysts"]);
      expect(await identity.getGroups("alice")).toEqual([
        "analysts",
        "new-group",
      ]);
    });

    it("can be invalidated so a membership change takes effect at once", async () => {
      const stub = client([
        { Groups: [{ GroupName: "analysts" }] },
        { Groups: [] },
      ]);
      const identity = source(stub);

      expect(await identity.getGroups("alice")).toEqual(["analysts"]);
      identity.invalidate("alice");
      expect(await identity.getGroups("alice")).toEqual([]);
    });

    it("can be invalidated wholesale", async () => {
      const stub = client([
        { Groups: [{ GroupName: "a" }] },
        { Groups: [{ GroupName: "b" }] },
      ]);
      const identity = source(stub);
      await identity.getGroups("alice");
      identity.invalidate();
      expect(await identity.getGroups("alice")).toEqual(["b"]);
    });
  });
});

describe("StaticIdentitySource", () => {
  it("returns configured membership", async () => {
    const identity = new StaticIdentitySource(
      { alice: ["analysts"] },
      { alice: ["clinician"] },
    );
    expect(await identity.getGroups("alice")).toEqual(["analysts"]);
    expect(await identity.getRoles("alice")).toEqual(["clinician"]);
    expect(await identity.getGroups("nobody")).toEqual([]);
  });

  it("parses the configuration form", async () => {
    const identity = StaticIdentitySource.parse(
      "alice=analysts,clinicians; bob=analysts",
    );
    expect(await identity.getGroups("alice")).toEqual([
      "analysts",
      "clinicians",
    ]);
    expect(await identity.getGroups("bob")).toEqual(["analysts"]);
  });

  it("rejects a malformed mapping instead of ignoring it", async () => {
    // Silently skipping an unparseable entry would drop somebody's group
    // membership with no signal.
    expect(() => StaticIdentitySource.parse("alice-analysts")).toThrow(
      /expected 'user=group,group'/,
    );
  });

  it("tolerates trailing separators and blank entries", async () => {
    const identity = StaticIdentitySource.parse("alice=analysts;;");
    expect(await identity.getGroups("alice")).toEqual(["analysts"]);
  });
});

describe("NoIdentitySource", () => {
  it("returns nothing for everyone", async () => {
    // A truthful "no membership", for a deployment that uses no group- or
    // role-scoped assignments. Named rather than an anonymous default so choosing
    // it is visible in the code and in the startup log.
    const identity = new NoIdentitySource();
    expect(await identity.getGroups("alice")).toEqual([]);
    expect(await identity.getRoles("alice")).toEqual([]);
  });
});
