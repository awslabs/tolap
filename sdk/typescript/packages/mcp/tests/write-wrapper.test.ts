/**
 * The write entry points an integrator actually calls (connector spec §4).
 *
 * `packages/core/tests/write-enforcement.test.ts` pins the decisions;
 * `packages/core/tests/write-path-parity.test.ts` pins them against the other two
 * SDKs. This file covers what only exists at the wrapper level:
 *
 * - `preWrite` / `executeWriteWithEnforcement` on the context wrapper
 * - the HTTP wrapper's write path, over an in-process transport
 * - §4.5 post-write results: a write's response IS a read of the data it returns
 * - that a denied write reaches neither the write function nor the transport
 *
 * The Python counterpart is `tests/test_write_enforcement.py`.
 */

import { describe, expect, it } from "vitest";

import {
  buildSecurityContext,
  signContext,
  MaskType,
  WriteOperation,
  type EffectivePolicy,
  type ObjectRules,
  type PolicyPermissions,
  type SecurityContext,
} from "@aws/tolap-core";
import { SecureContextToolWrapper } from "../src/context-wrapper.js";
import { SecureHttpToolWrapper, type FetchLike } from "../src/http-wrapper.js";

const KEY = "write-wrapper-key";

function policy(
  permissions: Partial<PolicyPermissions> = {},
  objectRules?: ObjectRules,
): EffectivePolicy {
  const now = new Date();
  return {
    version: "1.0",
    userId: "u",
    tenantId: "t",
    sourceConnectionId: "db:write-wrapper:patients",
    resolvedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3_600_000).toISOString(),
    sourceProfiles: ["write-wrapper"],
    permissions: {
      canQuery: true,
      readOnly: false,
      ...permissions,
    },
    ...(objectRules !== undefined ? { objectRules } : {}),
    integrity: { algorithm: "none", signature: "" },
  };
}

function signed(p: EffectivePolicy): SecurityContext {
  return signContext(buildSecurityContext(p.userId, p.tenantId, p, 3_600_000), KEY);
}

// ---------------------------------------------------------------------------
// SecureContextToolWrapper
// ---------------------------------------------------------------------------

describe("SecureContextToolWrapper: preWrite", () => {
  const WRITE_POLICY = policy(
    { canInsert: true, canUpdate: true },
    {
      allowedObjects: ["patients"],
      fieldRules: {
        hiddenFields: ["patients.ssn"],
        readOnlyFields: ["patients.created_at"],
        maskedFields: [
          {
            field: "patients.email",
            maskType: MaskType.Partial,
            parameters: { showFirst: 1 },
          },
        ],
      },
    },
  );

  const wrapper = () => new SecureContextToolWrapper({ signingKey: KEY });

  it("validates the context before the policy", () => {
    // A forged context is a signature failure, not a policy decision: the context
    // has to be trustworthy before its policy means anything, and checking the
    // policy first would let an attacker's own policy answer the question.
    const forged = signed(WRITE_POLICY);
    forged.signature = "not-the-real-signature";

    const result = wrapper().preWrite(forged, WriteOperation.Insert, "patients", {
      full_name: "x",
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("invalid signature");
  });

  it("permits a writable payload", () => {
    const result = wrapper().preWrite(
      signed(WRITE_POLICY),
      WriteOperation.Insert,
      "patients",
      { full_name: "x" },
    );

    expect(result.allowed).toBe(true);
  });

  it("denies a read-only field", () => {
    const result = wrapper().preWrite(
      signed(WRITE_POLICY),
      WriteOperation.Insert,
      "patients",
      { created_at: "x" },
    );

    expect(result.reason).toBe("field is read-only: created_at");
  });

  it("accepts the operation as a string as well as an enum member", () => {
    // The wrapper forwards the argument rather than narrowing it, so an integrator
    // reading a verb off the wire does not have to map it to the enum first.
    const context = signed(WRITE_POLICY);

    expect(
      wrapper().preWrite(context, "insert", "patients", { full_name: "x" }).allowed,
    ).toBe(true);
    expect(wrapper().preWrite(context, "delete", "patients", null).reason).toBe(
      "delete not permitted",
    );
  });

  it("passes fullReplace through to the write checks", () => {
    // Same body, two verdicts, and the only difference is the replace semantics: the
    // flag has to survive the wrapper hop or the HTTP PUT rule has no teeth.
    const context = signed(WRITE_POLICY);

    const partial = wrapper().preWrite(context, WriteOperation.Update, "patients", {
      full_name: "x",
    });
    const replace = wrapper().preWrite(
      context,
      WriteOperation.Update,
      "patients",
      { full_name: "x" },
      { fullReplace: true },
    );

    expect(partial.allowed).toBe(true);
    expect(replace.allowed).toBe(false);
    expect(replace.reason).toBe("field is hidden: patients.ssn");
  });

  it("names a protected field a full replace body already carries only once", () => {
    // The reason has to be the payload's own spelling (`patients.ssn` as written
    // here matches the rule exactly), not a second copy appended by the replace
    // expansion -- otherwise a caller could see the same field reported twice, or
    // reported under the policy's spelling rather than their own.
    const result = wrapper().preWrite(
      signed(WRITE_POLICY),
      WriteOperation.Update,
      "patients",
      { "patients.ssn": "1", full_name: "x" },
      { fullReplace: true },
    );

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("field is hidden: patients.ssn");
  });
});

describe("SecureContextToolWrapper: executeWriteWithEnforcement", () => {
  const WRITE_POLICY = policy(
    { canInsert: true, canUpdate: true },
    {
      allowedObjects: ["patients"],
      fieldRules: {
        hiddenFields: ["patients.ssn"],
        readOnlyFields: ["patients.created_at"],
        maskedFields: [
          {
            field: "patients.email",
            maskType: MaskType.Partial,
            parameters: { showFirst: 1 },
          },
        ],
      },
    },
  );

  const wrapper = () => new SecureContextToolWrapper({ signingKey: KEY });

  it("never calls the write function for a denied write", async () => {
    // The whole point of pre-write validation: there is nothing to filter
    // afterwards. If the function ran and we then denied, the row would already be
    // committed.
    let calls = 0;
    const writeFn = () => {
      calls += 1;
      return { id: 1 };
    };

    await expect(
      wrapper().executeWriteWithEnforcement(
        signed(WRITE_POLICY),
        WriteOperation.Insert,
        writeFn,
        "patients",
        { ssn: "1" },
      ),
    ).rejects.toThrow(/Access denied: field is hidden: ssn/);

    expect(calls).toBe(0);
  });

  it("runs the read pipeline over data a write returns", async () => {
    // §4.5: a write's response IS a read of the data it returns. The caller wrote
    // `email` itself and gets it back masked, because what comes back is a read and
    // every read is masked. A hidden field it did not write does not appear at all
    // -- an INSERT ... RETURNING * would otherwise disclose it.
    const returned = (await wrapper().executeWriteWithEnforcement(
      signed(WRITE_POLICY),
      WriteOperation.Insert,
      () => ({ id: 1, email: "alice@example.com", ssn: "111-22-3333" }),
      "patients",
      { email: "alice@example.com" },
    )) as Record<string, unknown>;

    expect(returned["email"]).toBe("a****************");
    expect(returned).not.toHaveProperty("ssn");
    expect(returned["id"]).toBe(1);
  });

  it("runs the pipeline over every record of a list a write returns", async () => {
    // A multi-row INSERT ... RETURNING is a read of every row it returns, not just
    // the first.
    const returned = (await wrapper().executeWriteWithEnforcement(
      signed(WRITE_POLICY),
      WriteOperation.Insert,
      async () => [
        { id: 1, ssn: "1", email: "a@b.c" },
        { id: 2, ssn: "2", email: "d@e.f" },
      ],
      "patients",
      { email: "a@b.c" },
    )) as Array<Record<string, unknown>>;

    expect(returned.every((record) => !("ssn" in record))).toBe(true);
    expect(returned.map((record) => record["email"])).toEqual(["a****", "d****"]);
  });

  it.each([
    ["null", null],
    ["undefined", undefined],
  ])("passes a write returning %s through rather than denying it", async (_label, empty) => {
    // There is no data to enforce a policy over, so nothing is a violation. Denying
    // here would make every DELETE fail: a delete legitimately returns nothing, and
    // the shape rules exist to stop *data* escaping unenforced.
    const returned = await wrapper().executeWriteWithEnforcement(
      signed(WRITE_POLICY),
      WriteOperation.Insert,
      () => empty,
      "patients",
      { full_name: "x" },
    );

    expect(returned).toBe(empty);
  });

  it("still denies a write returning a scalar", async () => {
    // A non-nullish unenforceable shape is denied exactly as on the read path. A row
    // count is fine to return, but the wrapper cannot tell a count from a leaked
    // value, so canonical spec §5 applies unchanged.
    await expect(
      wrapper().executeWriteWithEnforcement(
        signed(WRITE_POLICY),
        WriteOperation.Insert,
        () => "1 row inserted",
        "patients",
        { full_name: "x" },
      ),
    ).rejects.toThrow(/cannot be policy-enforced/);
  });

  it("awaits an async write function and a sync one alike", async () => {
    // An integrator's driver call is a promise; a mock or an in-memory store is not.
    // Both must be enforced, so the shape of the callback cannot decide whether the
    // pipeline runs.
    const context = signed(WRITE_POLICY);

    const fromAsync = await wrapper().executeWriteWithEnforcement(
      context,
      WriteOperation.Insert,
      async () => ({ id: 1, ssn: "leak" }),
      "patients",
      { full_name: "x" },
    );
    const fromSync = await wrapper().executeWriteWithEnforcement(
      context,
      WriteOperation.Insert,
      () => ({ id: 1, ssn: "leak" }),
      "patients",
      { full_name: "x" },
    );

    expect(fromAsync).toEqual({ id: 1 });
    expect(fromSync).toEqual({ id: 1 });
  });
});

// ---------------------------------------------------------------------------
// SecureHttpToolWrapper
// ---------------------------------------------------------------------------

describe("SecureHttpToolWrapper: the write path", () => {
  const POLICY = policy(
    { canInsert: true },
    {
      endpointRules: {
        allowedEndpoints: ["/patients", "/patients/*"],
        allowedMethods: ["GET", "POST", "PUT"],
      },
      fieldRules: {
        hiddenFields: ["ssn"],
        readOnlyFields: ["created_at"],
        maskedFields: [
          { field: "email", maskType: MaskType.Partial, parameters: { showFirst: 1 } },
        ],
      },
    },
  );

  /** A transport that echoes the request body back inside a created resource. */
  function echoWrapper() {
    const calls: Array<Parameters<FetchLike>[0]> = [];
    const fetchFn: FetchLike = async (input) => {
      calls.push(input);
      return {
        ok: true,
        status: 201,
        json: async () => ({
          id: 7,
          email: "alice@example.com",
          ssn: "111",
          ...(typeof input.body === "object" && input.body !== null ? input.body : {}),
        }),
      };
    };
    return {
      instance: new SecureHttpToolWrapper({ signingKey: KEY }, fetchFn),
      calls,
    };
  }

  it("never puts bytes on the transport for a denied write", async () => {
    // The denial has to happen before the request leaves the process; a server-side
    // rejection would already have disclosed the payload.
    const { instance, calls } = echoWrapper();

    await expect(
      instance.request(signed(POLICY), {
        method: "POST",
        path: "/patients",
        body: { created_at: "x" },
      }),
    ).rejects.toThrow(/Access denied: field is read-only: created_at/);

    expect(calls).toEqual([]);
  });

  it("masks and strips a 201 body like any read", async () => {
    // §4.5 over HTTP: the created resource's body is a read of it.
    const { instance } = echoWrapper();

    const body = (await instance.request(signed(POLICY), {
      method: "POST",
      path: "/patients",
      body: { email: "alice@example.com" },
    })) as Record<string, unknown>;

    expect(body["email"]).toBe("a****************");
    expect(body).not.toHaveProperty("ssn");
    expect(body["id"]).toBe(7);
  });

  it("denies a PUT for a protected field the body omits", async () => {
    // The full-replace rule reaches the HTTP wrapper. canUpdate is granted here and
    // PUT is in allowedMethods, so the only thing refusing this is the replace
    // semantics treating `ssn` as written.
    const { instance, calls } = echoWrapper();
    const context = signed(
      policy({ canUpdate: true }, POLICY.objectRules),
    );

    await expect(
      instance.request(context, {
        method: "PUT",
        path: "/patients/1",
        body: { full_name: "x" },
      }),
    ).rejects.toThrow(/Access denied: field is hidden: ssn/);

    expect(calls).toEqual([]);
  });

  it("passes the object name through to the object rules", async () => {
    const { instance } = echoWrapper();
    const context = signed(
      policy(
        { canInsert: true },
        {
          hiddenObjects: ["audit_log"],
          endpointRules: {
            allowedEndpoints: ["/patients", "/patients/*"],
            allowedMethods: ["POST"],
          },
        },
      ),
    );

    await expect(
      instance.request(context, {
        method: "POST",
        path: "/patients",
        body: { a: 1 },
        objectName: "audit_log",
      }),
    ).rejects.toThrow(/Access denied: object is hidden/);
  });

  it("passes the target row through to the row check", async () => {
    // Without this hop a DELETE under a row-scoped policy would be refused as
    // unverifiable even when the integrator had read the row and could prove it
    // qualified.
    const rules: ObjectRules = {
      rowFilters: [{ field: "region", operator: "equals", value: "us-east" }],
      endpointRules: {
        allowedEndpoints: ["/patients/*"],
        allowedMethods: ["DELETE"],
      },
    };
    const context = signed(policy({ canDelete: true }, rules));

    const permitted = echoWrapper();
    await expect(
      permitted.instance.request(context, {
        method: "DELETE",
        path: "/patients/1",
        targetRow: { region: "us-east" },
      }),
    ).resolves.toBeDefined();
    expect(permitted.calls).toHaveLength(1);

    const refused = echoWrapper();
    await expect(
      refused.instance.request(context, {
        method: "DELETE",
        path: "/patients/1",
        targetRow: { region: "eu-west" },
      }),
    ).rejects.toThrow(/Access denied: target row not permitted/);
    expect(refused.calls).toEqual([]);
  });

  it("extends a PUT to an allowedFields allow-list via resourceFields", async () => {
    // The policy cannot know which resource fields its allow-list omits, so the
    // integrator supplies the shape; the argument has to reach validateHttpWrite for
    // that to mean anything.
    const context = signed(
      policy(
        { canUpdate: true },
        {
          endpointRules: {
            allowedEndpoints: ["/patients/*"],
            allowedMethods: ["PUT"],
          },
          fieldRules: { allowedFields: ["full_name"] },
        },
      ),
    );

    const { instance, calls } = echoWrapper();
    await expect(
      instance.request(context, {
        method: "PUT",
        path: "/patients/1",
        body: { full_name: "x" },
        resourceFields: ["ssn"],
      }),
    ).rejects.toThrow(/Access denied: field not in allowed set: ssn/);
    expect(calls).toEqual([]);
  });

  it("leaves a read unaffected by the write checks", async () => {
    // Regression guard: routing reads through the same entry point as writes must
    // not make canQuery depend on canInsert. A policy granting no write permission
    // at all still reads.
    const calls: Array<Parameters<FetchLike>[0]> = [];
    const fetchFn: FetchLike = async (input) => {
      calls.push(input);
      return { ok: true, status: 200, json: async () => ({ id: 1, ssn: "111" }) };
    };
    const instance = new SecureHttpToolWrapper({ signingKey: KEY }, fetchFn);

    const body = await instance.request(
      signed(policy({ readOnly: true }, POLICY.objectRules)),
      { method: "GET", path: "/patients" },
    );

    expect(body).toEqual({ id: 1 });
    expect(calls).toHaveLength(1);
  });
});
