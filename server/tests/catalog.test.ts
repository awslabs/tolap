/**
 * The source catalog and its importers.
 *
 * The catalog's whole purpose is to stop an author typing `ssn` when the column is
 * `ssn_number` -- a typo TOLAP cannot detect, because the resulting policy
 * validates, signs, resolves and enforces perfectly while protecting nothing. So
 * these tests care most about names coming through *exactly*, and about the
 * importers not quietly dropping things.
 */

import { describe, expect, it } from "vitest";
import {
  ManifestError,
  parseManifest,
  selectableFields,
} from "../src/catalog/manifest.ts";
import { importOpenApi } from "../src/catalog/import-openapi.ts";
import { importSqlDdl } from "../src/catalog/import-sql.ts";

describe("parseManifest", () => {
  it("derives the category from the identifier", () => {
    const manifest = parseManifest({
      sourceConnectionId: "db:analytics:patients",
      objects: [{ name: "patients", fields: ["id", "ssn"] }],
    });
    // Category comes from the id, never a separate field, so the two cannot
    // disagree -- and the signed policy's category is what picks the wrapper.
    expect(manifest.category).toBe("db");
    expect(manifest.objects[0].fields).toEqual(["id", "ssn"]);
  });

  it.each([
    "not-three-parts",
    "db:only-two",
    "db:a:b:c",
    "bogus:a:b",
    "db::name",
  ])("rejects identifier '%s'", (id) => {
    expect(() => parseManifest({ sourceConnectionId: id })).toThrow(ManifestError);
  });

  it("requires a source identifier", () => {
    expect(() => parseManifest({})).toThrow(ManifestError);
    expect(() => parseManifest(null)).toThrow(ManifestError);
    expect(() => parseManifest([])).toThrow(ManifestError);
  });

  it("defaults every collection to empty", () => {
    const manifest = parseManifest({ sourceConnectionId: "kb:corp:docs" });
    expect(manifest.objects).toEqual([]);
    expect(manifest.endpoints).toEqual([]);
    expect(manifest.tags).toEqual([]);
    expect(manifest.prefixes).toEqual([]);
  });

  it("rejects malformed objects and fields", () => {
    const bad = (objects: unknown) =>
      parseManifest({ sourceConnectionId: "db:a:b", objects });

    expect(() => bad([{ fields: ["x"] }])).toThrow(/non-empty name/);
    expect(() => bad([{ name: "  " }])).toThrow(/non-empty name/);
    expect(() => bad([{ name: "t", fields: ["ok", ""] }])).toThrow(/non-empty strings/);
    expect(() => bad([{ name: "t", fields: "not-an-array" }])).toThrow(/must be an array/);
    expect(() => bad("not-an-array")).toThrow(/must be an array/);
  });

  it("normalizes and validates endpoint methods", () => {
    const manifest = parseManifest({
      sourceConnectionId: "api:internal:x",
      endpoints: [{ path: "/a", methods: ["get", "Post"] }],
    });
    expect(manifest.endpoints[0].methods).toEqual(["GET", "POST"]);

    expect(() =>
      parseManifest({
        sourceConnectionId: "api:internal:x",
        endpoints: [{ path: "/a", methods: ["TRACE"] }],
      }),
    ).toThrow(/unsupported method/);
  });

  it("defaults an endpoint to GET rather than to every method", () => {
    // Offering DELETE by default would put a write method in front of an author
    // who never asked for one.
    const manifest = parseManifest({
      sourceConnectionId: "api:internal:x",
      endpoints: [{ path: "/a" }],
    });
    expect(manifest.endpoints[0].methods).toEqual(["GET"]);
  });

  it("drops unknown keys instead of rejecting them", () => {
    // A manifest exported from another tool may carry extra metadata, and it
    // cannot affect an access decision.
    const manifest = parseManifest({
      sourceConnectionId: "db:a:b",
      vendorMetadata: { anything: true },
    }) as Record<string, unknown>;
    expect(manifest.vendorMetadata).toBeUndefined();
  });
});

describe("selectableFields", () => {
  it("offers both dotted and bare field names", () => {
    const manifest = parseManifest({
      sourceConnectionId: "db:analytics:patients",
      objects: [{ name: "patients", fields: ["ssn"] }],
    });
    // `patients.ssn` scopes a column to one table for a db policy; the bare `ssn`
    // is what api and kb policies match on (connector-spec section 3.2).
    expect(selectableFields(manifest)).toEqual(["patients.ssn", "ssn"]);
  });

  it("deduplicates a field shared by two objects", () => {
    const manifest = parseManifest({
      sourceConnectionId: "db:a:b",
      objects: [
        { name: "t1", fields: ["id"] },
        { name: "t2", fields: ["id"] },
      ],
    });
    expect(selectableFields(manifest)).toEqual(["id", "t1.id", "t2.id"]);
  });
});

describe("importSqlDdl", () => {
  it("reads tables and columns from CREATE TABLE", () => {
    const manifest = importSqlDdl(
      "db:analytics:patients",
      `CREATE TABLE patients (patient_id uuid, full_name text, ssn char(11));`,
    );
    expect(manifest.objects).toEqual([
      { name: "patients", fields: ["patient_id", "full_name", "ssn"] },
    ]);
  });

  it("skips table-level constraints", () => {
    // A PRIMARY KEY line is not a column. Offering "primary" as a field name
    // would put a value in the dropdown that can never match anything.
    const manifest = importSqlDdl(
      "db:a:b",
      `CREATE TABLE t (
         id uuid,
         region text,
         PRIMARY KEY (id),
         CONSTRAINT uq UNIQUE (region),
         FOREIGN KEY (region) REFERENCES r(code),
         CHECK (region <> ''),
         UNIQUE (id, region)
       );`,
    );
    expect(manifest.objects[0].fields).toEqual(["id", "region"]);
  });

  it("does not split a column on commas inside parentheses", () => {
    // NUMERIC(10,2) and CHECK (x IN (1,2)) both contain commas that must not be
    // read as column separators.
    const manifest = importSqlDdl(
      "db:a:b",
      `CREATE TABLE t (balance numeric(10,2), tier int CHECK (tier IN (1,2,3)), name text);`,
    );
    expect(manifest.objects[0].fields).toEqual(["balance", "tier", "name"]);
  });

  it("handles quoted, bracketed and schema-qualified names", () => {
    const manifest = importSqlDdl(
      "db:a:b",
      `CREATE TABLE "public"."Users" ("userId" uuid, [Name] text, \`email\` text);`,
    );
    expect(manifest.objects[0].name).toBe("Users");
    expect(manifest.objects[0].fields).toEqual(["userId", "Name", "email"]);
  });

  it("ignores comments", () => {
    const manifest = importSqlDdl(
      "db:a:b",
      `-- a comment mentioning fake_column
       /* block comment with another_fake */
       CREATE TABLE t (real_column text);`,
    );
    expect(manifest.objects[0].fields).toEqual(["real_column"]);
  });

  it("reads several tables and sorts them", () => {
    const manifest = importSqlDdl(
      "db:a:b",
      `CREATE TABLE zebra (id int);
       CREATE TABLE alpha (id int, name text);
       CREATE TABLE IF NOT EXISTS middle (id int);`,
    );
    expect(manifest.objects.map((o) => o.name)).toEqual([
      "alpha",
      "middle",
      "zebra",
    ]);
  });

  it("falls back to an information_schema column dump", () => {
    const manifest = importSqlDdl(
      "db:a:b",
      ` table_name | column_name
       ------------+-------------
        patients   | patient_id
        patients   | ssn
        encounters | id
       (3 rows)`,
    );
    expect(manifest.objects).toEqual([
      { name: "encounters", fields: ["id"] },
      { name: "patients", fields: ["patient_id", "ssn"] },
    ]);
  });

  it("accepts a CSV column dump", () => {
    const manifest = importSqlDdl("db:a:b", "patients,ssn\npatients,region");
    expect(manifest.objects[0].fields).toEqual(["ssn", "region"]);
  });

  it("rejects input with nothing recognizable", () => {
    expect(() => importSqlDdl("db:a:b", "SELECT 1;")).toThrow(/no tables found/);
    expect(() => importSqlDdl("db:a:b", "")).toThrow(ManifestError);
  });

  it("validates the identifier like any other manifest", () => {
    expect(() => importSqlDdl("nonsense", "CREATE TABLE t (id int);")).toThrow(
      ManifestError,
    );
  });
});

describe("importOpenApi", () => {
  const spec = {
    info: { title: "Clinical API" },
    paths: {
      "/api/v1/patients/{id}": {
        get: {
          responses: {
            "200": {
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/Patient" },
                },
              },
            },
          },
        },
        delete: { responses: { "204": {} } },
      },
      "/api/v1/labs": {
        get: {
          responses: {
            "200": {
              content: {
                "application/json": {
                  schema: {
                    type: "array",
                    items: { properties: { test: {}, value: {} } },
                  },
                },
              },
            },
          },
        },
      },
    },
    components: {
      schemas: {
        Patient: {
          properties: {
            id: {},
            full_name: {},
            ssn: {},
            address: { properties: { city: {}, zip: {} } },
          },
        },
      },
    },
  };

  it("converts path templates to TOLAP globs", () => {
    // OpenAPI writes `/patients/{id}`; TOLAP endpoint rules glob as
    // `/patients/*`. Keeping the literal `{id}` would produce a pattern that
    // never matches at enforcement time.
    const manifest = importOpenApi("api:internal:clinical", spec);
    const paths = manifest.endpoints.map((e) => e.path);
    expect(paths).toContain("/api/v1/patients/*");
    expect(paths).not.toContain("/api/v1/patients/{id}");
  });

  it("collects methods per path", () => {
    const manifest = importOpenApi("api:internal:clinical", spec);
    const patients = manifest.endpoints.find((e) =>
      e.path.startsWith("/api/v1/patients"),
    );
    expect(patients!.methods).toEqual(["GET", "DELETE"]);
  });

  it("resolves $ref and collects nested field names", () => {
    const manifest = importOpenApi("api:internal:clinical", spec);
    const patients = manifest.endpoints.find((e) =>
      e.path.startsWith("/api/v1/patients"),
    );
    // Nested properties are collected by their own names, which is how api field
    // rules match (connector-spec section 3.2).
    expect(patients!.responseFields).toEqual([
      "address",
      "city",
      "full_name",
      "id",
      "ssn",
      "zip",
    ]);
  });

  it("reads array item schemas", () => {
    const manifest = importOpenApi("api:internal:clinical", spec);
    const labs = manifest.endpoints.find((e) => e.path === "/api/v1/labs");
    expect(labs!.responseFields).toEqual(["test", "value"]);
  });

  it("uses the spec title as the display name", () => {
    expect(importOpenApi("api:internal:clinical", spec).displayName).toBe(
      "Clinical API",
    );
  });

  it("ignores remote $ref rather than fetching it", () => {
    // Following a remote ref would mean issuing an HTTP request from an
    // authenticated admin endpoint -- an SSRF primitive, for a catalog that only
    // fills dropdowns.
    const remote = {
      paths: {
        "/x": {
          get: {
            responses: {
              "200": {
                content: {
                  "application/json": {
                    schema: { $ref: "https://evil.example/schema.json" },
                  },
                },
              },
            },
          },
        },
      },
    };
    const manifest = importOpenApi("api:internal:x", remote);
    expect(manifest.endpoints[0].responseFields).toEqual([]);
  });

  it("resolves a $ref only against keys the document declares", () => {
    // A JSON Pointer is a caller-supplied path walked over an uploaded document, so
    // `#/__proto__` or `#/constructor/prototype` asks to leave that document and read
    // the runtime's object graph.
    //
    // Honest about what this covers: through the HTTP route it was never exploitable,
    // because `JSON.parse` keeps a literal `"__proto__"` as an ordinary own key instead
    // of setting the prototype. The inherited-member case below is therefore reachable
    // only by a caller that hands `deref` a hand-built object -- a YAML loader, or a
    // fixture like this one. That is exactly why it is pinned: the previous safety was a
    // side effect of the type guard and of the parser upstream, and a test that only
    // fed it JSON could not tell the difference.
    const pointers = ["#/__proto__", "#/constructor/prototype", "#/toString"];
    for (const ref of pointers) {
      const spec = {
        paths: {
          "/x": {
            get: {
              responses: {
                "200": { content: { "application/json": { schema: { $ref: ref } } } },
              },
            },
          },
        },
      };
      expect(
        importOpenApi("api:internal:x", spec).endpoints[0]!.responseFields,
        ref,
      ).toEqual([]);
    }

    // The case that actually distinguishes own-keys-only from a plain index: a schema
    // reachable by inheritance, which index access would happily follow.
    const leaky = Object.create({
      Inherited: { type: "object", properties: { leaked: { type: "string" } } },
    }) as Record<string, unknown>;
    leaky.Declared = { type: "object", properties: { fine: { type: "string" } } };

    const withInherited = {
      paths: {
        "/x": {
          get: {
            responses: {
              "200": {
                content: {
                  "application/json": { schema: { $ref: "#/schemas/Inherited" } },
                },
              },
            },
          },
        },
      },
      schemas: leaky,
    };
    expect(
      importOpenApi("api:internal:x", withInherited).endpoints[0]!.responseFields,
    ).toEqual([]);

    // ...while the sibling the document really declares still resolves.
    const withDeclared = {
      ...withInherited,
      paths: {
        "/x": {
          get: {
            responses: {
              "200": {
                content: {
                  "application/json": { schema: { $ref: "#/schemas/Declared" } },
                },
              },
            },
          },
        },
      },
    };
    expect(
      importOpenApi("api:internal:x", withDeclared).endpoints[0]!.responseFields,
    ).toEqual(["fine"]);

    expect(Object.keys(Object.prototype)).toEqual([]);
  });

  it("still resolves a legitimate local $ref", () => {
    // The guard above must not have cost the feature it protects.
    const spec = {
      paths: {
        "/x": {
          get: {
            responses: {
              "200": {
                content: {
                  "application/json": {
                    schema: { $ref: "#/components/schemas/Patient" },
                  },
                },
              },
            },
          },
        },
      },
      components: {
        schemas: {
          Patient: {
            type: "object",
            properties: { id: { type: "string" }, ssn: { type: "string" } },
          },
        },
      },
    };
    expect(importOpenApi("api:internal:x", spec).endpoints[0]!.responseFields).toEqual([
      "id",
      "ssn",
    ]);
  });

  it("survives a self-referential schema", () => {
    const recursive = {
      paths: {
        "/tree": {
          get: {
            responses: {
              "200": {
                content: {
                  "application/json": {
                    schema: { $ref: "#/components/schemas/Node" },
                  },
                },
              },
            },
          },
        },
      },
      components: {
        schemas: {
          Node: {
            properties: {
              name: {},
              child: { $ref: "#/components/schemas/Node" },
            },
          },
        },
      },
    };
    const manifest = importOpenApi("api:internal:x", recursive);
    expect(manifest.endpoints[0].responseFields).toContain("name");
    expect(manifest.endpoints[0].responseFields).toContain("child");
  });

  it("handles allOf composition", () => {
    const composed = {
      paths: {
        "/x": {
          get: {
            responses: {
              "200": {
                content: {
                  "application/json": {
                    schema: {
                      allOf: [
                        { properties: { a: {} } },
                        { properties: { b: {} } },
                      ],
                    },
                  },
                },
              },
            },
          },
        },
      },
    };
    expect(importOpenApi("api:internal:x", composed).endpoints[0].responseFields).toEqual(
      ["a", "b"],
    );
  });

  it("keeps an endpoint that has no documented response schema", () => {
    // A path with methods but no schema is still worth offering; dropping it
    // would hide a real endpoint from the author.
    const manifest = importOpenApi("api:internal:x", {
      paths: { "/ping": { get: { responses: { "200": {} } } } },
    });
    expect(manifest.endpoints).toEqual([
      { path: "/ping", methods: ["GET"], responseFields: [] },
    ]);
  });

  it("rejects a spec with no usable paths", () => {
    expect(() => importOpenApi("api:internal:x", {})).toThrow(/no 'paths'/);
    expect(() => importOpenApi("api:internal:x", { paths: {} })).toThrow(
      /no endpoints/,
    );
    expect(() =>
      importOpenApi("api:internal:x", { paths: { "/x": { summary: "no methods" } } }),
    ).toThrow(/no endpoints/);
    expect(() => importOpenApi("api:internal:x", "not an object")).toThrow(
      ManifestError,
    );
  });
});
