/**
 * The source catalog manifest: what a data source *contains*.
 *
 * Its only job is to let the console offer dropdowns of real object and field
 * names instead of free-text boxes. That is the highest-value correctness feature
 * in this server: `hiddenFields: ["ssn"]` protects nothing if the column is
 * actually `ssn_number`, and **nothing in TOLAP can detect that typo** -- the
 * policy validates, signs, resolves and enforces perfectly while protecting a
 * column that does not exist.
 *
 * ## Not an enforcement input
 *
 * Enforcement reads the signed policy and never this manifest. A catalog that
 * could influence an access decision would be a new trust dependency, and a stale
 * one would silently change what an existing policy means. Nothing here is signed,
 * and nothing here is consulted at resolve time.
 *
 * ## No credentials
 *
 * Manifests arrive by upload or import; the server never dials a data source to
 * discover one. Holding read-only source credentials would give the policy server
 * a data-source secret store, which is exactly what the SDKs avoid by never taking
 * a connection -- see docs/architecture.md on why the factory does not resolve
 * credentials.
 */

import { parseSourceIdentity } from "@tolap/core";

export class ManifestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ManifestError";
  }
}

/** A table, collection, or other addressable object and its fields. */
export interface CatalogObject {
  readonly name: string;
  readonly fields: string[];
}

/** An API endpoint, its methods, and the fields its response carries. */
export interface CatalogEndpoint {
  readonly path: string;
  readonly methods: string[];
  readonly responseFields: string[];
}

export interface SourceManifest {
  readonly sourceConnectionId: string;
  readonly category: "db" | "api" | "kb" | "storage";
  readonly displayName?: string;
  /** `db` tables and columns; also used for `kb` document attributes. */
  readonly objects: CatalogObject[];
  /** `api` only. */
  readonly endpoints: CatalogEndpoint[];
  /** `kb` classification tags. */
  readonly tags: string[];
  /** `storage` prefixes. */
  readonly prefixes: string[];
}

/** Methods the policy schema's `allowedMethods` enum permits. */
const HTTP_METHODS = new Set([
  "GET",
  "HEAD",
  "OPTIONS",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
]);

function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ManifestError("manifest must be a JSON object");
  }
  return value as Record<string, unknown>;
}

function stringArray(value: unknown, what: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new ManifestError(`${what} must be an array of strings`);
  }
  return value.map((entry) => {
    if (typeof entry !== "string" || entry.trim() === "") {
      throw new ManifestError(`${what} must contain only non-empty strings`);
    }
    return entry;
  });
}

/**
 * Validate and normalize a manifest.
 *
 * Unknown keys are dropped rather than rejected: a manifest exported from some
 * other tool may carry extra metadata, and refusing it would make the import
 * path needlessly brittle for something that cannot affect an access decision.
 */
export function parseManifest(input: unknown): SourceManifest {
  const raw = asRecord(input);

  const sourceConnectionId = raw.sourceConnectionId;
  if (typeof sourceConnectionId !== "string") {
    throw new ManifestError("sourceConnectionId is required");
  }

  // The category comes from the identifier rather than a separate field, so the
  // two can never disagree. `== null` because the TypeScript SDK returns
  // `undefined` here while the Python one returns `None`.
  const identity = parseSourceIdentity(sourceConnectionId);
  if (identity == null) {
    throw new ManifestError(
      "sourceConnectionId must be 'category:namespace:name' with category one of db, api, kb, storage",
    );
  }

  const objects = (raw.objects === undefined ? [] : raw.objects) as unknown;
  if (!Array.isArray(objects)) {
    throw new ManifestError("objects must be an array");
  }

  const parsedObjects: CatalogObject[] = objects.map((entry) => {
    const object = asRecord(entry);
    if (typeof object.name !== "string" || object.name.trim() === "") {
      throw new ManifestError("every object needs a non-empty name");
    }
    return {
      name: object.name,
      fields: stringArray(object.fields, `object '${object.name}' fields`),
    };
  });

  const endpoints = (raw.endpoints === undefined ? [] : raw.endpoints) as unknown;
  if (!Array.isArray(endpoints)) {
    throw new ManifestError("endpoints must be an array");
  }

  const parsedEndpoints: CatalogEndpoint[] = endpoints.map((entry) => {
    const endpoint = asRecord(entry);
    if (typeof endpoint.path !== "string" || endpoint.path.trim() === "") {
      throw new ManifestError("every endpoint needs a non-empty path");
    }
    const methods = stringArray(
      endpoint.methods,
      `endpoint '${endpoint.path}' methods`,
    ).map((method) => method.toUpperCase());

    for (const method of methods) {
      if (!HTTP_METHODS.has(method)) {
        throw new ManifestError(
          `endpoint '${endpoint.path}' has unsupported method '${method}'`,
        );
      }
    }

    return {
      path: endpoint.path,
      // Default to GET rather than to every method: a catalog entry that offered
      // DELETE by default would put it in front of an author who never asked for
      // it.
      methods: methods.length > 0 ? methods : ["GET"],
      responseFields: stringArray(
        endpoint.responseFields,
        `endpoint '${endpoint.path}' responseFields`,
      ),
    };
  });

  const displayName = raw.displayName;
  if (displayName !== undefined && typeof displayName !== "string") {
    throw new ManifestError("displayName must be a string");
  }

  return {
    sourceConnectionId,
    category: identity.category as SourceManifest["category"],
    ...(displayName !== undefined ? { displayName } : {}),
    objects: parsedObjects,
    endpoints: parsedEndpoints,
    tags: stringArray(raw.tags, "tags"),
    prefixes: stringArray(raw.prefixes, "prefixes"),
  };
}

/**
 * Every field name a policy author could pick for this source, in
 * `object.field` form plus the bare names.
 *
 * The dot form is what a `db` policy uses to scope a column to one table; the bare
 * form is what an `api` or `kb` policy uses, where fields are not table-qualified
 * (connector-spec section 3.2).
 */
export function selectableFields(manifest: SourceManifest): string[] {
  const fields = new Set<string>();
  for (const object of manifest.objects) {
    for (const field of object.fields) {
      fields.add(`${object.name}.${field}`);
      fields.add(field);
    }
  }
  for (const endpoint of manifest.endpoints) {
    for (const field of endpoint.responseFields) {
      fields.add(field);
    }
  }
  return [...fields].sort();
}
