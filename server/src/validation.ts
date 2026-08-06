/**
 * Policy and assignment validation against the v1.0 JSON Schema.
 *
 * Two modes, following the pattern the Python suite already established in
 * `sdk/python/tests/test_schema_fixture_validation.py`:
 *
 * - **document** -- the full schema, including top-level `required`. What a policy
 *   must satisfy to be published.
 * - **fragment** -- the same schema with top-level `required` removed and
 *   everything else intact: types, enums, bounds, `additionalProperties: false`,
 *   and *nested* `required`. What a half-authored draft is checked against, so the
 *   console can validate as someone types without demanding a complete document
 *   on the first keystroke.
 *
 * Validation lives here rather than in the SDKs on purpose. `CONTRIBUTING.md`
 * requires the core packages stay dependency-free, and the enforcement spec's own
 * reasoning argues against three independent draft-2020-12 interpretations -- which
 * is an argument for one central validator. Ajv is a server dependency only.
 *
 * All errors are returned, never just the first: an author fixing one field at a
 * time because the validator only ever reports one problem is a worse experience
 * than seeing the whole list.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv2020, type ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** Repository schema directory. The schemas are the normative artifact. */
const SCHEMA_DIR = path.resolve(HERE, "../../schema/v1.0");

export type SchemaName = "policy-definition" | "policy-assignment";

export interface ValidationError {
  /** JSON Pointer-ish path to the offending value, e.g. `/permissions/canQuery`. */
  readonly path: string;
  readonly message: string;
}

export interface ValidationResult {
  readonly valid: boolean;
  readonly errors: ValidationError[];
}

function loadSchema(name: SchemaName): Record<string, unknown> {
  // Throws rather than returning a default. A validator that silently falls back
  // to "no schema" would report every policy as valid, which is the worst possible
  // failure mode for this component.
  const file = path.join(SCHEMA_DIR, `${name}.schema.json`);
  return JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
}

function buildValidator(
  schema: Record<string, unknown>,
  fragment: boolean,
): ValidateFunction {
  const ajv = new Ajv2020({
    allErrors: true,
    // The schemas carry `$schema`/`$id` and a `format` here and there; neither
    // should abort compilation.
    strict: false,
  });
  addFormats(ajv);

  let effective = schema;
  if (fragment) {
    // Structured clone so the document validator is unaffected. Only the
    // top-level `required` is dropped -- nested `required` (a masking rule needs
    // `field` and `maskType`; a filter needs `field` and `operator`) still applies,
    // because a half-written masking rule is a mistake even in a draft.
    effective = structuredClone(schema);
    delete effective.required;
  }
  return ajv.compile(effective);
}

// Compiling Ajv schemas is not cheap and these are immutable, so cache the four
// validators (two schemas x two modes) for the process lifetime.
const cache = new Map<string, ValidateFunction>();

function validator(name: SchemaName, fragment: boolean): ValidateFunction {
  const key = `${name}:${fragment}`;
  let found = cache.get(key);
  if (!found) {
    found = buildValidator(loadSchema(name), fragment);
    cache.set(key, found);
  }
  return found;
}

/**
 * Validate a policy definition or assignment.
 *
 * @param fragment Relax only the top-level `required` list, for drafts.
 */
export function validateSchema(
  data: unknown,
  name: SchemaName,
  options: { fragment?: boolean } = {},
): ValidationResult {
  const validate = validator(name, options.fragment === true);
  const valid = validate(data) as boolean;

  if (valid) return { valid: true, errors: [] };

  const errors = (validate.errors ?? []).map((error) => ({
    // Ajv's instancePath is "" at the root, which reads as a missing value in a
    // UI; name the document instead.
    path: error.instancePath === "" ? "/" : error.instancePath,
    message: error.message ?? "is invalid",
  }));

  // Sorted so the same bad document always produces the same list -- an unstable
  // order makes diffing two validation runs pointlessly noisy.
  errors.sort((a, b) =>
    a.path === b.path
      ? a.message.localeCompare(b.message)
      : a.path.localeCompare(b.path),
  );

  return { valid: false, errors };
}

/**
 * Validate a definition and throw a single readable error if it fails.
 *
 * For write paths, where a partial policy must not reach the datastore at all.
 */
export function assertValidDefinition(data: unknown): void {
  const result = validateSchema(data, "policy-definition");
  if (!result.valid) {
    throw new SchemaValidationError(result.errors);
  }
}

export class SchemaValidationError extends Error {
  readonly errors: ValidationError[];

  constructor(errors: ValidationError[]) {
    super(
      `policy failed schema validation: ${errors
        .map((e) => `${e.path} ${e.message}`)
        .join("; ")}`,
    );
    this.name = "SchemaValidationError";
    this.errors = errors;
  }
}
