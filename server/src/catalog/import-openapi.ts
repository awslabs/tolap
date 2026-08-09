/**
 * Build an `api` manifest from an OpenAPI document.
 *
 * Administrators already have OpenAPI specs for their internal services, so
 * importing one beats hand-writing a manifest -- and a hand-written list of
 * endpoints is exactly where a typo becomes a policy that protects nothing.
 *
 * This is a **pragmatic reader, not a validator**. It pulls out paths, methods and
 * response field names and ignores everything else. A spec it cannot fully
 * understand still yields a usable catalog rather than an error, because the
 * catalog only populates dropdowns: a missing field means an author types it
 * manually, which is where they started.
 */

import { ManifestError, parseManifest, type SourceManifest } from "./manifest.ts";

const METHODS = [
  "get",
  "head",
  "options",
  "post",
  "put",
  "patch",
  "delete",
] as const;

type Json = Record<string, unknown>;

const isRecord = (value: unknown): value is Json =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * One step of a JSON Pointer walk, confined to keys the document itself declares.
 *
 * A JSON Pointer is a caller-supplied path walked over an uploaded document, so
 * `#/__proto__` or `#/constructor/prototype` is a request to leave that document and
 * read the runtime's object graph. `Object.entries` yields own enumerable keys only, so
 * a pointer reaches nothing the spec did not declare — inherited members included.
 *
 * Two things this is **not**. It is not a fix for prototype pollution: nothing is
 * written here, so the concern was only ever the read. And it was not exploitable
 * through the HTTP route before — `JSON.parse` keeps a literal `"__proto__"` as an
 * ordinary own key rather than setting the prototype, so a request body cannot produce
 * an object with inherited members, and `isRecord` rejected the prototype itself anyway.
 * Both verified rather than assumed.
 *
 * It is kept because the safety was incidental: it rested on the shape of the type guard
 * and on the parser upstream, neither stated here, and a future caller handing `deref` a
 * hand-built object — a YAML loader that does honour `__proto__`, a fixture — would get a
 * different answer. This makes the rule local and legible, and clears the Semgrep finding
 * for dynamic member access on a caller-supplied key, which is worth clearing rather than
 * annotating in a repository whose subject is access control.
 */
function ownChild(node: Json, key: string): unknown {
  return ownKeys(node).get(key);
}

/**
 * The own-key map for a node, built once.
 *
 * Rebuilding it per pointer *step* made a lookup cost the width of the node being
 * walked, and `#/components/schemas/X` walks `components` -- so a spec with N schemas and
 * N paths did N lookups over N entries. Measured 113ms at 150 KB and 2.0s at 600 KB,
 * quadratic in a document an admin uploads. Caching keeps every property the comment
 * above depends on (still `Object.entries`, still own enumerable keys only) and makes
 * repeated lookups against the same node free. Weak so a rejected spec is collectable.
 */
const keyCache = new WeakMap<Json, Map<string, unknown>>();

function ownKeys(node: Json): Map<string, unknown> {
  let keys = keyCache.get(node);
  if (keys === undefined) {
    keys = new Map(Object.entries(node));
    keyCache.set(node, keys);
  }
  return keys;
}

/**
 * Follow a local `$ref` such as `#/components/schemas/Patient`.
 *
 * Iterative rather than recursive on the ref-chasing step. A chain of refs that each
 * point at the next is not a cycle, so `seen` does not stop it, and it recursed once per
 * link: 10,000 links -- well inside the 2 MB body limit -- threw `RangeError: Maximum
 * call stack size exceeded`, which escapes `importOpenApi` as a 500 instead of the 422 a
 * malformed spec should get. A loop bounds the stack at one frame; `seen` still bounds
 * the iterations, because a chain cannot revisit a ref without terminating.
 */
function deref(root: Json, node: unknown, seen = new Set<string>()): unknown {
  let target = node;

  for (;;) {
    if (!isRecord(target)) return target;
    const ref = target.$ref;
    if (typeof ref !== "string") return target;

    // Only local refs. Chasing a remote one would mean fetching a URL during an
    // authenticated admin request -- an SSRF primitive for no benefit here.
    if (!ref.startsWith("#/")) return undefined;
    // A self-referential schema (a tree node whose child is the same type) would
    // otherwise loop forever.
    if (seen.has(ref)) return undefined;
    seen.add(ref);

    let current: unknown = root;
    for (const segment of ref.slice(2).split("/")) {
      if (!isRecord(current)) return undefined;
      // JSON Pointer escapes, so a key containing "/" or "~" resolves correctly.
      const key = segment.replace(/~1/g, "/").replace(/~0/g, "~");
      current = ownChild(current, key);
      if (current === undefined) return undefined;
    }
    target = current;
  }
}

/**
 * Collect leaf field names from a JSON Schema.
 *
 * Nested object properties are collected by their own names rather than as dotted
 * paths, because that is what an API response field looks like to the enforcement
 * layer: masking and hiding for `api` sources match on the field name wherever it
 * appears in the body (connector-spec section 3.2).
 */
function fieldNames(
  root: Json,
  schema: unknown,
  into: Set<string>,
  depth = 0,
  done: Map<Json, Set<number>> = new Map(),
): void {
  if (depth > 6) return; // Deep enough for real payloads; a bound stops pathological specs.
  const resolved = deref(root, schema);
  if (!isRecord(resolved)) return;

  // The depth bound alone bounds depth, not *work*. `seen` inside `deref` stops a schema
  // referring to itself, but it is per-call, so a schema whose k properties all `$ref`
  // back to it re-expands the whole subtree once per property at every level: k^6 visits
  // from an input that grows with k. Measured on a spec of well under 1 KB -- 902ms at
  // k=10, 7.4s at k=14 -- so unlike the other findings here this one is not even bounded
  // by the 2 MB body limit, and the request that stalls the event loop is cheap to send.
  //
  // Memoized on (node, depth) rather than on the node alone, which keeps the result
  // identical instead of merely close: the names a node contributes are a pure function of
  // that pair, so a repeat visit can only re-add what `into` already holds -- whereas
  // ignoring depth would skip a node first reached deep and later reached shallow, losing
  // the fields the shallower visit was entitled to walk down to. Work is now bounded by
  // distinct nodes times the seven depths.
  let depths = done.get(resolved);
  if (depths === undefined) {
    depths = new Set<number>();
    done.set(resolved, depths);
  }
  if (depths.has(depth)) return;
  depths.add(depth);

  if (isRecord(resolved.properties)) {
    for (const [name, child] of Object.entries(resolved.properties)) {
      into.add(name);
      fieldNames(root, child, into, depth + 1, done);
    }
  }
  if (resolved.items !== undefined) {
    fieldNames(root, resolved.items, into, depth + 1, done);
  }
  // A response modelled as a union still has fields worth offering.
  for (const key of ["allOf", "anyOf", "oneOf"]) {
    const branch = resolved[key];
    if (Array.isArray(branch)) {
      for (const entry of branch) fieldNames(root, entry, into, depth + 1, done);
    }
  }
}

/** Pull the response schema out of an operation, preferring 2xx. */
function responseSchema(root: Json, operation: Json): unknown {
  const responses = operation.responses;
  if (!isRecord(responses)) return undefined;

  const codes = Object.keys(responses)
    .filter((code) => /^2\d\d$/.test(code) || code === "default")
    .sort(); // "200" before "204" before "default"

  for (const code of codes) {
    const response = deref(root, responses[code]);
    if (!isRecord(response) || !isRecord(response.content)) continue;

    for (const [mediaType, media] of Object.entries(response.content)) {
      if (!mediaType.includes("json") || !isRecord(media)) continue;
      if (media.schema !== undefined) return media.schema;
    }
  }
  return undefined;
}

export function importOpenApi(
  sourceConnectionId: string,
  spec: unknown,
): SourceManifest {
  if (!isRecord(spec)) {
    throw new ManifestError("OpenAPI spec must be a JSON object");
  }
  if (!isRecord(spec.paths)) {
    throw new ManifestError("OpenAPI spec has no 'paths' object");
  }

  const endpoints: Array<{
    path: string;
    methods: string[];
    responseFields: string[];
  }> = [];

  for (const [rawPath, pathItemNode] of Object.entries(spec.paths)) {
    const pathItem = deref(spec, pathItemNode);
    if (!isRecord(pathItem)) continue;

    const methods: string[] = [];
    const fields = new Set<string>();

    for (const method of METHODS) {
      const operation = pathItem[method];
      if (!isRecord(operation)) continue;
      methods.push(method.toUpperCase());
      fieldNames(spec, responseSchema(spec, operation), fields);
    }

    if (methods.length === 0) continue;

    // OpenAPI templates paths as `/patients/{id}`; TOLAP endpoint rules glob as
    // `/patients/*` (connector-spec section 3.1). Converting here means an author
    // picking from the catalog gets a pattern that actually matches at
    // enforcement time, rather than a literal `{id}` that never does.
    //
    // `[^{}]` rather than `[^}]`: excluding only `}` lets an opening brace be consumed by
    // the repeat, so a key of `"{".repeat(n)` -- no closing brace anywhere -- makes the
    // engine rescan the whole remaining run from every offset. Measured 63ms at 12 KB and
    // 3.9s at 100 KB, growing with the square; a path key is a JSON object key in a body an
    // admin uploads, and stalling this event loop delays `/v1/resolve` for every install.
    // Excluding both braces bounds each attempt at the next brace, and the two forms agree
    // on every well-formed template because a parameter name cannot contain a brace
    // (OpenAPI 3.1 section 4.8.9.1).
    const path = rawPath.replace(/\{[^{}]+\}/g, "*");

    endpoints.push({
      path,
      methods,
      responseFields: [...fields].sort(),
    });
  }

  if (endpoints.length === 0) {
    throw new ManifestError("OpenAPI spec produced no endpoints");
  }

  const title = isRecord(spec.info) && typeof spec.info.title === "string"
    ? spec.info.title
    : undefined;

  // Routed through parseManifest so an import and an upload cannot diverge: the
  // category check and every field validation happen in exactly one place.
  return parseManifest({
    sourceConnectionId,
    ...(title !== undefined ? { displayName: title } : {}),
    endpoints,
  });
}
