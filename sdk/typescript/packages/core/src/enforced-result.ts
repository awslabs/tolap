/**
 * A tool's declaration that its result has already been policy-enforced.
 *
 * Some tools enforce at the data layer: an ORM adapter that applies the result
 * pipeline as it materializes rows, say. Running the pipeline again in the wrapper
 * is not harmless. `hash` masking is not idempotent, so a hashed field comes back
 * hashed twice, and a row filter on a field the data layer already hid fails closed
 * and drops every row.
 *
 * Such a tool returns an {@link EnforcedResult} instead of the bare data. The marker
 * is bound to the signature of the signed context the pipeline was applied under,
 * and the context wrapper honours it only when that signature matches the current
 * call's verified context exactly, compared in constant time. Anything else (another
 * context, a tampered or empty signature, an unsigned context) is treated as though
 * no marker were present, and the full pipeline runs.
 *
 * A marker is a class, never an object key or a caller-supplied flag. A plain object
 * with `data` and `contextSignature` keys is ordinary data, and model-controlled
 * arguments cannot reach a class instance the tool code has to construct. Only an
 * object the constructor ran on carries the private `#brand`, so neither
 * `Object.create(EnforcedResult.prototype)` nor a Proxy is honoured.
 *
 * Scope and trust. Only `executeWithEnforcement` honours a marker; the SQL and write
 * paths, and `postExecute` called directly, unwrap it and run the full pipeline. A
 * marker is a claim by the tool code, not proof that the pipeline ran: the wrapper
 * checks only that it is bound to the current verified context. It is reusable for
 * every call made with that context for the context's whole TTL. An honoured marker
 * skips masking, so if the data layer did not really run the pipeline, masked
 * fields come back raw. SQL pushdown alone does not qualify: pushdown applies row
 * filters, not masking or field rules.
 */

import { timingSafeEqual } from "node:crypto";
import type { SecurityContext } from "./types.js";

/**
 * Cross-copy brand. Two copies of this package (a duplicated dependency) have two
 * `EnforcedResult` classes, and neither recognizes the other's instances by class
 * or private field. The registered symbol is shared by both, so a marker from the
 * other copy is still found and unwrapped. It is never used to honour a marker: any
 * object can carry it.
 */
const FOREIGN_BRAND = Symbol.for("tolap.EnforcedResult");

let hasBrand: (value: object) => boolean = () => false;

/** Tool output the data layer already ran the result pipeline over. */
export class EnforcedResult<T = unknown> {
  // Set only by the constructor. `#brand in value` is false for an object built by
  // Object.create(EnforcedResult.prototype) and for a Proxy, whatever its traps say.
  #brand = true;

  static {
    hasBrand = (value: object): boolean => #brand in value;
  }

  readonly data: T;
  readonly contextSignature: string;

  constructor(data: T, contextSignature: string) {
    this.data = data;
    this.contextSignature = contextSignature;
    Object.freeze(this);
  }

  /** See {@link FOREIGN_BRAND}: for unwrapping only, never for honouring. */
  get [FOREIGN_BRAND](): true {
    return true;
  }

  /**
   * Bind `data` to the signature of the context it was enforced under.
   *
   * @throws Error if the context is unsigned. An unbound marker could never be
   *   honoured, so building one is a mistake worth surfacing at the call site
   *   rather than as a silent second pass.
   */
  static forContext<T>(data: T, context: SecurityContext): EnforcedResult<T> {
    if (!context.signature) {
      throw new Error(
        "EnforcedResult needs a signed context: the marker is bound to the " +
          "context signature, and an unsigned context has none",
      );
    }
    return new EnforcedResult(data, context.signature);
  }

  /** Keeps the records out of `console.log` / `util.inspect` output. */
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return "EnforcedResult { data: [hidden] }";
  }
}

/**
 * Whether `value` is exactly an {@link EnforcedResult} this copy of the package
 * constructed: not a subclass, not a Proxy, not `Object.create(prototype)`.
 *
 * A subclass could override `data` with a getter that returns something else on the
 * second read, so only the exact class is ever honoured. The private-field check
 * comes first: it is the one a Proxy cannot fake, and it means the prototype read
 * never reaches a Proxy's `getPrototypeOf` trap. Everything that fails is still
 * unwrapped (see {@link unwrapEnforcedResults}), which is the safe direction.
 */
export function isExactEnforcedResult(value: unknown): value is EnforcedResult {
  return (
    typeof value === "object" &&
    value !== null &&
    hasBrand(value) &&
    Object.getPrototypeOf(value) === EnforcedResult.prototype
  );
}

/**
 * Whether `value` is a marker to unwrap: an instance of this copy's class, or an
 * object carrying the registered cross-copy brand (a marker from a second copy of
 * the package). Never used to decide whether to honour one.
 */
function isMarkerToUnwrap(value: unknown): value is { data: unknown } {
  if (value instanceof EnforcedResult) return true;
  if (typeof value !== "object" || value === null) return false;
  try {
    return (value as Record<symbol, unknown>)[FOREIGN_BRAND] === true;
  } catch {
    // A hostile getter or Proxy trap: treat it as ordinary data.
    return false;
  }
}

/**
 * Whether `marker` names exactly the signature `context` carries, in constant time.
 *
 * This proves only that the two strings match. The caller must separately have
 * verified the context signature, or the match proves nothing: an unverified
 * signature field is whatever the sender wrote.
 */
export function isBoundTo(marker: EnforcedResult, context: SecurityContext): boolean {
  const expected: unknown = context.signature;
  const presented: unknown = marker.contextSignature;
  if (typeof expected !== "string" || typeof presented !== "string" || expected === "") {
    return false;
  }
  const expectedBuf = Buffer.from(expected, "utf8");
  const presentedBuf = Buffer.from(presented, "utf8");
  if (expectedBuf.length !== presentedBuf.length) return false;
  return timingSafeEqual(presentedBuf, expectedBuf);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Whether an {@link EnforcedResult} appears in a tree of arrays and plain objects.
 *
 * Only arrays and plain objects are walked. A marker inside a Map, a Set or a class
 * instance is not found, and every pipeline step passes such a container through by
 * reference as well.
 */
export function containsEnforcedResult(node: unknown): boolean {
  if (isMarkerToUnwrap(node)) return true;
  if (Array.isArray(node)) return node.some((item) => containsEnforcedResult(item));
  if (isPlainObject(node)) {
    return Object.values(node).some((value) => containsEnforcedResult(value));
  }
  return false;
}

/**
 * Replace every {@link EnforcedResult} in a tree with the data it carries.
 *
 * Every pipeline step walks plain objects and arrays and passes any class instance
 * through by reference. A marker left in place would carry its data past the
 * hidden-field strip and masking, and `JSON.stringify` would then serialize it
 * whole. So an unhonoured marker is unwrapped before enforcement and its contents
 * are enforced like any other data. Containers are rebuilt only when a marker was
 * found beneath them.
 *
 * Walks arrays and plain objects only; a marker inside a Map, a Set or another class
 * instance is left in place. Markers from a second copy of the package are found by
 * their registered brand.
 */
export function unwrapEnforcedResults(node: unknown): unknown {
  return unwrap(node)[0];
}

function unwrap(node: unknown): [unknown, boolean] {
  if (isMarkerToUnwrap(node)) return [unwrap(node.data)[0], true];
  if (Array.isArray(node)) {
    const items = node.map((item) => unwrap(item));
    if (!items.some(([, changed]) => changed)) return [node, false];
    return [items.map(([value]) => value), true];
  }
  if (isPlainObject(node)) {
    const entries = Object.entries(node).map(
      ([key, value]) => [key, unwrap(value)] as const,
    );
    if (!entries.some(([, [, changed]]) => changed)) return [node, false];
    const out: Record<string, unknown> = {};
    for (const [key, [value]] of entries) {
      // defineProperty, not assignment: an own "__proto__" key (JSON.parse makes
      // them) assigned with `=` would replace the prototype instead of copying.
      Object.defineProperty(out, key, {
        value,
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return [out, true];
  }
  return [node, false];
}
