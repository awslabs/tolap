/**
 * TOLAP Purpose Action Resolution (canonical spec §15.2)
 *
 * Resolves a call's action category from administrator-supplied configuration and
 * validates it against the resolved purpose.
 *
 * **Two lookups rather than one**, because the two wrapper families identify a call
 * differently. An MCP-style tool has a name. An HTTP request has a method and a path
 * and no name at all — `RequestArgs` carries no tool identifier — so a single
 * name-keyed map would mean this enforcement point silently never ran for API
 * sources. A gate that does not exist is worse than no gate, because the
 * configuration implies one does.
 *
 * The maps are **configuration on the wrapper**, set by whoever deploys it. They are
 * deliberately not policy fields and deliberately not caller arguments: an agent that
 * can name its own action category can name an allowed one, which turns the whole
 * check into a formality.
 *
 * Lives in `@aws/tolap-core` rather than in the wrappers so that both wrappers, in
 * all three SDKs, share one fail-closed rule and one set of tests.
 */

import { validateAction } from "./enforcement.js";
import { globMatch } from "./resolution.js";
import type { AccessResult, EffectivePolicy, PurposeProfile } from "./types.js";

/**
 * Tool name (or `"METHOD path-glob"` key) to semantic action category.
 *
 * A plain record rather than a `Map` so a deployment can spell it as a literal in
 * whatever config format it already uses.
 */
export type ActionCategoryMap = Readonly<Record<string, string>>;

/**
 * The denial for a call whose action category cannot be determined under a purpose
 * that constrains actions.
 *
 * Part of the contract; integrators log and branch on it. Phrased as a configuration
 * problem rather than an access problem, because that is what it is: the fix is to
 * add the tool to the map, not to widen the policy.
 */
export const UNDECLARED_CATEGORY_REASON = "action category not declared for tool";

/**
 * What to do with a call no map entry classified.
 *
 * Denied whenever the purpose constrains actions at all — whether by an allow-list
 * or by a **non-empty** deny-list. The deny-list case is the less obvious half and
 * the more important one: a purpose declaring only
 * `prohibitedActions: ["export_pii"]` means "anything but exporting PII", and an
 * unclassified tool might be an exporter. Letting it through because no rule named
 * it would permit the unclassified while forbidding the classified, which cannot be
 * what the author meant.
 *
 * An **empty** `prohibitedActions` restricts nothing, so it does not make a call
 * unclassifiable — mirroring the null-versus-empty rule in spec §3, where the two
 * arrays read in opposite directions.
 */
function unclassified(profile: PurposeProfile): AccessResult {
  const constrainsActions =
    profile.allowedActions !== undefined ||
    (profile.prohibitedActions !== undefined &&
      profile.prohibitedActions.length > 0);

  return constrainsActions
    ? { allowed: false, reason: UNDECLARED_CATEGORY_REASON }
    : { allowed: true };
}

/**
 * Validate a named tool call against the policy's purpose.
 *
 * The .NET counterpart is `PurposeActionResolver.ValidateTool`.
 *
 * @param policy The resolved policy. A policy with no purpose profile always allows.
 * @param toolName The tool about to run.
 * @param toolActionCategories
 * Tool name to action category, supplied by the integrator. Matched **exactly and
 * case-sensitively**, as `allowedTools` is — a tool name is an identifier, not a
 * pattern. An absent or empty map classifies nothing, which is not the same as
 * placing no restriction: see {@link unclassified}.
 */
export function validateToolAction(
  policy: EffectivePolicy,
  toolName: string,
  toolActionCategories: ActionCategoryMap | undefined,
): AccessResult {
  const profile = policy.purposeProfile;
  if (profile === undefined) return { allowed: true };

  if (toolActionCategories !== undefined) {
    // `Object.prototype.hasOwnProperty` rather than a truthy lookup, so a tool
    // named `constructor` or `toString` cannot pick up a category from the
    // prototype chain -- the map is caller-supplied configuration, and an
    // inherited "category" is one nobody wrote.
    if (Object.prototype.hasOwnProperty.call(toolActionCategories, toolName)) {
      return validateAction(toolActionCategories[toolName], profile);
    }
  }

  return unclassified(profile);
}

/**
 * Whether a `"METHOD path-glob"` key covers this request.
 *
 * A key with no space, or with an empty method or an empty pattern, matches
 * **nothing**. It is a misconfiguration, and a key that silently matched everything
 * would be the worst possible reading of one — the map exists to narrow.
 */
function keyMatches(key: string, method: string, path: string): boolean {
  const separator = key.indexOf(" ");
  if (separator <= 0 || separator === key.length - 1) return false;

  const keyMethod = key.slice(0, separator);
  const keyPattern = key.slice(separator + 1);

  return (
    keyMethod.toLowerCase() === method.toLowerCase() &&
    globMatch(keyPattern, path)
  );
}

/**
 * Validate an HTTP request against the policy's purpose.
 *
 * The .NET counterpart is `PurposeActionResolver.ValidateHttpRequest`.
 *
 * @param policy The resolved policy. A policy with no purpose profile always allows.
 * @param method The HTTP method.
 * @param path The request path, without host or query string.
 * @param httpActionCategories
 * Keys of the form `"METHOD path-glob"` — for example `"GET /segments/*"` — mapped
 * to an action category. The method is compared **case-insensitively**, matching how
 * `allowedMethods` is compared; the path is matched with the same glob dialect
 * `allowedEndpoints` uses, so a deployment writes one kind of endpoint pattern
 * rather than two.
 *
 * When several entries match, **all** of them are validated and the first denial is
 * returned. Picking a single "best" match would need a specificity rule, and any
 * such rule can be gamed by adding a broader entry; evaluating every match makes the
 * outcome independent of ordering and of how the map happens to be written. Keys are
 * considered in sorted order so the reason string is stable.
 */
export function validateHttpRequestAction(
  policy: EffectivePolicy,
  method: string,
  path: string,
  httpActionCategories: ActionCategoryMap | undefined,
): AccessResult {
  const profile = policy.purposeProfile;
  if (profile === undefined) return { allowed: true };

  let matched = false;

  if (httpActionCategories !== undefined) {
    for (const key of Object.keys(httpActionCategories).sort()) {
      if (!keyMatches(key, method, path)) continue;

      matched = true;
      const result = validateAction(httpActionCategories[key], profile);
      if (!result.allowed) return result;
    }
  }

  return matched ? { allowed: true } : unclassified(profile);
}
