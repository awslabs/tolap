/**
 * Purpose binding: which declared purpose a policy serves, and what it may do under it.
 *
 * This editor differs from the others on this page in one important way. Every other
 * rule group *narrows what a policy returns*; a purpose profile narrows **whether the
 * policy applies at all**. Once a profile exists, resolution excludes the policy for any
 * caller that declares no purpose or a different one, matched exactly and
 * case-sensitively (canonical-enforcement-spec section 15.1). Adding a profile to a
 * working policy is therefore closer to unassigning it than to adding a rule, and an
 * author who does not know that will read the resulting deny-all as an outage. So the
 * consequence is stated on screen, not left to the schema description.
 *
 * Three more things are easy to get wrong and are surfaced inline:
 *
 * 1. **Absent is not empty, for `allowedActions` only.** Absent means unrestricted;
 *    `[]` denies every action (section 15.2, following section 3). Both are legitimate
 *    things to author, so this editor cannot collapse them into "no chips" the way the
 *    field pickers do -- an explicit checkbox owns the distinction, exactly as
 *    `MethodPicker` does for `allowedMethods`. `prohibitedActions` is the deliberate
 *    asymmetry: a deny-list of nothing restricts nothing, so absent and `[]` are the
 *    same policy and the chip list may drop the key when the last chip goes.
 * 2. **Constraining actions at all makes unclassified tools deny.** When
 *    `allowedActions` is non-null or `prohibitedActions` is non-empty, a tool the
 *    *deployment* has not mapped to an action category is denied (section 15.2, "fail
 *    closed on an unclassified call"). The console cannot see the wrapper's category
 *    map, so it cannot check this -- which is precisely why it has to warn. An author
 *    adding one prohibited category to a deployment with no map configured breaks every
 *    call.
 * 3. **Inverted judge thresholds escalate everything.** `getDisposition` checks
 *    `escalationThreshold > confidenceThreshold` before any verdict is considered
 *    (section 15.4), so an inverted pair sends every call to human review -- which is a
 *    denial wherever no review handler is wired.
 *
 * Action categories are free text. Unlike fields, tags and endpoints there is no
 * catalog of them: they come from administrator-supplied wrapper configuration that the
 * policy server never sees. So the only check available is the schema's own pattern,
 * applied as the author types.
 */

import { useState } from "react";
import type { PurposeJudgeConfig, PurposeProfile } from "../api.ts";

/**
 * The schema's patterns, as literals.
 *
 * Note they are *not* the same: a purpose id is `[a-z0-9-]` and needs at least two
 * characters (the pattern anchors a final character class), while an action category
 * also admits `_` and may be a single character. Reusing one for the other would reject
 * `export_pii`, which is the spec's own example.
 */
const PURPOSE_ID_PATTERN = /^[a-z0-9][a-z0-9-]*[a-z0-9]$/;
const ACTION_CATEGORY_PATTERN = /^[a-z0-9][a-z0-9_-]*$/;

const PURPOSE_ID_MAX = 128;
const ACTION_CATEGORY_MAX = 128;
const DESCRIPTION_MAX = 2048;
const MODEL_MAX = 256;

/** The schema's documented defaults, shown as placeholders rather than written in. */
const JUDGE_DEFAULTS = {
  historyWindow: 10,
  confidenceThreshold: 0.85,
  escalationThreshold: 0.6,
  maxLatencyMs: 2000,
} as const;

/** Why a value the author typed is not something the schema accepts. */
function purposeIdProblem(purposeId: string): string | undefined {
  if (purposeId === "") return undefined; // A fresh profile is not yet a mistake.
  if (purposeId.length > PURPOSE_ID_MAX) {
    return `Longer than ${PURPOSE_ID_MAX} characters.`;
  }
  if (!PURPOSE_ID_PATTERN.test(purposeId)) {
    return "Lowercase letters, digits and hyphens only, starting and ending with a letter or digit. At least two characters.";
  }
  return undefined;
}

function actionCategoryProblem(category: string): string | undefined {
  if (category.length > ACTION_CATEGORY_MAX) {
    return `longer than ${ACTION_CATEGORY_MAX} characters`;
  }
  if (!ACTION_CATEGORY_PATTERN.test(category)) {
    return "must be lowercase letters, digits, hyphens and underscores, starting with a letter or digit";
  }
  return undefined;
}

/** The optional keys, so a value can be removed rather than set to `undefined`. */
type OptionalProfileKey = "description" | "allowedActions" | "prohibitedActions" | "judge";

/**
 * Rebuild the profile with one optional key set, or **absent**.
 *
 * `{ ...profile, allowedActions: undefined }` is not good enough: it survives every
 * in-memory comparison but `JSON.stringify` drops it, so the difference between
 * "unrestricted" and "deny every action" would depend on which side of the wire you
 * looked at. Deleting the key makes the in-memory object say what the wire will.
 */
function withKey<K extends OptionalProfileKey>(
  profile: PurposeProfile,
  key: K,
  value: PurposeProfile[K] | undefined,
): PurposeProfile {
  const next: PurposeProfile = { ...profile };
  if (value === undefined) delete next[key];
  else next[key] = value;
  return next;
}

/** Same, one level down. Every judge key is optional and none has a merge-time default. */
function withJudgeKey<K extends keyof PurposeJudgeConfig>(
  judge: PurposeJudgeConfig,
  key: K,
  value: PurposeJudgeConfig[K] | undefined,
): PurposeJudgeConfig {
  const next: PurposeJudgeConfig = { ...judge };
  if (value === undefined) delete next[key];
  else next[key] = value;
  return next;
}

/**
 * A free-text list of action categories.
 *
 * The chip idiom of `TagPicker` without the catalog, because there is no catalog of
 * action categories to draw from -- and no `datalist`, for the same reason.
 */
function ActionCategoryList({
  label,
  categories,
  alsoProhibited,
  onChange,
}: {
  readonly label: string;
  readonly categories: string[];
  /** Categories that the deny-list also names, so "prohibited wins" can be shown. */
  readonly alsoProhibited?: ReadonlySet<string>;
  readonly onChange: (next: string[]) => void;
}) {
  const [draft, setDraft] = useState("");

  const add = (value: string) => {
    const trimmed = value.trim();
    if (trimmed === "" || categories.includes(trimmed)) return;
    onChange([...categories, trimmed]);
    setDraft("");
  };

  return (
    <div className="field-picker">
      <span className="field-picker__label">{label}</span>

      {categories.length > 0 ? (
        <ul className="field-picker__selected">
          {categories.map((category) => {
            const problem = actionCategoryProblem(category);
            return (
              <li key={category} className="field-picker__chip">
                <code>{category}</code>
                {problem ? (
                  <span
                    className="field-picker__warning"
                    title={`The schema rejects this category: it ${problem}.`}
                  >
                    ⚠ invalid category
                  </span>
                ) : null}
                {alsoProhibited?.has(category.toLowerCase()) ? (
                  <span
                    className="field-picker__warning"
                    title="This category is also prohibited, and prohibited wins. It is denied."
                  >
                    ⚠ also prohibited
                  </span>
                ) : null}
                <button
                  type="button"
                  onClick={() =>
                    onChange(categories.filter((existing) => existing !== category))
                  }
                  aria-label={`Remove ${category} from ${label}`}
                >
                  ×
                </button>
              </li>
            );
          })}
        </ul>
      ) : null}

      <div className="field-picker__add">
        <input
          type="text"
          value={draft}
          placeholder="Action category, e.g. aggregate_overlap"
          aria-label={`Add to ${label}`}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              // Otherwise Enter submits the surrounding form, discarding the entry.
              event.preventDefault();
              add(draft);
            }
          }}
        />
        <button type="button" onClick={() => add(draft)} disabled={draft.trim() === ""}>
          Add
        </button>
      </div>
    </div>
  );
}

/**
 * The judge's numeric and model settings.
 *
 * Rendered whenever the `judge` object exists, not only when it is enabled: a policy
 * carrying `judge: { enabled: false, model: "claude-sonnet" }` must still show the model,
 * or the setting is invisible, un-editable, and applies again the moment someone ticks
 * the box.
 */
function JudgeFields({
  judge,
  onChange,
}: {
  readonly judge: PurposeJudgeConfig;
  readonly onChange: (next: PurposeJudgeConfig) => void;
}) {
  const numberField = (
    key: "historyWindow" | "confidenceThreshold" | "escalationThreshold" | "maxLatencyMs",
    label: string,
    attributes: { min: number; max?: number; step?: number },
  ) => (
    <label className="rule-editor__param">
      {label}
      <input
        type="number"
        min={attributes.min}
        {...(attributes.max !== undefined ? { max: attributes.max } : {})}
        {...(attributes.step !== undefined ? { step: attributes.step } : {})}
        value={judge[key] ?? ""}
        placeholder={String(JUDGE_DEFAULTS[key])}
        aria-label={label}
        onChange={(event) =>
          onChange(
            withJudgeKey(
              judge,
              key,
              // Cleared means "leave it to the SDK default", which is an absent key.
              // Storing 0 instead would be a real setting, and for the thresholds a
              // legal one -- so the empty check cannot be a truthiness check.
              event.target.value === "" ? undefined : Number(event.target.value),
            ),
          )
        }
      />
    </label>
  );

  const confidence = judge.confidenceThreshold ?? JUDGE_DEFAULTS.confidenceThreshold;
  const escalation = judge.escalationThreshold ?? JUDGE_DEFAULTS.escalationThreshold;

  return (
    <>
      <label className="rule-editor__param">
        Judge model
        <input
          type="text"
          maxLength={MODEL_MAX}
          value={judge.model ?? ""}
          placeholder="any model"
          aria-label="Judge model"
          onChange={(event) =>
            onChange(withJudgeKey(judge, "model", event.target.value || undefined))
          }
        />
      </label>
      <p className="rule-editor__note">
        Compared exactly and case-sensitively against the model the wrapper invokes; a
        mismatch escalates rather than running. Leave it empty to accept any model — ids
        differ per account and region. Two policies naming <em>different</em> models
        cannot be merged and resolve to deny-all.
      </p>

      <div className="rule-editor__params">
        {numberField("historyWindow", "Judge history window", { min: 1 })}
        {numberField("confidenceThreshold", "Judge confidence threshold", {
          min: 0,
          max: 1,
          step: 0.01,
        })}
        {numberField("escalationThreshold", "Judge escalation threshold", {
          min: 0,
          max: 1,
          step: 0.01,
        })}
        {numberField("maxLatencyMs", "Judge max latency (ms)", { min: 100 })}
      </div>

      {escalation > confidence ? (
        <p className="rule-editor__warning">
          ⚠ The escalation threshold ({escalation}) is above the confidence threshold (
          {confidence}). An inverted pair is checked before any verdict, so{" "}
          <strong>every call escalates</strong> — and escalation is a denial wherever no
          human-review handler is wired.
        </p>
      ) : null}

      <p className="rule-editor__note">
        Empty fields use the SDK defaults ({JUDGE_DEFAULTS.historyWindow} calls of
        history, confidence {JUDGE_DEFAULTS.confidenceThreshold}, escalation{" "}
        {JUDGE_DEFAULTS.escalationThreshold}, {JUDGE_DEFAULTS.maxLatencyMs}
        ms) rather than writing a number into the policy. A timeout escalates; it never
        allows.
      </p>
    </>
  );
}

export interface PurposeProfileEditorProps {
  readonly profile?: PurposeProfile;
  readonly onChange: (next: PurposeProfile | undefined) => void;
}

export function PurposeProfileEditor({ profile, onChange }: PurposeProfileEditorProps) {
  if (!profile) {
    return (
      <div className="rule-editor">
        <span className="field-picker__label">Purpose profile</span>
        <p className="muted">
          No purpose profile. This policy resolves for every caller its assignments
          cover, whatever purpose is declared — the behaviour of every policy written
          before purpose binding existed.
        </p>
        <button type="button" onClick={() => onChange({ purposeId: "" })}>
          Add purpose profile
        </button>
      </div>
    );
  }

  const idProblem = purposeIdProblem(profile.purposeId);
  const allowed = profile.allowedActions;
  const prohibited = profile.prohibitedActions ?? [];
  const prohibitedSet = new Set(prohibited.map((category) => category.toLowerCase()));
  // Section 15.2's fail-closed rule keys off exactly this: a non-null allow-list, or a
  // NON-EMPTY deny-list. An empty deny-list restricts nothing and so cannot make a call
  // unclassifiable.
  const constrainsActions = allowed !== undefined || prohibited.length > 0;

  return (
    <div className="rule-editor">
      <span className="field-picker__label">Purpose profile</span>

      <p className="rule-editor__warning">
        ⚠ A purpose profile changes <strong>whether this policy applies</strong>, not
        only what it returns. Once it exists, the policy resolves{" "}
        <strong>only</strong> for a caller declaring{" "}
        <code>{profile.purposeId || "this purpose id"}</code> exactly and
        case-sensitively. A caller declaring no purpose, or a differently-cased one, does
        not get this policy at all.
      </p>

      <label className="rule-editor__param">
        Purpose id
        <input
          type="text"
          value={profile.purposeId}
          maxLength={PURPOSE_ID_MAX}
          // The schema's pattern, surfaced here rather than discovered on save.
          pattern="[a-z0-9][a-z0-9-]*[a-z0-9]"
          title="Lowercase letters, digits and hyphens"
          placeholder="e.g. fraud-detection"
          aria-label="Purpose id"
          onChange={(event) => onChange({ ...profile, purposeId: event.target.value })}
        />
      </label>
      {idProblem ? (
        <p className="rule-editor__warning">
          ⚠ <code>{profile.purposeId}</code> is not a valid purpose id. {idProblem}
        </p>
      ) : profile.purposeId === "" ? (
        <p className="rule-editor__note">
          Required. Until it is set the policy cannot be saved.
        </p>
      ) : null}

      <label className="rule-editor__param">
        Purpose description
        <input
          type="text"
          value={profile.description ?? ""}
          maxLength={DESCRIPTION_MAX}
          placeholder="Why this data is being read"
          aria-label="Purpose description"
          onChange={(event) =>
            onChange(withKey(profile, "description", event.target.value || undefined))
          }
        />
      </label>
      <p className="rule-editor__note">
        Carried into audit logs, and into the judge's prompt when it is enabled.
      </p>

      {/*
        The absent-versus-empty control. Checked means the key is absent, which is
        unrestricted; unchecking writes `[]`, which denies every action. That direction
        is deliberate -- turning the restriction on should fail closed, so an author who
        stops here has denied everything rather than allowed it.
      */}
      <label>
        <input
          type="checkbox"
          checked={allowed === undefined}
          onChange={(event) =>
            onChange(
              withKey(
                profile,
                "allowedActions",
                event.target.checked ? undefined : [],
              ),
            )
          }
        />
        Permit every action category (no <code>allowedActions</code> rule)
      </label>

      {allowed !== undefined ? (
        <div className="nested">
          <ActionCategoryList
            label="Allowed actions"
            categories={allowed}
            alsoProhibited={prohibitedSet}
            onChange={(next) => onChange(withKey(profile, "allowedActions", next))}
          />
          {allowed.length === 0 ? (
            <p className="rule-editor__warning">
              ⚠ An empty allow-list <strong>denies every action</strong> under this
              purpose. That is a real and authorable policy — the most restrictive this
              form can express — but if you meant "no restriction", tick the box above
              instead of leaving the list empty.
            </p>
          ) : null}
        </div>
      ) : null}

      <ActionCategoryList
        label="Prohibited actions"
        categories={prohibited}
        onChange={(next) =>
          // Absent and `[]` are the same deny-list of nothing (section 15.2's stated
          // asymmetry with the allow-list), so dropping the key when the last chip goes
          // changes the spelling and not the policy. Doing the same to `allowedActions`
          // would change deny-all into unrestricted.
          onChange(
            withKey(profile, "prohibitedActions", next.length > 0 ? next : undefined),
          )
        }
      />
      <p className="rule-editor__note">
        Checked first, so a category in both lists is <strong>denied</strong>. An empty
        deny-list restricts nothing.
      </p>

      {constrainsActions ? (
        <p className="rule-editor__warning">
          ⚠ This policy now constrains action categories, so any tool the{" "}
          <strong>deployment</strong> has not mapped to a category is denied
          (&ldquo;action category not declared for tool&rdquo;). The console cannot see
          that map — if the wrappers have none configured, this denies every call until
          one is added.
        </p>
      ) : null}

      {/*
        The judge object, gated on its existence rather than on `enabled`, so a disabled
        judge's model and thresholds stay visible and removable.
      */}
      <label>
        <input
          type="checkbox"
          checked={profile.judge !== undefined}
          onChange={(event) =>
            onChange(
              withKey(
                profile,
                "judge",
                event.target.checked ? { enabled: true } : undefined,
              ),
            )
          }
        />
        Configure a semantic judge (advisory, and can only deny)
      </label>

      {profile.judge !== undefined ? (
        <div className="nested">
          <label>
            <input
              type="checkbox"
              checked={profile.judge.enabled === true}
              onChange={(event) =>
                onChange(
                  withKey(
                    profile,
                    "judge",
                    withJudgeKey(profile.judge!, "enabled", event.target.checked),
                  ),
                )
              }
            />
            Consult the judge (<code>enabled</code>)
          </label>
          <JudgeFields
            judge={profile.judge}
            onChange={(next) => onChange(withKey(profile, "judge", next))}
          />
        </div>
      ) : null}

      <button
        type="button"
        // Removes the whole profile rather than blanking its fields: an empty-ish
        // profile still filters resolution, so "clear the boxes" would look like
        // removal and behave like a deny-all.
        onClick={() => onChange(undefined)}
      >
        Remove purpose profile
      </button>
    </div>
  );
}
