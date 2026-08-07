/**
 * Masking rules, picked from the source catalog.
 *
 * Masking is where a policy author most easily produces something that looks right and
 * protects nothing, in two ways:
 *
 * 1. **A field name that does not exist.** `ssn` when the column is `ssn_number` masks
 *    nothing, and no part of TOLAP can detect it — the policy validates, signs,
 *    resolves and enforces perfectly. The catalog dropdown is the fix.
 * 2. **A mask type that discloses more than intended.** The five types are not
 *    interchangeable: `partial` reveals real characters, and `hash` is an unsalted
 *    truncated digest that the spec explicitly says is *not* a confidentiality control
 *    — it is brute-forceable for low-entropy values like SSNs and dates of birth. Both
 *    are stated inline rather than left to the schema docs.
 */

import { useId } from "react";
import type { MaskingRule, SourceManifest } from "../api.ts";
import { fieldOptions } from "./FieldPicker.tsx";

/**
 * The five mask types, ordered most- to least-restrictive.
 *
 * This is the merge order from the enforcement spec: when two policies mask the same
 * field differently, the one revealing least wins. Presenting them in that order makes
 * the trade-off visible while choosing.
 */
const MASK_TYPES: Array<{
  readonly value: MaskingRule["maskType"];
  readonly label: string;
  readonly note: string;
}> = [
  { value: "null", label: "null", note: "Value replaced with null. Neither the value nor its length survives." },
  { value: "redact", label: "redact", note: "Replaced with the literal [REDACTED]." },
  { value: "full", label: "full", note: "Every character replaced. Discloses the length." },
  {
    value: "hash",
    label: "hash",
    note: "Stable digest — usable as a join key, and NOT a confidentiality control: brute-forceable for SSNs, dates of birth, and small enumerations.",
  },
  {
    value: "partial",
    label: "partial",
    note: "Reveals real characters of the original. The least restrictive option.",
  },
];

/**
 * The hash algorithms the schema permits.
 *
 * Closed set on purpose: the SDKs translate these to platform digest names, and a value
 * outside the set produces a pseudonym that does not match across languages.
 */
const HASH_ALGORITHMS = ["sha256", "sha512", "blake2b"] as const;

/** Parameters the schema defines. Anything else fails validation on save. */
type MaskParameters = NonNullable<MaskingRule["parameters"]>;

/**
 * The per-mask-type parameters.
 *
 * Only rendered for the types that use them, because the schema closes
 * `parameters` to these four keys and a `showFirst` on a `redact` rule is simply
 * invalid rather than ignored.
 */
function MaskParameterFields({
  rule,
  index,
  onChange,
}: {
  readonly rule: MaskingRule;
  readonly index: number;
  readonly onChange: (parameters: MaskParameters | undefined) => void;
}) {
  const parameters = (rule.parameters ?? {}) as Record<string, unknown>;

  /** Drop a key rather than storing an empty string, which the schema rejects. */
  const set = (key: string, value: string | number | undefined) => {
    const next: Record<string, unknown> = { ...parameters };
    if (value === undefined || value === "") delete next[key];
    else next[key] = value;
    onChange(Object.keys(next).length === 0 ? undefined : (next as MaskParameters));
  };

  const numberField = (key: "showFirst" | "showLast", label: string) => (
    <label className="rule-editor__param">
      {label}
      <input
        type="number"
        min={0}
        value={typeof parameters[key] === "number" ? String(parameters[key]) : ""}
        placeholder="0"
        aria-label={`${label} for field ${index + 1}`}
        onChange={(event) =>
          set(key, event.target.value === "" ? undefined : Number(event.target.value))
        }
      />
    </label>
  );

  const maskCharField = (
    <label className="rule-editor__param">
      Mask character
      <input
        type="text"
        maxLength={1}
        value={typeof parameters.maskChar === "string" ? parameters.maskChar : ""}
        placeholder="*"
        aria-label={`Mask character for field ${index + 1}`}
        onChange={(event) => set("maskChar", event.target.value)}
      />
    </label>
  );

  if (rule.maskType === "partial") {
    const showFirst = Number(parameters.showFirst ?? 0);
    const showLast = Number(parameters.showLast ?? 0);
    return (
      <>
        <div className="rule-editor__params">
          {numberField("showFirst", "Show first")}
          {numberField("showLast", "Show last")}
          {maskCharField}
        </div>
        {showFirst + showLast === 0 ? (
          <p className="rule-editor__note">
            Revealing nothing: this behaves as a <code>full</code> mask until you show at
            least one character.
          </p>
        ) : (
          <p className="rule-editor__note">
            Reveals {showFirst > 0 ? `the first ${showFirst}` : ""}
            {showFirst > 0 && showLast > 0 ? " and " : ""}
            {showLast > 0 ? `the last ${showLast}` : ""} character(s). A value short
            enough to be fully revealed is masked completely instead.
          </p>
        )}
      </>
    );
  }

  if (rule.maskType === "full") {
    return <div className="rule-editor__params">{maskCharField}</div>;
  }

  if (rule.maskType === "hash") {
    return (
      <div className="rule-editor__params">
        <label className="rule-editor__param">
          Algorithm
          <select
            value={typeof parameters.algorithm === "string" ? parameters.algorithm : ""}
            aria-label={`Hash algorithm for field ${index + 1}`}
            onChange={(event) => set("algorithm", event.target.value || undefined)}
          >
            <option value="">sha256 (default)</option>
            {HASH_ALGORITHMS.map((algorithm) => (
              <option key={algorithm} value={algorithm}>
                {algorithm}
              </option>
            ))}
          </select>
        </label>
      </div>
    );
  }

  return null;
}

export interface MaskedFieldEditorProps {
  readonly rules: MaskingRule[];
  readonly manifest?: SourceManifest;
  readonly onChange: (next: MaskingRule[]) => void;
}

export function MaskedFieldEditor({
  rules,
  manifest,
  onChange,
}: MaskedFieldEditorProps) {
  const options = fieldOptions(manifest);
  const known = new Set(options);
  // Per-instance, so a second editor on one page cannot capture this one's datalist.
  const listId = `${useId()}-masked-fields`;

  const update = (index: number, patch: Partial<MaskingRule>) => {
    onChange(rules.map((rule, i) => (i === index ? { ...rule, ...patch } : rule)));
  };

  /**
   * Switching mask type must drop parameters the new type does not accept.
   *
   * `parameters` is a closed object in the schema and each key names the type it belongs
   * to, so a `showFirst` left behind on a `hash` rule does not get ignored -- it fails
   * validation on save, with an error pointing at a control that is no longer on screen.
   */
  const changeMaskType = (index: number, maskType: MaskingRule["maskType"]) => {
    const keep: Record<string, readonly string[]> = {
      partial: ["showFirst", "showLast", "maskChar"],
      full: ["maskChar"],
      hash: ["algorithm"],
    };
    const allowed = keep[maskType] ?? [];
    const current = (rules[index]!.parameters ?? {}) as Record<string, unknown>;
    const parameters: Record<string, unknown> = {};
    for (const key of allowed) {
      if (key in current) parameters[key] = current[key];
    }

    const next: MaskingRule = { field: rules[index]!.field, maskType };
    if (Object.keys(parameters).length > 0) {
      next.parameters = parameters as MaskParameters;
    }
    onChange(rules.map((rule, i) => (i === index ? next : rule)));
  };

  const add = () => {
    // Defaults to `redact` rather than `partial`: a new rule should start restrictive,
    // so forgetting to change it errs toward disclosing less.
    onChange([...rules, { field: "", maskType: "redact" }]);
  };

  return (
    <div className="rule-editor">
      <span className="field-picker__label">Masked fields</span>

      {rules.length === 0 ? (
        <p className="muted">No masking rules. Fields are returned as stored.</p>
      ) : (
        <ul className="rule-editor__list">
          {rules.map((rule, index) => {
            const selected = MASK_TYPES.find((t) => t.value === rule.maskType);
            const unknownField =
              manifest !== undefined &&
              rule.field !== "" &&
              !known.has(rule.field) &&
              !rule.field.includes("*");

            return (
              <li key={index} className="rule-editor__row">
                <div className="rule-editor__inputs">
                  <input
                    type="text"
                    list={listId}
                    value={rule.field}
                    placeholder={manifest ? "Select or type a field" : "Field name"}
                    aria-label={`Masked field ${index + 1}`}
                    onChange={(event) => update(index, { field: event.target.value })}
                  />

                  <select
                    value={rule.maskType}
                    aria-label={`Mask type for field ${index + 1}`}
                    onChange={(event) =>
                      changeMaskType(
                        index,
                        event.target.value as MaskingRule["maskType"],
                      )
                    }
                  >
                    {MASK_TYPES.map((type) => (
                      <option key={type.value} value={type.value}>
                        {type.label}
                      </option>
                    ))}
                  </select>

                  <button
                    type="button"
                    onClick={() => onChange(rules.filter((_, i) => i !== index))}
                    aria-label={`Remove masking rule ${index + 1}`}
                  >
                    ×
                  </button>
                </div>

                {unknownField ? (
                  <p className="rule-editor__warning">
                    ⚠ <code>{rule.field}</code> is not in this source's catalog. If it is
                    a typo, this rule masks nothing.
                  </p>
                ) : null}

                {selected ? (
                  <p className="rule-editor__note">{selected.note}</p>
                ) : null}

                <MaskParameterFields
                  rule={rule}
                  index={index}
                  onChange={(parameters) => update(index, { parameters })}
                />
              </li>
            );
          })}
        </ul>
      )}

      <datalist id={listId}>
        {options.map((option) => (
          <option key={option} value={option} />
        ))}
      </datalist>

      <button type="button" onClick={add}>
        Add masking rule
      </button>
    </div>
  );
}
