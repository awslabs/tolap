/**
 * Row filters, picked from the source catalog.
 *
 * Row filters are how TOLAP selects *records* — there is no record-id concept anywhere
 * in the policy model, so "which rows may this user see" is always a predicate over a
 * field. That makes the field name load-bearing in a way worth guarding: a filter on a
 * column that does not exist drops **every** record, because a record missing the
 * referenced field fails the filter (fail closed, per the enforcement spec).
 *
 * So a typo here does not silently grant access — it silently denies all of it, which
 * an author usually discovers as "the agent returns nothing" rather than as a policy
 * error. The catalog dropdown and the not-in-catalog warning exist for that.
 */

import { useEffect, useId, useState } from "react";
import type { RowFilter, SourceManifest } from "../api.ts";
import { fieldOptions } from "./FieldPicker.tsx";

/** Operators, grouped by the shape of value they take. */
const SINGLE_VALUE = [
  "equals",
  "notEquals",
  "greaterThan",
  "greaterThanOrEqual",
  "lessThan",
  "lessThanOrEqual",
  "contains",
  "startsWith",
  "like",
  "notLike",
  "matches",
] as const;

const MULTI_VALUE = ["in", "notIn", "between"] as const;

const NO_VALUE = ["isNull", "isNotNull"] as const;

const ALL_OPERATORS = [...SINGLE_VALUE, ...MULTI_VALUE, ...NO_VALUE];

function operatorShape(operator: string): "single" | "multi" | "none" {
  if ((MULTI_VALUE as readonly string[]).includes(operator)) return "multi";
  if ((NO_VALUE as readonly string[]).includes(operator)) return "none";
  return "single";
}

/** Guidance for the operators whose behavior is easy to get wrong. */
const OPERATOR_NOTES: Record<string, string> = {
  like: "SQL LIKE wildcards: % for any sequence, _ for any single character.",
  notLike: "SQL LIKE wildcards, negated.",
  matches: "Regular expression. Keep it simple — a pattern that cannot be evaluated is treated as a non-match, which denies.",
  between: "Exactly two values, ordered [low, high], inclusive.",
  in: "One value per line.",
  notIn: "One value per line.",
  isNull: "Takes no value.",
  isNotNull: "Takes no value.",
};

/**
 * One value per line, for `in` / `notIn` / `between`.
 *
 * The text the author is typing and the values that get stored are deliberately not the
 * same thing. Stored values have blank lines dropped, because an empty-string entry
 * matches nothing and is never what a trailing newline meant. But deriving the textarea's
 * text from the stored values would delete the newline the instant Enter is pressed,
 * making a second line impossible to type. So the raw text lives here and only the
 * cleaned list escapes.
 */
function ValueListInput({
  values,
  ariaLabel,
  onChange,
}: {
  readonly values: unknown[];
  readonly ariaLabel: string;
  readonly onChange: (next: unknown[]) => void;
}) {
  const [text, setText] = useState(() => values.join("\n"));

  // Adopt values that changed elsewhere -- switching operator, loading another policy --
  // without clobbering in-progress typing, which always round-trips to itself.
  useEffect(() => {
    const canonical = values.join("\n");
    if (canonical !== clean(text).join("\n")) setText(canonical);
    // Reacting to the stored values only; `text` is this component's own state and
    // including it here would undo each keystroke.
  }, [values.join("\n")]);

  return (
    <textarea
      rows={2}
      value={text}
      placeholder="One value per line"
      aria-label={ariaLabel}
      onChange={(event) => {
        setText(event.target.value);
        onChange(clean(event.target.value));
      }}
    />
  );
}

function clean(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

export interface RowFilterEditorProps {
  readonly filters: RowFilter[];
  readonly manifest?: SourceManifest;
  readonly onChange: (next: RowFilter[]) => void;
}

export function RowFilterEditor({
  filters,
  manifest,
  onChange,
}: RowFilterEditorProps) {
  const options = fieldOptions(manifest);
  const known = new Set(options);
  // Per-instance, so a second editor on one page cannot capture this one's datalist.
  const listId = `${useId()}-row-filter-fields`;

  const update = (index: number, patch: Partial<RowFilter>) => {
    onChange(
      filters.map((filter, i) => (i === index ? { ...filter, ...patch } : filter)),
    );
  };

  /** Switching operator shape must drop the value that no longer applies. */
  const changeOperator = (index: number, operator: string) => {
    const shape = operatorShape(operator);
    const next: RowFilter = { field: filters[index]!.field, operator };
    if (shape === "single") next.value = filters[index]!.value ?? "";
    if (shape === "multi") next.values = filters[index]!.values ?? [];
    onChange(filters.map((filter, i) => (i === index ? next : filter)));
  };

  return (
    <div className="rule-editor">
      <span className="field-picker__label">Row filters</span>

      {filters.length === 0 ? (
        <p className="muted">
          No row filters. Every record the source returns is passed through.
        </p>
      ) : (
        <>
          <p className="hint">
            All filters are ANDed. A record missing a referenced field is{" "}
            <strong>dropped</strong>, so a misspelled field name denies everything rather
            than nothing.
          </p>
          <ul className="rule-editor__list">
            {filters.map((filter, index) => {
              const shape = operatorShape(filter.operator);
              const unknownField =
                manifest !== undefined &&
                filter.field !== "" &&
                !known.has(filter.field) &&
                !filter.field.includes("*");

              return (
                <li key={index} className="rule-editor__row">
                  <div className="rule-editor__inputs">
                    <input
                      type="text"
                      list={listId}
                      value={filter.field}
                      placeholder={manifest ? "Select or type a field" : "Field name"}
                      aria-label={`Filter field ${index + 1}`}
                      onChange={(event) =>
                        update(index, { field: event.target.value })
                      }
                    />

                    <select
                      value={filter.operator}
                      aria-label={`Filter operator ${index + 1}`}
                      onChange={(event) => changeOperator(index, event.target.value)}
                    >
                      {ALL_OPERATORS.map((operator) => (
                        <option key={operator} value={operator}>
                          {operator}
                        </option>
                      ))}
                    </select>

                    {shape === "single" ? (
                      <input
                        type="text"
                        value={String(filter.value ?? "")}
                        placeholder="Value"
                        aria-label={`Filter value ${index + 1}`}
                        onChange={(event) =>
                          update(index, { value: event.target.value })
                        }
                      />
                    ) : null}

                    {shape === "multi" ? (
                      <ValueListInput
                        values={filter.values ?? []}
                        ariaLabel={`Filter values ${index + 1}`}
                        onChange={(values) => update(index, { values })}
                      />
                    ) : null}

                    <button
                      type="button"
                      onClick={() =>
                        onChange(filters.filter((_, i) => i !== index))
                      }
                      aria-label={`Remove filter ${index + 1}`}
                    >
                      ×
                    </button>
                  </div>

                  {unknownField ? (
                    <p className="rule-editor__warning">
                      ⚠ <code>{filter.field}</code> is not in this source's catalog. If it
                      is a typo, this filter drops every record.
                    </p>
                  ) : null}

                  {OPERATOR_NOTES[filter.operator] ? (
                    <p className="rule-editor__note">
                      {OPERATOR_NOTES[filter.operator]}
                    </p>
                  ) : null}
                </li>
              );
            })}
          </ul>
        </>
      )}

      <datalist id={listId}>
        {options.map((option) => (
          <option key={option} value={option} />
        ))}
      </datalist>

      <button
        type="button"
        onClick={() => onChange([...filters, { field: "", operator: "equals", value: "" }])}
      >
        Add row filter
      </button>
    </div>
  );
}
