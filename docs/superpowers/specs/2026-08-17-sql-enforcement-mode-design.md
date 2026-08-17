# SQL enforcement mode: naming a choice that already exists

**Date:** 2026-08-17
**Status:** approved

## The problem

TOLAP restricts database results in two places, and both already work in all three SDKs:

1. **Before the query runs** — the rewriter pushes row filters into `WHERE`, the result
   limit into `LIMIT`, and projects hidden columns out of the `SELECT`.
2. **After the query runs** — the post-execution pipeline drops rows, removes hidden
   fields, applies masking, and caps the result count.

An integrator already chooses between them, implicitly, by calling the rewriter or not.
Three things are wrong with that:

**No name and no stated default.** The choice is "which function did you happen to
call". Nothing tells an integrator the option exists or which to prefer.

**The README is wrong.** It says "For SQL sources *the .NET SDK* additionally offers
optional query rewriting". Python has `prepare_sql_query`, TypeScript has
`SqlQueryRewriter`. A reader would conclude they need .NET for this.

**The SDKs disagree on the default, because they are shaped differently.** .NET has
`ExecuteSqlWithEnforcementAsync` — one call that rewrites *and* post-executes, with
`rewriter ??= new SqlQueryRewriter()`, so rewriting is on unless you pass a null object.
Python's `execute_with_enforcement` and TypeScript's `executeTool` are generic, have no
SQL awareness, and never rewrite. Same policy, same database, different query — which
this project's own standard calls a security defect rather than an inconsistency.

## What this does not change

The post-execution pass stays **unconditional**. It is the enforcement boundary
(canonical-enforcement-spec §4), and two things have no SQL form at all:

- **Masking.** No `SELECT` returns `[REDACTED]` or a salted hash.
- **`contains`, `startsWith`, `matches`.** Not portably expressible, so the rewriter
  declines to push them and reports them in `unpushable_filters`.

Demonstrated against the shipped code: a policy with `startsWith` and a redacted email,
rewritten for Postgres, produced
`SELECT ... WHERE "region" = 'us-east' LIMIT 2` and reported `startsWith` as unpushable.
The database returned a row the filter should have removed; the post pass removed it and
redacted the email. A rewrite-only path would have returned both the extra row and a
clear-text address.

So there is deliberately **no** `rewrite_only` mode. An enum with no name for the unsafe
option cannot select it by accident.

## Design

### `SqlEnforcementMode`

A two-value enum in `core`, beside `MaskType` and `SqlDialect`:

| Value | Meaning |
|---|---|
| `rewrite_and_post` | Push filters, limit and projection into the SQL, then enforce on results. **Default.** |
| `post_only` | Leave the SQL untouched; enforce entirely on results. |

`rewrite_and_post` is the default because it is what .NET already does (so no existing
caller changes behaviour), because it is strictly better on resources, and because it is
safe — the post pass runs identically in both modes.

`post_only` exists for integrators who will not have their SQL edited: a query the
rewriter's parser does not handle, a stored procedure, an ORM that owns its own SQL, or a
reviewer who wants the query that ran to be the query they wrote.

**Pre-execution checks run in both modes.** `post_only` skips the *rewrite*, not the
`allowedObjects` check, the `canQuery` check, or the refusal of a query naming a hidden
field. Declining to rewrite must never relax a denial.

### Where the mode is set

Integrator configuration, passed at the call site next to `dialect`. **Not** in the
policy document:

- It is a deployment and performance concern, not an access-control rule. Two
  deployments enforcing the same policy may reasonably differ.
- A signed policy dictating execution strategy would make the security artifact
  responsible for something it cannot verify happened.
- It avoids a schema change, cross-SDK fixture churn, console work, and a merge-semantics
  question with no good answer (which mode is "more restrictive"? Neither — they produce
  identical results).

### Per-SDK surface

| SDK | Change |
|---|---|
| .NET | `mode` parameter on `PrepareSqlQuery` and `ExecuteSqlWithEnforcementAsync`, defaulting to `RewriteAndPost`. |
| Python | `mode=` on `prepare_sql_query`; new `execute_sql_with_enforcement` on the wrapper. |
| TypeScript | `mode` on the rewriter path; new `executeSqlWithEnforcement` on the wrapper. |

The two new helpers are the substance of the fix. Without them the mode is reachable
only in .NET, and the three SDKs stay shaped differently.

## The invariant, and how it is tested

**Both modes MUST return identical results for the same policy and the same data.**

This is the whole safety argument. If they diverged, the mode would be an access-control
setting wearing a performance setting's clothes — the divergence class §4 exists to
prevent.

Tested by running both modes against live PostgreSQL and MySQL and asserting
byte-identical output, rather than asserting each mode works in isolation. A per-mode test
would pass if `post_only` quietly returned extra rows, because nothing would compare the
two.

Also tested:

- `post_only` leaves the query string untouched, byte for byte.
- `post_only` still denies a query naming a hidden field, and still denies on
  `allowedObjects` — skipping the rewrite does not skip a check.
- An unrecognized mode fails closed rather than silently selecting a default.
- Cross-SDK: the same policy and query produce the same mode-independent result in all
  three languages, pinned in `fixtures/`.

## Documentation

- **README** — replace the ".NET SDK additionally offers" paragraph with the two places
  enforcement applies, the mode names, the default, and when to choose `post_only`.
- **canonical-enforcement-spec §4** — name the modes; restate that the post pass is
  unconditional in both and that no rewrite-only mode exists, with the masking and
  unpushable-operator reasons.
- **connector-spec** — the `db` category section.
- **Three implementation guides** — the mode in each language's idiom.

## Out of scope

- **Narrowing a projection instead of refusing it.** Today a query naming a hidden field
  is refused. Silently dropping the column is a different feature and a change to an
  existing security decision.
- **A `rewrite_only` mode.** Unsafe, as above.
- **Policy-level mode selection.** Reasoning under "Where the mode is set".
