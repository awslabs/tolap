/**
 * Rendering a tool call as the one line a semantic judge reasons over.
 */

import type { PreExecuteArgs } from "./context-wrapper.js";

/**
 * Render a call for the judge and for the tool-call history.
 *
 * Deterministic, and includes only what the wrapper was given: the tool name, and the object,
 * fields and endpoint when present. Field *names* appear because "which columns" is most of what
 * makes a read on-purpose or not; field *values* never reach here, so no row data is sent to a
 * model by this path.
 *
 * Shared with the wrapper rather than reimplemented by an integrator calling `evaluateJudge`
 * directly: two renderings of one call would make the wrapper's history and a hand-rolled one
 * incomparable, and the history is what the judge uses to see drift.
 */
export function renderToolCall(args: PreExecuteArgs): string {
  const parts: string[] = [];
  if (args.objectName) parts.push(`object=${args.objectName}`);
  if (args.fields && args.fields.length > 0) parts.push(`fields=[${args.fields.join(",")}]`);
  if (args.endpointPath) {
    parts.push(`endpoint=${args.endpointMethod ?? "GET"} ${args.endpointPath}`);
  }

  return parts.length === 0 ? `${args.toolName}()` : `${args.toolName}(${parts.join(" ")})`;
}
