/**
 * TOLAP Tool-Call History (canonical spec §15.4)
 *
 * A bounded, in-order record of recent tool calls, for supplying a judge its
 * context window.
 *
 * Purpose drift is a property of a **sequence**, not of a single call. An agent
 * that asks for one more field each turn is unremarkable at every individual step
 * and obvious across ten, so a judge given only the current call cannot see the
 * thing it exists to notice.
 *
 * Deliberately not persistent and not shared. It holds whatever the caller records,
 * which may include argument values, so a process-local buffer that dies with the
 * session is the narrowest thing that does the job. An integrator wanting durable
 * history should store it themselves, with the retention rules their data demands.
 */

import { DEFAULT_HISTORY_WINDOW } from "./judge.js";

export class ToolCallHistory {
  /** The retention bound. */
  readonly maxSize: number;

  private entries: string[] = [];

  /**
   * @param maxSize
   * How many calls to keep. Must be at least one: a zero-size window would make
   * {@link record} a no-op and hand the judge an empty history that looks like a
   * fresh conversation, which is precisely the state a drifting agent would
   * benefit from.
   *
   * @throws Error when `maxSize` is less than one, or not an integer. Checked at
   * runtime rather than left to the type: types are erased, and the failure this
   * guards is silent — a judge that sees nothing reports everything as fine.
   */
  constructor(maxSize: number = DEFAULT_HISTORY_WINDOW) {
    if (!Number.isInteger(maxSize) || maxSize < 1) {
      throw new Error(
        `ToolCallHistory maxSize must be an integer of at least 1, received ` +
          `${String(maxSize)}; a zero-size window silently hands the judge an ` +
          `empty conversation`,
      );
    }
    this.maxSize = maxSize;
  }

  /** The number of entries currently retained. */
  get count(): number {
    return this.entries.length;
  }

  /**
   * Record a call, evicting the oldest entry once the window is full.
   *
   * @throws Error when `toolCall` is not a string. A `null` recorded and later
   * rendered into a judge prompt reads as a real call named "null", so it is
   * refused where the mistake is made.
   */
  record(toolCall: string): void {
    if (typeof toolCall !== "string") {
      throw new Error(
        `ToolCallHistory.record expects a string rendering of the call, received ` +
          `${toolCall === null ? "null" : typeof toolCall}`,
      );
    }

    this.entries.push(toolCall);
    while (this.entries.length > this.maxSize) {
      this.entries.shift();
    }
  }

  /**
   * The retained calls, **oldest first**.
   *
   * Oldest first because a judge reading a trajectory needs it in the order it
   * happened. Returns a copy, so a caller holding the result cannot see it change
   * underneath them on the next {@link record} — nor mutate the buffer through it.
   */
  getRecent(): string[] {
    return [...this.entries];
  }

  /** Discard every entry, for reuse across conversations. The bound is kept. */
  clear(): void {
    this.entries = [];
  }
}
