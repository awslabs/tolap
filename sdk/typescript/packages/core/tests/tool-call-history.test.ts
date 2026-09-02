/**
 * `ToolCallHistory` — the bounded trajectory a judge is shown (canonical spec §15.4).
 *
 * Purpose drift is a property of a sequence, not of a single call. An agent that asks
 * for one more field each turn is unremarkable at every individual step and obvious
 * across ten, so the two properties that matter are **order** and **retention**: the
 * judge must see the calls in the order they happened, and a window that silently kept
 * nothing would hand it a conversation that looks fresh — precisely the state a
 * drifting agent would benefit from.
 */

import { describe, expect, it } from "vitest";
import { ToolCallHistory } from "../src/history.js";
import { DEFAULT_HISTORY_WINDOW } from "../src/judge.js";
import type { JudgeRequest } from "../src/judge.js";

describe("a fresh history", () => {
  it("retains nothing", () => {
    const history = new ToolCallHistory();

    expect(history.getRecent()).toEqual([]);
    expect(history.count).toBe(0);
  });

  it("defaults to the documented judge window", () => {
    // The default matches what `judgeHistoryWindow` returns for an unconfigured policy,
    // so an integrator who sizes nothing still gets the window the schema documents.
    expect(new ToolCallHistory().maxSize).toBe(DEFAULT_HISTORY_WINDOW);
  });
});

describe("retention", () => {
  it("keeps everything below the bound, oldest first", () => {
    const history = new ToolCallHistory(5);
    history.record("count_segments()");
    history.record("aggregate_overlap(campaign-x)");

    expect(history.getRecent()).toEqual([
      "count_segments()",
      "aggregate_overlap(campaign-x)",
    ]);
    expect(history.count).toBe(2);
  });

  it("keeps everything exactly at the bound", () => {
    const history = new ToolCallHistory(3);
    for (const call of ["a", "b", "c"]) history.record(call);

    expect(history.getRecent()).toEqual(["a", "b", "c"]);
    expect(history.count).toBe(3);
  });

  it("evicts the oldest above the bound", () => {
    const history = new ToolCallHistory(3);
    for (const call of ["a", "b", "c", "d", "e"]) history.record(call);

    expect(history.getRecent()).toEqual(["c", "d", "e"]);
    expect(history.count).toBe(3);
  });

  it("a window of one keeps only the latest", () => {
    // The smallest legal window, and the boundary the constructor guard sits next to.
    const history = new ToolCallHistory(1);
    history.record("a");
    history.record("b");

    expect(history.getRecent()).toEqual(["b"]);
    expect(history.count).toBe(1);
  });

  it("keeps duplicates and empty strings rather than de-duplicating", () => {
    // A repeated call IS the signal in a drift trajectory -- an agent retrying the same
    // widening request looks different from one that asked once. Collapsing duplicates
    // would erase exactly that.
    const history = new ToolCallHistory(4);
    history.record("aggregate_overlap()");
    history.record("aggregate_overlap()");
    history.record("");

    expect(history.getRecent()).toEqual([
      "aggregate_overlap()",
      "aggregate_overlap()",
      "",
    ]);
  });
});

describe("the retention bound is validated", () => {
  for (const maxSize of [0, -1, Number.MIN_SAFE_INTEGER]) {
    it(`refuses ${maxSize}`, () => {
      // A zero-size window would make `record` a no-op and hand the judge an empty
      // conversation. Refused where the mistake is made, because the symptom -- a judge
      // that never notices anything -- looks like the judge working.
      expect(() => new ToolCallHistory(maxSize)).toThrow(
        /maxSize must be an integer of at least 1/,
      );
    });
  }

  for (const maxSize of [1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    it(`refuses the non-integer ${String(maxSize)}`, () => {
      // `NaN < 1` is false, so a bare comparison would accept it and then compare every
      // length against `NaN` -- retaining without limit. `Infinity` is the same class of
      // input arriving from a config file that meant "unbounded".
      expect(() => new ToolCallHistory(maxSize)).toThrow(
        /maxSize must be an integer of at least 1/,
      );
    });
  }

  it("accepts one, and the error names the value it refused", () => {
    // The paired control, plus the actionable half of the message.
    expect(new ToolCallHistory(1).maxSize).toBe(1);
    expect(() => new ToolCallHistory(0)).toThrow(/received 0/);
  });

  it("the bound is read-only after construction", () => {
    // Resizing after the fact would let a caller widen what the policy chose. The
    // policy's window is read once, when the buffer is created.
    const history = new ToolCallHistory(2);
    expect(history.maxSize).toBe(2);
    history.record("a");
    history.record("b");
    history.record("c");
    expect(history.maxSize).toBe(2);
    expect(history.getRecent()).toEqual(["b", "c"]);
  });
});

describe("record refuses a non-string", () => {
  it("rejects null and undefined", () => {
    // A `null` recorded and later rendered into a judge prompt reads as a real call
    // named "null", which is a fact about the trajectory that never happened.
    const history = new ToolCallHistory();

    expect(() => history.record(null as unknown as string)).toThrow(
      /expects a string rendering of the call, received null/,
    );
    expect(() => history.record(undefined as unknown as string)).toThrow(
      /received undefined/,
    );
    expect(history.count).toBe(0);
  });

  it("rejects a non-string value and records nothing", () => {
    const history = new ToolCallHistory();

    expect(() => history.record({ tool: "x" } as unknown as string)).toThrow(
      /received object/,
    );
    expect(() => history.record(7 as unknown as string)).toThrow(/received number/);
    expect(history.getRecent()).toEqual([]);
  });

  it("accepts a string, including an empty one", () => {
    const history = new ToolCallHistory();
    history.record("");
    expect(history.getRecent()).toEqual([""]);
  });
});

describe("getRecent returns a copy", () => {
  it("a held snapshot does not change on the next record", () => {
    const history = new ToolCallHistory(2);
    history.record("a");
    const snapshot = history.getRecent();
    history.record("b");

    expect(snapshot).toEqual(["a"]);
    expect(history.getRecent()).toEqual(["a", "b"]);
  });

  it("mutating the snapshot does not reach the buffer", () => {
    // A caller handed the live array could rewrite the trajectory the judge is about to
    // be shown -- and the buffer is the thing the judge's context window is built from.
    const history = new ToolCallHistory(2);
    history.record("a");
    const snapshot = history.getRecent();
    snapshot[0] = "mutated";
    snapshot.push("injected");

    expect(history.getRecent()).toEqual(["a"]);
  });

  it("two snapshots are distinct arrays", () => {
    const history = new ToolCallHistory();
    history.record("a");

    expect(history.getRecent()).not.toBe(history.getRecent());
    expect(history.getRecent()).toEqual(history.getRecent());
  });
});

describe("clear", () => {
  it("discards every entry and keeps the bound", () => {
    const history = new ToolCallHistory(2);
    history.record("a");
    history.clear();

    expect(history.getRecent()).toEqual([]);
    expect(history.count).toBe(0);
    expect(history.maxSize).toBe(2);
  });

  it("a cleared history still evicts correctly afterwards", () => {
    // Reuse across conversations is the documented purpose, so the buffer has to behave
    // like a fresh one rather than like one whose internals were half-reset.
    const history = new ToolCallHistory(2);
    history.record("a");
    history.record("b");
    history.clear();
    for (const call of ["c", "d", "e"]) history.record(call);

    expect(history.getRecent()).toEqual(["d", "e"]);
  });

  it("clearing an empty history is harmless", () => {
    const history = new ToolCallHistory();
    history.clear();
    expect(history.count).toBe(0);
  });

  it("a snapshot taken before clear is unaffected", () => {
    const history = new ToolCallHistory(2);
    history.record("a");
    const snapshot = history.getRecent();
    history.clear();

    expect(snapshot).toEqual(["a"]);
  });
});

describe("feeding a judge request", () => {
  it("supplies the trajectory in chronological order", () => {
    // The order is the whole point: a trajectory read backwards shows an agent
    // narrowing where it was in fact widening.
    const history = new ToolCallHistory(3);
    history.record("count_segments()");
    history.record("aggregate_overlap(campaign-x)");
    history.record("export_csv(customer_segments)");

    const request: JudgeRequest = {
      purpose: { purposeId: "campaign-x-overlap" },
      currentToolCall: "export_csv(customer_segments)",
      recentHistory: history.getRecent(),
      maxLatencyMs: 2000,
    };

    expect(request.recentHistory).toEqual([
      "count_segments()",
      "aggregate_overlap(campaign-x)",
      "export_csv(customer_segments)",
    ]);
  });
});
