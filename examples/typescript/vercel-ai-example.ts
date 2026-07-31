/**
 * TOLAP enforcement inside a Vercel AI SDK tool.
 *
 * `tool()` pairs a zod schema with an `execute` function. TOLAP goes inside `execute`, so the
 * schema the model sees is unchanged and the rows it receives are already enforced.
 *
 * Verified against ai 7.0.
 */

import { tool } from "ai";
import { z } from "zod";

import { enforcedQuery } from "./tolap-setup.js";

export const queryPatients = tool({
  description: "Query a patient table. Returns only what the caller's policy permits.",
  inputSchema: z.object({ table: z.string() }),
  execute: async ({ table }: { table: string }) => enforcedQuery(table),
});
