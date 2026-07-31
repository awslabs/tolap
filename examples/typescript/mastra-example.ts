/**
 * TOLAP enforcement inside a Mastra tool.
 *
 * `createTool` takes an id, schemas and an `execute`. TOLAP goes inside `execute` — same
 * substitution as every other framework here.
 *
 * Verified against @mastra/core 1.55.
 */

import { createTool } from "@mastra/core/tools";
import { z } from "zod";

import { enforcedQuery } from "./tolap-setup.js";

export const queryPatients = createTool({
  id: "query_patients",
  description: "Query a patient table. Returns only what the caller's policy permits.",
  inputSchema: z.object({ table: z.string() }),
  execute: async ({ table }: { table: string }) => enforcedQuery(table),
});
