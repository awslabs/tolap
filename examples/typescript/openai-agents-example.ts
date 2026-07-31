/**
 * TOLAP enforcement inside an OpenAI Agents JS function tool.
 *
 * `tool()` derives the JSON schema the model sees from the zod parameters. TOLAP lives inside
 * `execute`, so the schema is unchanged and the rows the model receives are already enforced.
 *
 * Verified against @openai/agents 0.14. No API key is needed: the test drives the enforced
 * function, which is the code path the runtime reaches once the model chooses the tool.
 */

import { tool } from "@openai/agents";
import { z } from "zod";

import { enforcedQuery } from "./tolap-setup.js";

export const queryPatients = tool({
  name: "query_patients",
  description: "Query a patient table. Returns only what the caller's policy permits.",
  parameters: z.object({ table: z.string() }),
  execute: async ({ table }: { table: string }) => enforcedQuery(table),
});
