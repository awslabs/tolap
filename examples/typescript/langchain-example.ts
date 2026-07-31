/**
 * TOLAP enforcement inside a LangChain.js tool.
 *
 * The integration is one line: the tool function calls `enforcedQuery` instead of the database.
 * LangChain sees an ordinary tool; the model cannot reach the raw rows because the only path to
 * them runs through the policy.
 *
 * Verified against @langchain/core 1.2.
 */

import { tool } from "@langchain/core/tools";
import { z } from "zod";

import { enforcedQuery } from "./tolap-setup.js";

export const queryPatients = tool(
  // No enforcement logic here on purpose. Everything policy-related lives behind enforcedQuery,
  // so a second tool cannot accidentally implement it differently — the failure mode where one
  // tool strips a hidden field and its neighbour forgets.
  ({ table }: { table: string }) => enforcedQuery(table),
  {
    name: "query_patients",
    description: "Query a patient table. Returns only what the caller's policy permits.",
    schema: z.object({ table: z.string() }),
  },
);
