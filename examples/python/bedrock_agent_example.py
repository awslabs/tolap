"""TOLAP enforcement in a Bedrock Agents action group.

Bedrock Agents differ from the in-process frameworks in this directory: the agent does not call
your function, it invokes a **Lambda** with an event describing the chosen action. The
enforcement point is therefore the Lambda handler, and the integration is the same substitution --
the handler calls :func:`enforced_query` rather than the data source.

The difference that matters is *where the signed context comes from*. In-process, the tool can
build it because it is inside your service. A Lambda is a separate execution environment, so the
context must arrive with the request: pass it as a session attribute, which Bedrock forwards to
the action group unchanged. It must be the **signed** context -- the Lambda verifies the
signature before enforcing, so a tampered policy is refused rather than applied.

    python bedrock_agent_example.py

No AWS call is made: the example feeds the handler a Bedrock-shaped event, which is what the
service delivers.
"""

from __future__ import annotations

import json
from typing import Any

from tolap_core.context import deserialize_context
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper

from tolap_setup import (
    SIGNING_KEY,
    query_patients_unsafe,
    signed_context,
)


def lambda_handler(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    """The action-group handler. Verifies the caller's context, then enforces on the result."""
    params = {p["name"]: p["value"] for p in event.get("parameters", [])}
    table = params.get("table", "")

    # The context travels in session attributes. Absent or unverifiable means deny: an action
    # group that fell back to "no policy" would be an unauthenticated read of the data source.
    serialized = (event.get("sessionAttributes") or {}).get("tolapContext")
    if not serialized:
        return _response(event, 403, {"error": "no TOLAP context supplied"})

    # deserialize_context verifies the signature as it parses, so an unverifiable context
    # cannot get as far as the enforcement call -- the check is not something a handler can
    # forget to perform separately.
    try:
        context = deserialize_context(serialized, SIGNING_KEY)
    except Exception as exc:
        return _response(event, 403, {"error": f"context rejected: {exc}"})

    wrapper = SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=SIGNING_KEY))
    try:
        rows = wrapper.execute_with_enforcement(
            context=context,
            tool_name="query_patients",
            tool_fn=query_patients_unsafe,
            tool_args={"table": table},
            object_name=table,
        )
    except PermissionError as exc:
        # 403 rather than an empty 200. The agent must be able to tell "not permitted" from
        # "nothing matched", and so must the audit trail.
        return _response(event, 403, {"error": str(exc)})

    return _response(event, 200, {"rows": rows})


def _response(event: dict[str, Any], status: int, body: dict[str, Any]) -> dict[str, Any]:
    """The response envelope Bedrock Agents expects from an action group."""
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": event.get("actionGroup", "patients"),
            "apiPath": event.get("apiPath", "/patients"),
            "httpMethod": event.get("httpMethod", "GET"),
            "httpStatusCode": status,
            "responseBody": {"application/json": {"body": json.dumps(body)}},
        },
    }


def _event(table: str, serialized_context: str | None) -> dict[str, Any]:
    return {
        "messageVersion": "1.0",
        "actionGroup": "patients",
        "apiPath": "/patients",
        "httpMethod": "GET",
        "parameters": [{"name": "table", "value": table, "type": "string"}],
        "sessionAttributes": {"tolapContext": serialized_context} if serialized_context else {},
    }


def _body(response: dict[str, Any]) -> dict[str, Any]:
    return json.loads(response["response"]["responseBody"]["application/json"]["body"])


def main() -> None:
    from tolap_core.context import serialize_context

    serialized = serialize_context(signed_context())

    ok = lambda_handler(_event("patients", serialized))
    rows = _body(ok)["rows"]
    print(f"permitted table -> {len(rows)} row(s)")
    for row in rows:
        print("   ", row)

    denied = lambda_handler(_event("encounters", serialized))
    print(f"denied table    -> {denied['response']['httpStatusCode']} {_body(denied)['error'][:50]}")

    missing = lambda_handler(_event("patients", None))
    print(f"no context      -> {missing['response']['httpStatusCode']} {_body(missing)['error']}")


if __name__ == "__main__":
    main()
