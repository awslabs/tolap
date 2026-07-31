#!/usr/bin/env python3
"""Local test API for TOLAP integration testing.

Serves the recorded openFDA fixtures over real HTTP, plus a set of endpoints that
exercise the enforcement paths the in-process transport mocks cannot reach:
authorization headers, error statuses, nested response bodies, and endpoint/method
restrictions.

Why this exists. The integration suites mock HTTP in-process, which is fast and
hermetic but never puts bytes on a socket -- so it cannot catch a wrapper that
mishandles a real response, a redirect, a chunked body, or a non-2xx status. The
only tests that used the network hit api.fda.gov to *refresh fixtures*, which
means they mutate the repository and fail when the internet (or the FDA) is
unavailable. This server closes that gap without either drawback.

Standard library only: the core packages ship zero runtime dependencies and the
test tooling should not be the thing that introduces one.

Usage
-----
    python3 tools/test-api/server.py                 # port 8888
    python3 tools/test-api/server.py --port 9000
    TOLAP_TEST_API_URL=http://127.0.0.1:8888 python3 -m pytest ...

Endpoints
---------
    GET  /healthz                     liveness probe, always 200
    GET  /drug/event.json             recorded openFDA drug-event payload
    GET  /drug/label.json             recorded openFDA drug-label payload
    GET  /food/enforcement.json       recorded openFDA food-enforcement payload
    GET  /patients                    flat records with PII (masking/hiding)
    GET  /patients/nested             nested records (recursive enforcement)
    GET  /patients/envelope           {"items": [...]} wrapper shape
    GET  /admin/audit                 should be denied by endpoint rules
    GET  /status/<code>               returns that HTTP status (error paths)
    GET  /slow?ms=N                   delayed response (timeout handling)
    GET  /echo                        reflects method, headers, and query
    POST /patients                    should be denied for read-only policies
"""

from __future__ import annotations

import argparse
import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
OPENFDA_FIXTURES = REPO_ROOT / "fixtures" / "api" / "openfda"

# Mirrors OPENFDA_ROUTES in the language test suites so the same recorded bodies
# are served here as are replayed in-process.
OPENFDA_ROUTES = {
    "/drug/event.json": "drug_event_limit3.json",
    "/drug/label.json": "drug_label_limit3.json",
    "/food/enforcement.json": "food_enforcement_limit2.json",
}

# Deliberately includes fields a policy is expected to hide or mask (ssn,
# date_of_birth, email) alongside fields it should leave intact, and a `tags`
# array so tag rules can be exercised over a real response.
PATIENTS = [
    {
        "id": 1,
        "full_name": "Alice Nguyen",
        "ssn": "111-22-3333",
        "date_of_birth": "1979-04-12",
        "email": "alice@example.com",
        "region": "us-east",
        "status": "active",
        "tags": ["public"],
    },
    {
        "id": 2,
        "full_name": "Bruno Sato",
        "ssn": "222-33-4444",
        "date_of_birth": "1985-11-02",
        "email": "bruno@example.com",
        "region": "us-west",
        "status": "active",
        "tags": ["public", "research"],
    },
    {
        "id": 3,
        "full_name": "Chloe Adeyemi",
        "ssn": "333-44-5555",
        "date_of_birth": "1992-07-30",
        "email": "chloe@example.com",
        "region": "eu-west",
        "status": "active",
        "tags": ["confidential"],
    },
    {
        "id": 4,
        "full_name": "Dmitri Volkov",
        "ssn": "444-55-6666",
        "date_of_birth": "1968-01-19",
        "email": "dmitri@example.com",
        "region": "us-east",
        "status": "deleted",
        "tags": ["public"],
    },
    # No `tags` key at all: exercises the untagged-record rule (dropped only when
    # allowedTags is specified, kept under a denylist-only policy).
    {
        "id": 5,
        "full_name": "Elena Rossi",
        "ssn": "555-66-7777",
        "date_of_birth": "2001-03-08",
        "email": "elena@example.com",
        "region": "us-west",
        "status": "active",
    },
]

# Sensitive values sit below the top level so a wrapper that only walks the first
# level of a response is caught.
NESTED_PATIENTS = [
    {
        "id": 1,
        "demographics": {
            "full_name": "Alice Nguyen",
            "ssn": "111-22-3333",
            "contact": {"email": "alice@example.com", "phone": "555-0100"},
        },
        "encounters": [
            {"id": 11, "notes": "routine", "billing": {"amount_cents": 12000}},
        ],
        "region": "us-east",
    },
    {
        "id": 2,
        "demographics": {
            "full_name": "Bruno Sato",
            "ssn": "222-33-4444",
            "contact": {"email": "bruno@example.com", "phone": "555-0101"},
        },
        "encounters": [
            {"id": 21, "notes": "follow-up", "billing": {"amount_cents": 8000}},
        ],
        "region": "us-west",
    },
]

STATUS_PATH = re.compile(r"^/status/(\d{3})$")

# /redirect/<code>?to=<target> issues a real 3xx to <target>. Exists so a wrapper's
# redirect handling can be tested over a socket: a permitted endpoint that redirects
# to a denied one must not bypass the endpoint rules (connector-spec.md section 6).
REDIRECT_PATH = re.compile(r"^/redirect/(30[1278])$")

# /redirect-loop bounces to itself, so a wrapper that follows redirects without a hop
# limit spins rather than failing.
LOOP_PATH = "/redirect-loop"


class TestApiHandler(BaseHTTPRequestHandler):
    """Request handler for the TOLAP test API."""

    server_version = "TolapTestApi/1.0"

    # -- helpers ---------------------------------------------------------------

    def _send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Echoed back so a test can assert the wrapper preserved (or stripped)
        # response headers as the policy requires.
        self.send_header("X-Tolap-Test-Api", "1")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _openfda(self, path: str, query: dict[str, list[str]]) -> None:
        fixture = OPENFDA_ROUTES.get(path)
        if fixture is None:
            self._send_json(404, {"error": {"code": "NOT_FOUND", "message": path}})
            return
        source = OPENFDA_FIXTURES / fixture
        if not source.exists():
            self._send_json(
                500,
                {"error": {"code": "FIXTURE_MISSING", "message": str(source)}},
            )
            return
        body = json.loads(source.read_text())
        # Honour ?limit= so a test can distinguish server-side truncation from the
        # policy's own maxResults enforcement.
        limit = query.get("limit", [None])[0]
        if limit is not None and isinstance(body.get("results"), list):
            try:
                body["results"] = body["results"][: int(limit)]
            except ValueError:
                self._send_json(
                    400, {"error": {"code": "BAD_LIMIT", "message": limit}}
                )
                return
        self._send_json(200, body)

    # -- routing ---------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        if path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return

        if path in OPENFDA_ROUTES:
            self._openfda(path, query)
            return

        if path == "/patients":
            records = PATIENTS
            region = query.get("region", [None])[0]
            if region:
                records = [r for r in records if r.get("region") == region]
            self._send_json(200, {"results": records})
            return

        if path == "/patients/nested":
            self._send_json(200, {"results": NESTED_PATIENTS})
            return

        if path == "/patients/envelope":
            self._send_json(200, {"items": PATIENTS, "total": len(PATIENTS)})
            return

        if path == "/admin/audit":
            # Reachable on purpose: the point is that TOLAP endpoint rules deny it,
            # not that the server hides it. A test asserting denial here proves the
            # policy did the work.
            self._send_json(200, {"results": [{"id": 1, "actor": "root"}]})
            return

        match = STATUS_PATH.match(path)
        if match:
            code = int(match.group(1))
            self._send_json(code, {"error": {"code": code, "message": "synthetic"}})
            return

        match = REDIRECT_PATH.match(path)
        if match:
            # Defaults to /admin/audit so the common case is the one that matters: a
            # permitted endpoint redirecting to one the policy denies.
            target = query.get("to", ["/admin/audit"])[0]
            body = json.dumps({"redirectedTo": target}).encode("utf-8")
            self.send_response(int(match.group(1)))
            self.send_header("Location", target)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            return

        if path == LOOP_PATH:
            self.send_response(302)
            self.send_header("Location", LOOP_PATH)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/slow":
            delay_ms = query.get("ms", ["1000"])[0]
            try:
                time.sleep(min(int(delay_ms), 30_000) / 1000)
            except ValueError:
                self._send_json(400, {"error": {"code": "BAD_MS"}})
                return
            self._send_json(200, {"results": [], "delayedMs": int(delay_ms)})
            return

        if path == "/echo":
            self._send_json(
                200,
                {
                    "method": self.command,
                    "path": parsed.path,
                    "query": {k: v for k, v in query.items()},
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                },
            )
            return

        self._send_json(404, {"error": {"code": "NOT_FOUND", "message": path}})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""

        if path in ("/patients", "/echo"):
            try:
                sent = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                self._send_json(400, {"error": {"code": "BAD_JSON"}})
                return
            # Succeeds by design: a read-only policy must be what prevents the
            # write, so a test asserting denial is testing enforcement.
            self._send_json(201, {"created": True, "received": sent})
            return

        self._send_json(404, {"error": {"code": "NOT_FOUND", "message": path}})

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.do_GET()

    def log_message(self, fmt: str, *args: object) -> None:
        # Quiet by default: the suites start this server as a child process and
        # per-request logging drowns the test output. Enable with --verbose.
        if self.server.verbose:  # type: ignore[attr-defined]
            super().log_message(fmt, *args)


class TestApiServer(ThreadingHTTPServer):
    """Threading server so a /slow request cannot block the rest of a suite."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], verbose: bool) -> None:
        super().__init__(address, TestApiHandler)
        self.verbose = verbose


def main() -> None:
    parser = argparse.ArgumentParser(description="TOLAP local test API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--verbose", action="store_true", help="log every request")
    args = parser.parse_args()

    if not OPENFDA_FIXTURES.exists():
        raise SystemExit(f"openFDA fixtures not found at {OPENFDA_FIXTURES}")

    server = TestApiServer((args.host, args.port), args.verbose)
    print(f"TOLAP test API listening on http://{args.host}:{args.port}")
    print(f"  serving openFDA recordings from {OPENFDA_FIXTURES}")
    print("  GET /healthz to probe; Ctrl-C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
