# TOLAP local test API

A dependency-free HTTP server for exercising TOLAP enforcement over a real socket.

```bash
python3 tools/test-api/server.py            # http://127.0.0.1:8888
python3 tools/test-api/server.py --port 9000 --verbose
curl -s http://127.0.0.1:8888/healthz       # {"status": "ok"}
```

Python standard library only. The core SDK packages ship zero runtime
dependencies and the test tooling should not be what introduces one.

## Why this exists

The integration suites mock HTTP in-process. That is fast and hermetic, but no
bytes ever cross a socket, so those tests cannot catch a wrapper that mishandles a
real response — an actual non-2xx status, real response headers, a chunked body, a
redirect. The only tests that used the network called `api.fda.gov` in order to
*refresh* the recorded fixtures, which means they rewrite files in the repository
and fail whenever the network (or the FDA) is unavailable. Neither approach
exercises `SecureHttpToolWrapper` against a genuine HTTP server.

This server closes that gap with no network dependency and no fixture mutation.

## Endpoints

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET | `/healthz` | Liveness probe. Always 200. |
| GET | `/drug/event.json` | Recorded openFDA drug-event payload. Honors `?limit=`. |
| GET | `/drug/label.json` | Recorded openFDA drug-label payload. Honors `?limit=`. |
| GET | `/food/enforcement.json` | Recorded openFDA food-enforcement payload. Honors `?limit=`. |
| GET | `/patients` | Flat records with PII. Filter with `?region=`. |
| GET | `/patients/nested` | Sensitive values nested below the top level. |
| GET | `/patients/envelope` | `{"items": [...], "total": N}` wrapper shape. |
| GET | `/admin/audit` | Target for endpoint-rule denial. |
| GET | `/status/<code>` | Returns that HTTP status. |
| GET | `/redirect/<code>?to=<target>` | Issues a real 301/302/307/308 to `target` (default `/admin/audit`). |
| GET | `/redirect-loop` | Redirects to itself, unbounded. |
| GET | `/slow?ms=N` | Delays N ms (capped at 30s) before responding. |
| GET | `/echo` | Reflects method, headers, and query string. |
| POST | `/patients` | Target for read-only / method denial. |

The openFDA routes serve the same recordings from `fixtures/api/openfda/` that the
in-process mocks replay, so a test can be written against either transport and
assert the same enforcement outcome.

## What each endpoint is for

**`/patients`** carries fields a policy is expected to hide (`ssn`,
`date_of_birth`), mask (`email`, `full_name`), filter on (`region`, `status`), and
tag-filter (`tags`). One record (id 5) has **no `tags` key at all**, which
exercises the untagged-record rule: dropped only when `allowedTags` is specified,
kept under a denylist-only policy.

**`/patients/nested`** puts `ssn` under `demographics` and `email` under
`demographics.contact`, so a wrapper that only walks the first level of a response
is caught. Real nested-field masking, not a synthetic dictionary.

**`/patients/envelope`** returns a collection wrapped in `{"items": [...]}`. Per
spec §5 a map is a record, so the envelope runs the full pipeline and is stripped
recursively rather than denied — a test should confirm the nested leak is closed.

**`/admin/audit` and `POST /patients` both succeed by design.** The server does not
hide them. The point is that TOLAP's endpoint and method rules are what deny them,
so a test asserting denial proves the policy did the work rather than the server.

**`/status/<code>`** covers error handling without needing an unreachable host:
4xx and 5xx bodies, and whether enforcement still applies to an error payload.

**`/redirect/<code>`** defaults its target to `/admin/audit` because that is the case
that matters: a permitted endpoint redirecting to one the policy denies. A wrapper that
inherits a redirect-following client bypasses its own endpoint rules on that hop. Pass
`?to=` for a relative target, or an absolute URL to exercise a cross-host redirect, which
is outside the policy's frame of reference and should be refused rather than re-matched.

**`/redirect-loop`** redirects to itself forever, so a wrapper that follows redirects
without a hop limit spins instead of failing.

**`/slow`** covers client timeout behavior. Threaded server, so a slow request
never blocks the rest of a suite.

**`/echo`** lets a test assert what the wrapper actually transmitted — headers
(including `Authorization`), method, and query — rather than inferring it.

## Notes

- Bound to `127.0.0.1` by default. It has no authentication and is for local
  testing only; do not expose it.
- Request logging is off unless `--verbose`, since the suites start it as a child
  process and per-request logs drown the test output.
- The server never writes to `fixtures/`. Refreshing recordings remains the job of
  the `TOLAP_TEST_LIVE=1` tests that call the real openFDA API.
