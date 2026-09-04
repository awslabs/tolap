#!/usr/bin/env python3
"""One row per HTTP route the policy server exposes.

Fastify: a route IS its handler (`app.get("/path", opts, handler)`). No separate handler
directory, no router table, so "dispatched" is not a gap axis -- a declared route is wired by
construction. Recorded in .claude/platform-audit.json.

Auth comes from the route's OWN body, bounded by the next `app.<method>(` declaration. An
earlier version used a fixed 45-line window and reported `POST .../rollback` and
`DELETE /v1/installs/:id` as auditor-only by matching a NEIGHBOURING route's guard. Both are
admin. Bounding the window is what makes the column trustworthy.

There is no API Gateway here (infra/lib: Network/Database/Identity/Server/Edge behind an ALB),
so auth is read from source rather than from a synth `AuthorizationType`. Weaker signal; said
so rather than implied.
"""
import json, re, pathlib

REPO = pathlib.Path("/Users/pspies/code/tolap-public")
ROUTES = REPO / "server/src/routes"
EXCLUDE = ("infra/cdk.out", "node_modules", "dist", "coverage", "TestResults", "/obj/", "/bin/")
excluded = lambda p: any(e in p for e in EXCLUDE)

ROUTE_RE = re.compile(
    r'\bapp\.(get|post|put|patch|delete|head|options)\s*(?:<[^>]*>)?\s*\(\s*["\'`]([^"\'`]+)["\'`]')

rows = []
for f in sorted(ROUTES.rglob("*.ts")):
    src = f.read_text()
    matches = list(ROUTE_RE.finditer(src))
    for i, m in enumerate(matches):
        line = src[:m.start()].count("\n") + 1
        # Bound the body at the NEXT route declaration in the same file.
        end = matches[i + 1].start() if i + 1 < len(matches) else len(src)
        body = src[m.start():end]
        if "requireInstall" in body:
            auth = "install-credential"
        elif re.search(r'\bauth\(\s*request\s*,\s*["\']auditor["\']', body):
            auth = "cognito:auditor"
        elif re.search(r'\bauth\(\s*request\s*\)', body):
            auth = "cognito:admin"
        else:
            auth = "NONE"
        rows.append({"method": m.group(1).upper(), "path": m.group(2),
                     "contract": f"{f.relative_to(REPO)}:{line}", "auth": auth})

def seg_regex(p: str) -> re.Pattern:
    segs = [s for s in p.strip("/").split("/") if s]
    if not segs: return re.compile(re.escape(p))
    parts = [r"/[^/\s\"'`?&]+" if s.startswith(":") else "/" + re.escape(s) for s in segs]
    # Anchor the END of the path. Without this, `/v1/policies` matches a test string
    # `/v1/policies/analyst/versions`, so eleven prefix-shadowed routes would claim coverage
    # from tests that only ever exercise a deeper route. The lookahead requires the path to
    # actually stop here: a closing quote, a query string, or whitespace.
    # `$` is allowed because the console builds nearly every URL as a template literal:
    # `/v1/policies${pageQuery(page)}`. Excluding it reported `GET /v1/policies` and
    # `POST /v1/policies/validate` as having no caller at all, which was wrong -- the console
    # calls both. `/` stays excluded, so `/v1/policies` still does not match
    # `/v1/policies/${name}` (that is the `:name` route), and the prefix-shadowing fix holds.
    return re.compile("".join(parts) + r"""(?=["'`?\s&)$]|$)""")

test_src = {p: p.read_text(errors="ignore")
            for p in REPO.rglob("*.test.ts") if not excluded(str(p))}
for r in rows:
    rx = seg_regex(r["path"])
    r["tests"] = sorted(str(p.relative_to(REPO)) for p, s in test_src.items() if rx.search(s))

cfg = json.loads((REPO / ".claude/platform-audit.json").read_text())
client_src = {}
for root in cfg["clients"]:
    base = REPO / root
    if not base.exists(): continue
    for ext in ("*.ts", "*.tsx", "*.py", "*.cs", "*.js", "*.html"):
        for p in base.rglob(ext):
            if excluded(str(p)) or p.name.endswith(".test.ts"): continue
            client_src[p] = p.read_text(errors="ignore")
for r in rows:
    rx = seg_regex(r["path"])
    r["callers"] = sorted(str(p.relative_to(REPO)) for p, s in client_src.items() if rx.search(s))

print(json.dumps(rows, indent=2))
