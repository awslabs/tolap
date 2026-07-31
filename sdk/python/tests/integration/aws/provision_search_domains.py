"""Provisions AWS OpenSearch Service domains for the `kb` filter renderers.

TOLAP renders `kb` metadata filters for six providers. Only Bedrock was ever verified against a
live service; the other five are marked ``from_grammar`` -- meaning we wrote them from the
documented query DSL and no engine has ever confirmed it accepts them. This script closes two of
those five, and it closes them against the *real* engines rather than a lookalike:

* ``OpenSearch_2.19``    -- the ``opensearch`` renderer
* ``Elasticsearch_7.10`` -- the ``elasticsearch`` renderer

Both renderers currently emit the same document (a ``bool``/``filter``/``terms`` query), and one
of the questions worth answering is whether that is still correct: Elasticsearch 7.10 was forked
from OpenSearch's ancestor, and the DSLs have drifted since. If they accept identical documents,
the shared implementation is justified; if not, we have a divergence to fix. Either outcome is
worth knowing, and neither can be learned from a fixture we wrote ourselves.

Cost and safety
---------------
A managed domain bills per hour for as long as it exists and takes 15-25 minutes to create, so
this is not a resource to leak. Two habits from the Bedrock KB provisioning, which orphaned a
bucket and an IAM role when it crashed midway:

* every resource id is written to the ``--state`` file *as it is created*, not at the end, so a
  crash still leaves a complete teardown manifest;
* ``down`` is idempotent and deletes only ids recorded in that file -- never by prefix sweep, in
  an account that is shared and holds real data.

Usage::

    python3 provision_search_domains.py up   --state /tmp/search.env
    python3 provision_search_domains.py down --from /tmp/search.env
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

# t3.small.search is the cheapest instance that supports both engines. One node, no replica,
# 10 GiB -- this holds four documents.
INSTANCE_TYPE = "t3.small.search"
VOLUME_SIZE_GIB = 10

ENGINES = {
    "opensearch": "OpenSearch_2.19",
    "elasticsearch": "Elasticsearch_7.10",
}

#: The seeded corpus, mirroring the Bedrock KB so the two `kb` backends are compared on the same
#: data: two public documents and two secret ones.
DOCUMENTS = [
    {"id": "1", "classification": "public", "text": "Q3 product roadmap and public release notes."},
    {"id": "2", "classification": "public", "text": "Published quarterly financial summary."},
    {"id": "3", "classification": "secret", "text": "Unannounced acquisition target analysis."},
    {"id": "4", "classification": "secret", "text": "Internal margin breakdown by product line."},
]

INDEX = "tolap-kb"


def log(message: str) -> None:
    print(f"[provision] {message}", flush=True)


class State:
    """The teardown manifest, flushed to disk on every mutation."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.values: dict[str, str] = {}

    def set(self, key: str, value: str) -> None:
        self.values[key] = value
        self.flush()

    def flush(self) -> None:
        with open(self.path, "w") as handle:
            for key, value in self.values.items():
                handle.write(f"{key}={value}\n")

    @classmethod
    def load(cls, path: str) -> State:
        state = cls(path)
        with open(path) as handle:
            for line in handle:
                line = line.strip()
                if line and "=" in line:
                    key, value = line.split("=", 1)
                    state.values[key] = value
        return state


def _caller() -> tuple[str, str]:
    """The account id and the IAM *role* ARN of the current caller.

    ``get_caller_identity`` returns an assumed-role *session* ARN
    (``sts::<acct>:assumed-role/Admin/<session>``), which is not a valid policy principal. The
    role ARN it derives from (``iam::<acct>:role/Admin``) is.
    """
    identity = boto3.client("sts").get_caller_identity()
    account = identity["Account"]
    arn = identity["Arn"]
    if ":assumed-role/" in arn:
        role = arn.split(":assumed-role/")[1].split("/")[0]
        return account, f"arn:aws:iam::{account}:role/{role}"
    return account, arn


def _access_policy(region: str, domain: str) -> str:
    """Access policy naming this caller's role and this domain -- nothing wider.

    AWS refuses ``Principal: "*"`` outright ("Enable fine-grained access control or apply a
    restrictive access policy"), which is the correct refusal: an open policy on an
    internet-facing search domain is an unauthenticated read/write endpoint. The first draft of
    this script tried it and was rejected, so the guardrail is doing real work.

    Naming the role means every request has to be SigV4-signed, so :func:`_request` signs with
    the same credentials boto3 resolved. Fine-grained access control would add an internal user
    database and a master password to manage for a domain that holds four synthetic documents
    and lives under an hour; principal-scoping gets the same containment without the secret.
    """
    account, principal = _caller()
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": principal},
                    "Action": "es:*",
                    "Resource": f"arn:aws:es:{region}:{account}:domain/{domain}/*",
                }
            ],
        }
    )


def create_domain(client: Any, name: str, engine: str, region: str) -> None:
    log(f"creating {name} ({engine}) -- 15-25 minutes")
    client.create_domain(
        DomainName=name,
        EngineVersion=engine,
        ClusterConfig={
            "InstanceType": INSTANCE_TYPE,
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": VOLUME_SIZE_GIB},
        NodeToNodeEncryptionOptions={"Enabled": True},
        EncryptionAtRestOptions={"Enabled": True},
        DomainEndpointOptions={"EnforceHTTPS": True},
        AccessPolicies=_access_policy(region, name),
    )


def wait_for_endpoint(client: Any, name: str, timeout_s: int = 2400) -> str:
    """Blocks until the domain reports an endpoint and is no longer processing."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        status = client.describe_domain(DomainName=name)["DomainStatus"]
        endpoint = status.get("Endpoint") or status.get("Endpoints", {}).get("vpc")
        if endpoint and not status.get("Processing", True):
            log(f"{name} ready at {endpoint}")
            return endpoint
        time.sleep(30)
    raise TimeoutError(f"{name} did not become ready within {timeout_s}s")


def _request(method: str, url: str, body: Any = None, region: str = "us-east-1") -> Any:
    """Signed request to a domain endpoint.

    SigV4 rather than a password: the access policy names an IAM role, so an unsigned request is
    refused with 403. Signed with botocore's own signer, which is already present as a boto3
    dependency -- no new package for the test environment.
    """
    data = json.dumps(body).encode() if body is not None else None
    signed = AWSRequest(method=method, url=url, data=data, headers={"Content-Type": "application/json"})
    credentials = boto3.Session().get_credentials().get_frozen_credentials()
    SigV4Auth(credentials, "es", region).add_auth(signed)

    request = urllib.request.Request(url, data=data, method=method)
    for header, value in signed.headers.items():
        request.add_header(header, value)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc


def seed(endpoint: str, region: str) -> None:
    """Creates the index with an explicit mapping and indexes the corpus.

    ``classification`` is mapped as ``keyword``, not ``text``. That is the mapping a
    ``terms`` filter requires: a ``text`` field is analysed into tokens, so an exact-match
    ``terms`` clause silently matches nothing and every filter would look like it denied
    everything. Making the mapping explicit means the transcript is testing our filter rather
    than a dynamic-mapping accident.
    """
    base = f"https://{endpoint}"
    log(f"creating index {INDEX}")
    _request(
        "PUT",
        f"{base}/{INDEX}",
        {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "classification": {"type": "keyword"},
                    "text": {"type": "text"},
                }
            },
        },
        region=region,
    )
    for document in DOCUMENTS:
        _request("PUT", f"{base}/{INDEX}/_doc/{document['id']}", document, region=region)
    # Refresh so the documents are searchable immediately rather than after the 1s interval.
    _request("POST", f"{base}/{INDEX}/_refresh", region=region)
    count = _request("GET", f"{base}/{INDEX}/_count", region=region)["count"]
    if count != len(DOCUMENTS):
        raise RuntimeError(f"seeded {count} documents, expected {len(DOCUMENTS)}")
    log(f"seeded {count} documents")


def up(region: str, state_path: str, suffix: str) -> None:
    client = boto3.client("opensearch", region_name=region)
    state = State(state_path)
    state.set("REGION", region)

    names = {key: f"tolap-{key}-{suffix}" for key in ENGINES}

    # Record the names BEFORE creating anything: a domain that fails midway through creation
    # still exists and still bills, so the manifest has to cover it.
    for key, name in names.items():
        state.set(f"{key.upper()}_DOMAIN", name)

    for key, name in names.items():
        create_domain(client, name, ENGINES[key], region)

    # Both were requested before either wait, so the 15-25 minute creations overlap.
    for key, name in names.items():
        endpoint = wait_for_endpoint(client, name)
        state.set(f"{key.upper()}_ENDPOINT", endpoint)
        seed(endpoint, region)

    log("both domains ready")
    print(f"\nState written to {state_path}")
    for key, value in state.values.items():
        print(f"  {key}={value}")


def down(state_path: str) -> None:
    state = State.load(state_path)
    region = state.values.get("REGION", "us-east-1")
    client = boto3.client("opensearch", region_name=region)

    for key in ENGINES:
        name = state.values.get(f"{key.upper()}_DOMAIN")
        if not name:
            continue
        try:
            client.delete_domain(DomainName=name)
            log(f"deleted domain {name}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                log(f"domain {name} already gone")
            else:
                raise

    log("teardown requested; deletion completes asynchronously (~10 min)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["up", "down"])
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--state", help="where to write the teardown manifest (up)")
    parser.add_argument("--from", dest="from_state", help="manifest to tear down (down)")
    parser.add_argument("--suffix", help="domain name suffix; must be unique per run")
    args = parser.parse_args()

    if args.action == "up":
        if not args.state or not args.suffix:
            print("up requires --state and --suffix", file=sys.stderr)
            return 2
        up(args.region, args.state, args.suffix)
    else:
        if not args.from_state:
            print("down requires --from", file=sys.stderr)
            return 2
        down(args.from_state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
