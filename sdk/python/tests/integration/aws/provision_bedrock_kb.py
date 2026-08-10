#!/usr/bin/env python3
"""Provision (and tear down) a real Bedrock Knowledge Base for the end-to-end kb test.

A Knowledge Base is not a single resource: it needs a vector store (OpenSearch Serverless
collection + index), an IAM role the KB assumes, an S3 data source, and an ingestion job.
Standing this up takes minutes and costs money while it exists, so it is a deliberate,
explicit step rather than a per-test fixture:

    python provision_bedrock_kb.py up     > kb.env    # writes KB_ID / DATA_SOURCE_ID / ...
    TOLAP_TEST_KB_ID=... pytest test_bedrock_kb_e2e.py
    python provision_bedrock_kb.py down --from kb.env  # deletes everything it created

Everything created carries the same random suffix and is recorded, so `down` removes
exactly what `up` made and nothing else -- this account is shared. `up` is idempotent
enough to resume: each step checks for its resource before creating it.

Run under sandbox credentials, e.g. `AWS_REGION=us-east-1 \\
  python provision_bedrock_kb.py up`.

This is test infrastructure. It is not shipped, imports boto3 (a test-only dependency),
and none of it touches the SDK -- the SDK's job begins once the test has real chunks in
hand.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import uuid

import boto3
from botocore.exceptions import ClientError

EMBED_MODEL = "amazon.titan-embed-text-v2:0"
EMBED_DIM = 1024
VECTOR_FIELD = "tolap-vector"
TEXT_FIELD = "tolap-text"
METADATA_FIELD = "tolap-metadata"

# The corpus the e2e test asserts against. classification is the tag the policy filters on.
DOCUMENTS = [
    ("public-1.txt", "Quarterly revenue summary for the public shareholder report.", "public"),
    ("public-2.txt", "Press release describing the new product launch.", "public"),
    ("secret-1.txt", "Unannounced acquisition target and deal terms.", "secret"),
    ("secret-2.txt", "Internal pre-earnings financial projections.", "secret"),
]


def _log(msg: str) -> None:
    print(f"[provision] {msg}", file=sys.stderr, flush=True)


def _stack(region: str):
    return {
        "s3": boto3.client("s3", region_name=region),
        "iam": boto3.client("iam", region_name=region),
        "aoss": boto3.client("opensearchserverless", region_name=region),
        "agent": boto3.client("bedrock-agent", region_name=region),
        "sts": boto3.client("sts", region_name=region),
    }


def up(region: str, state_path: str | None = None) -> dict:
    c = _stack(region)
    acct = c["sts"].get_caller_identity()["Account"]
    suffix = uuid.uuid4().hex[:10]
    name = f"tolap-kb-{suffix}"
    env: dict[str, str] = {"REGION": region, "SUFFIX": suffix, "NAME": name}

    # Persist state to disk as each resource is created, not only on success. The first
    # run of this script crashed at ingestion and lost every id because they were printed
    # only at the end, turning a one-line fix into a hunt-and-delete. A resource whose id
    # is written the instant it exists can always be torn down, even mid-failure.
    def _save() -> None:
        if state_path:
            with open(state_path, "w") as fh:
                for k, v in env.items():
                    fh.write(f"{k}={v}\n")

    _save()

    bucket = f"tolap-kb-src-{suffix}"
    _log(f"S3 source bucket {bucket}")
    c["s3"].create_bucket(Bucket=bucket)
    env["BUCKET"] = bucket
    _save()
    for key, text, classification in DOCUMENTS:
        c["s3"].put_object(Bucket=bucket, Key=key, Body=text.encode())
        # Bedrock reads per-document metadata from a sidecar <key>.metadata.json.
        meta = {"metadataAttributes": {"classification": classification}}
        c["s3"].put_object(Bucket=bucket, Key=f"{key}.metadata.json", Body=json.dumps(meta).encode())

    coll_name = f"tolap-{suffix}"  # AOSS collection names are <=32 chars, lowercase.
    _log(f"OpenSearch Serverless collection {coll_name} (+ encryption/network/access policies)")
    _aoss_policies(c["aoss"], coll_name, acct, region, env)
    coll = c["aoss"].create_collection(name=coll_name, type="VECTORSEARCH")["createCollectionDetail"]
    env["COLLECTION_ID"] = coll["id"]
    env["COLLECTION_ARN"] = coll["arn"]
    _save()
    endpoint = _wait_collection_active(c["aoss"], coll_name)
    env["COLLECTION_ENDPOINT"] = endpoint
    _save()

    role_arn = _kb_role(c["iam"], suffix, acct, region, bucket, env["COLLECTION_ARN"], env)
    _save()

    _log("vector index")
    _create_index(endpoint, region)
    # The index and the data-access policy need a moment to be consistent everywhere.
    time.sleep(30)

    _log("knowledge base")
    kb_id = _create_kb(c["agent"], name, role_arn, env["COLLECTION_ARN"], region, acct)
    env["KB_ID"] = kb_id
    _save()
    # The KB reports CREATING for a while after create returns; StartIngestionJob rejects a
    # KB that is not yet ACTIVE. This wait is the fix for the first run's crash.
    _wait_kb_active(c["agent"], kb_id)

    _log("data source + ingestion")
    ds_id = _create_data_source(c["agent"], kb_id, bucket)
    env["DATA_SOURCE_ID"] = ds_id
    _save()
    job = c["agent"].start_ingestion_job(knowledgeBaseId=kb_id, dataSourceId=ds_id)["ingestionJob"]
    _wait_ingestion(c["agent"], kb_id, ds_id, job["ingestionJobId"])

    _log("KB is ready")
    _save()
    return env


def _wait_kb_active(agent, kb_id: str) -> None:
    for _ in range(60):
        kb = agent.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]
        status = kb["status"]
        if status == "ACTIVE":
            return
        if status in ("FAILED", "DELETE_UNSUCCESSFUL"):
            raise RuntimeError(f"knowledge base entered {status}: {kb.get('failureReasons')}")
        time.sleep(10)
    raise TimeoutError("knowledge base did not become ACTIVE")


def _aoss_policies(aoss, coll_name, acct, region, env) -> None:
    enc = {
        "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{coll_name}"]}],
        "AWSOwnedKey": True,
    }
    aoss.create_security_policy(name=f"{coll_name}-enc", type="encryption", policy=json.dumps(enc))
    net = [{
        "Rules": [
            {"ResourceType": "collection", "Resource": [f"collection/{coll_name}"]},
            {"ResourceType": "dashboard", "Resource": [f"collection/{coll_name}"]},
        ],
        "AllowFromPublic": True,
    }]
    aoss.create_security_policy(name=f"{coll_name}-net", type="network", policy=json.dumps(net))
    env["ENC_POLICY"] = f"{coll_name}-enc"
    env["NET_POLICY"] = f"{coll_name}-net"


def _kb_role(iam, suffix, acct, region, bucket, coll_arn, env) -> str:
    role_name = f"tolap-kb-role-{suffix}"
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "bedrock.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    env["ROLE_NAME"] = role_name
    env["ROLE_ARN"] = role["Role"]["Arn"]
    perms = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["bedrock:InvokeModel"],
             "Resource": [f"arn:aws:bedrock:{region}::foundation-model/{EMBED_MODEL}"]},
            {"Effect": "Allow", "Action": ["aoss:APIAccessAll"], "Resource": [coll_arn]},
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
             "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"]},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="kb-access", PolicyDocument=json.dumps(perms))

    # The KB role must also be an AOSS data-access principal.
    aoss = boto3.client("opensearchserverless", region_name=region)
    coll_name = env["NAME"].replace("tolap-kb-", "tolap-")[:32]
    caller = boto3.client("sts", region_name=region).get_caller_identity()["Arn"]
    access = [{
        "Rules": [
            {"ResourceType": "index", "Resource": [f"index/{coll_name}/*"],
             "Permission": ["aoss:*"]},
            {"ResourceType": "collection", "Resource": [f"collection/{coll_name}"],
             "Permission": ["aoss:*"]},
        ],
        "Principal": [env["ROLE_ARN"], caller],
    }]
    aoss.create_access_policy(name=f"{coll_name}-acc", type="data", policy=json.dumps(access))
    env["ACCESS_POLICY"] = f"{coll_name}-acc"
    _log("waiting for IAM role propagation")
    time.sleep(15)
    return env["ROLE_ARN"]


def _wait_collection_active(aoss, coll_name: str) -> str:
    for _ in range(60):
        detail = aoss.batch_get_collection(names=[coll_name])["collectionDetails"]
        if detail and detail[0]["status"] == "ACTIVE":
            return detail[0]["collectionEndpoint"]
        if detail and detail[0]["status"] == "FAILED":
            raise RuntimeError("collection creation FAILED")
        time.sleep(10)
    raise TimeoutError("collection did not become ACTIVE")


def _create_index(endpoint: str, region: str) -> None:
    # Signed request straight to the collection's OpenSearch endpoint.
    from opensearchpy import OpenSearch, RequestsHttpConnection, AWSV4SignerAuth

    host = endpoint.replace("https://", "")
    creds = boto3.Session().get_credentials()
    client = OpenSearch(
        hosts=[{"host": host, "port": 443}],
        http_auth=AWSV4SignerAuth(creds, region, "aoss"),
        use_ssl=True, verify_certs=True, connection_class=RequestsHttpConnection,
    )
    body = {
        "settings": {"index": {"knn": True}},
        "mappings": {"properties": {
            VECTOR_FIELD: {"type": "knn_vector", "dimension": EMBED_DIM,
                           "method": {"name": "hnsw", "engine": "faiss", "space_type": "l2"}},
            TEXT_FIELD: {"type": "text"},
            METADATA_FIELD: {"type": "text"},
        }},
    }
    for attempt in range(10):
        try:
            client.indices.create(index="tolap-index", body=body)
            return
        except Exception as exc:  # index-exists or not-yet-authorized
            if "resource_already_exists" in str(exc):
                return
            _log(f"index create retry {attempt}: {exc}")
            time.sleep(15)
    raise RuntimeError("could not create the vector index")


def _create_kb(agent, name, role_arn, coll_arn, region, acct) -> str:
    resp = agent.create_knowledge_base(
        name=name, roleArn=role_arn,
        knowledgeBaseConfiguration={
            "type": "VECTOR",
            "vectorKnowledgeBaseConfiguration": {
                "embeddingModelArn": f"arn:aws:bedrock:{region}::foundation-model/{EMBED_MODEL}",
            },
        },
        storageConfiguration={
            "type": "OPENSEARCH_SERVERLESS",
            "opensearchServerlessConfiguration": {
                "collectionArn": coll_arn,
                "vectorIndexName": "tolap-index",
                "fieldMapping": {"vectorField": VECTOR_FIELD, "textField": TEXT_FIELD,
                                 "metadataField": METADATA_FIELD},
            },
        },
    )
    return resp["knowledgeBase"]["knowledgeBaseId"]


def _create_data_source(agent, kb_id, bucket) -> str:
    resp = agent.create_data_source(
        knowledgeBaseId=kb_id, name="s3-source",
        dataSourceConfiguration={"type": "S3",
                                 "s3Configuration": {"bucketArn": f"arn:aws:s3:::{bucket}"}},
    )
    return resp["dataSource"]["dataSourceId"]


def _wait_ingestion(agent, kb_id, ds_id, job_id) -> None:
    for _ in range(60):
        job = agent.get_ingestion_job(knowledgeBaseId=kb_id, dataSourceId=ds_id,
                                      ingestionJobId=job_id)["ingestionJob"]
        status = job["status"]
        if status == "COMPLETE":
            return
        if status == "FAILED":
            raise RuntimeError(f"ingestion FAILED: {job.get('failureReasons')}")
        time.sleep(10)
    raise TimeoutError("ingestion did not complete")


def down(env: dict) -> None:
    region = env["REGION"]
    c = _stack(region)

    def _try(label, fn):
        try:
            fn()
            _log(f"deleted {label}")
        except ClientError as exc:
            _log(f"skip {label}: {exc.response['Error']['Code']}")

    if env.get("KB_ID"):
        _try("knowledge base", lambda: c["agent"].delete_knowledge_base(knowledgeBaseId=env["KB_ID"]))
        time.sleep(10)
    if env.get("COLLECTION_ID"):
        coll_name = env["NAME"].replace("tolap-kb-", "tolap-")[:32]
        _try("collection", lambda: c["aoss"].delete_collection(id=env["COLLECTION_ID"]))
        for key in ("ACCESS_POLICY", "NET_POLICY", "ENC_POLICY"):
            if env.get(key):
                ptype = {"ACCESS_POLICY": "data", "NET_POLICY": "network", "ENC_POLICY": "encryption"}[key]
                _try(f"{key}", lambda n=env[key], t=ptype: c["aoss"].delete_security_policy(name=n, type=t)
                     if t != "data" else c["aoss"].delete_access_policy(name=n, type=t))
    if env.get("ROLE_NAME"):
        _try("role policy", lambda: c["iam"].delete_role_policy(RoleName=env["ROLE_NAME"], PolicyName="kb-access"))
        _try("role", lambda: c["iam"].delete_role(RoleName=env["ROLE_NAME"]))
    if env.get("BUCKET"):
        _try("bucket objects + bucket", lambda: _empty_and_delete(c["s3"], env["BUCKET"]))


def _empty_and_delete(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents") or []
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=bucket)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["up", "down"])
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--from", dest="env_file", help="env file written by `up`, for `down`")
    ap.add_argument("--state", dest="state_path",
                    help="write resource ids here as they are created, so a mid-run "
                         "failure can still be torn down with `down --from <state>`")
    args = ap.parse_args()

    if args.action == "up":
        try:
            env = up(args.region, state_path=args.state_path)
        except Exception:
            # The state file already holds every id created before the failure. Surface
            # where it is so cleanup is one command, not a hunt.
            if args.state_path:
                _log(f"provisioning failed; tear down with: {sys.argv[0]} down --from {args.state_path}")
            raise
        # stdout is the machine-readable env; logs go to stderr.
        for k, v in env.items():
            print(f"{k}={v}")
        return 0

    if not args.env_file:
        _log("down needs --from <env file>")
        return 2
    env = {}
    with open(args.env_file) as fh:
        for line in fh:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k] = v
    down(env)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
