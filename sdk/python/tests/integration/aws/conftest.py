"""Fixtures for the AWS-backed integration tests.

These tests run against **real AWS**, so they are opt-in and default to skipping:
set ``TOLAP_TEST_AWS=1``. They are never run in CI on a pull request — a public
repository must not expose credentials to a fork-triggered workflow.

Two constraints shape everything here.

**boto3 is a test-only dependency.** No shipped package declares an AWS SDK, and none
should: TOLAP never holds a connection. The wrapper is handed records that the *caller*
retrieved, so the AWS call belongs in the test, not behind the enforcement API. Adding
boto3 to a package's dependencies to make a test convenient would trade away the
zero-runtime-dependency property for nothing.

**Resources are created, never reused.** Every fixture makes a uniquely-suffixed bucket
and deletes only what it created. The account these run in is shared and contains real
data (CloudTrail logs, CDK assets); a test that adopted an existing bucket, or cleaned up
by prefix, could delete someone's work. Teardown is unconditional so a failing assertion
does not leak a bucket.
"""

from __future__ import annotations

import os
import pathlib
import uuid
from typing import Iterator

import pytest

_HERE = pathlib.Path(__file__).parent

#: Set to ``1`` to opt in to the AWS-backed tests.
AWS_ENABLED = os.environ.get("TOLAP_TEST_AWS") == "1"

_OPT_IN_REASON = "AWS integration tests are opt-in; set TOLAP_TEST_AWS=1"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip every test in this package unless ``TOLAP_TEST_AWS=1``.

    A collection hook, **not** a module-level ``pytestmark``. Assigning ``pytestmark`` in a
    ``conftest.py`` looks like it gates the whole package but does nothing: pytest only reads
    that name from test *modules*. The gate silently did not exist, so a developer with no
    credentials saw 35 errors and 3 failures from a suite that is meant to skip -- and a
    contributor could reasonably have concluded the AWS tests were broken and deleted them.

    Applied per collected item so it covers every module in the package including ones added
    later, which is the property the ``pytestmark`` spelling only appeared to have. Guarded by
    :func:`test_the_opt_in_gate_is_applied` below.
    """
    if AWS_ENABLED:
        return
    skip = pytest.mark.skip(reason=_OPT_IN_REASON)
    for item in items:
        if _HERE in item.path.parents:
            item.add_marker(skip)


def _require_boto3():
    boto3 = pytest.importorskip("boto3", reason="boto3 is required for the AWS tests")
    return boto3


@pytest.fixture(scope="session")
def aws_region() -> str:
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"


@pytest.fixture(scope="session")
def s3_client(aws_region: str):
    """A plain S3 client. Fails loudly if credentials are absent.

    Deliberately not wrapped in a try/except that skips: once TOLAP_TEST_AWS=1 has been
    set, missing credentials are a setup error the runner needs to see, not a reason to
    silently report success. That is the same distinction the local test-API fixtures
    make between an absent dependency and a broken one.
    """
    boto3 = _require_boto3()
    from botocore.exceptions import NoCredentialsError

    client = boto3.client("s3", region_name=aws_region)
    try:
        client.list_buckets()
    except NoCredentialsError as exc:  # pragma: no cover - setup failure
        raise RuntimeError(
            "TOLAP_TEST_AWS=1 but no AWS credentials are available. "
            "Assume a role first (e.g. isengardcli assume <account>)."
        ) from exc
    return client


@pytest.fixture(scope="session")
def seeded_bucket(s3_client, aws_region: str) -> Iterator[str]:
    """A bucket seeded with the shared storage corpus, deleted afterwards.

    The key layout mirrors connector-spec §8's worked example so the prefix-glob
    behaviour under test is the documented one:

        exports/public/a.csv            allowed by  exports/public/*
        exports/public/sub/deep.csv     allowed too -- prefixes descend arbitrarily
        exports/private/secret.csv      denied
        exports/public                  the bare prefix, which is NOT granted

    Two objects carry S3 object tags, which is the interesting part: ListObjectsV2 does
    not return tags, so a listing alone cannot satisfy an allowedTags policy. The tests
    assert that consequence rather than working around it.
    """
    bucket = f"tolap-test-{uuid.uuid4().hex[:12]}"

    if aws_region == "us-east-1":
        # us-east-1 rejects an explicit LocationConstraint.
        s3_client.create_bucket(Bucket=bucket)
    else:
        s3_client.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": aws_region},
        )

    try:
        # (body, tagging, user-metadata). The user metadata carries fields the
        # field-rule and masking controls act on -- S3 returns it on HeadObject/GetObject
        # as the record's "metadata keys" (§8 maps Field -> a metadata key). Sizes are
        # chosen so maxObjectSizeBytes has both a survivor and a casualty.
        objects = {
            "exports/public/a.csv": (
                b"id,region\n1,us-east\n",
                None,
                {"owner": "analytics", "ssn": "000-11-2222"},
            ),
            "exports/public/sub/deep.csv": (b"id,region\n2,us-west\n", None, {}),
            "exports/private/secret.csv": (b"id,ssn\n3,000-00-0000\n", None, {}),
            "exports/public/tagged-public.csv": (b"id\n4\n", "classification=public", {}),
            "exports/public/tagged-secret.csv": (b"id\n5\n", "classification=secret", {}),
            # ~2 KiB: over a 1 KiB ceiling, under a generous one.
            "exports/public/large.csv": (b"x" * 2048, None, {}),
        }
        for key, (body, tagging, metadata) in objects.items():
            kwargs = {"Bucket": bucket, "Key": key, "Body": body}
            if tagging is not None:
                kwargs["Tagging"] = tagging
            if metadata:
                kwargs["Metadata"] = metadata
            s3_client.put_object(**kwargs)

        yield bucket
    finally:
        # Unconditional, and scoped to this bucket only -- never a prefix sweep across
        # the account, which is shared and holds real data.
        _delete_bucket(s3_client, bucket)


def _delete_bucket(s3_client, bucket: str) -> None:
    """Empty and remove a bucket this test session created."""
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        contents = page.get("Contents") or []
        if contents:
            s3_client.delete_objects(
                Bucket=bucket,
                Delete={"Objects": [{"Key": o["Key"]} for o in contents]},
            )
    s3_client.delete_bucket(Bucket=bucket)


@pytest.fixture
def call_recorder(s3_client):
    """Records every S3 API call the client makes, for asserting a call did NOT happen.

    connector-spec §8 requires the caller's requested prefix to be validated *before* the
    provider call, "not only after -- otherwise an unauthorized list is issued and merely
    filtered on return, which is slower and records the request in the provider's audit
    log as though it were authorized."

    That requirement is about a call's *absence*, which post-hoc result filtering cannot
    demonstrate: a wrapper that lists everything and then discards the denied rows returns
    the same data as one that never asked. Counting botocore events is the cheap way to
    tell those two apart. CloudTrail would be the authoritative check and is what an
    auditor would look at, but it lags by minutes and would make the suite slow and flaky
    for no extra signal here.
    """
    calls: list[tuple[str, dict]] = []

    def _record(**kwargs):
        # `before-call.s3.<Operation>` fires once per real API call, after params are
        # built and before the request goes out. The operation name is on the `model`;
        # taking everything via **kwargs keeps this robust to botocore's handler
        # signature rather than pinning positional names that differ per event.
        model = kwargs.get("model")
        operation = getattr(model, "name", None) if model is not None else None
        calls.append((operation, kwargs.get("params")))

    s3_client.meta.events.register("before-call.s3.*", _record)
    try:
        yield calls
    finally:
        s3_client.meta.events.unregister("before-call.s3.*", _record)


def test_the_opt_in_gate_is_applied(request: pytest.FixtureRequest) -> None:
    """The opt-in gate exists and reaches this package's tests.

    The gate above replaced a module-level ``pytestmark`` in this same file, which pytest
    ignores in a ``conftest.py`` -- so the suite was fully unguarded while reading as guarded.
    Nothing failed to catch that, because a missing skip has no symptom on a machine that
    happens to have credentials.

    This test is the symptom. It runs in both modes and asserts the two things that can break
    independently: with the variable unset every item here carries the skip mark (and so this
    test never executes, which is itself the signal), and with it set the gate stands down
    instead of skipping a suite the runner asked for.
    """
    if not AWS_ENABLED:  # pragma: no cover - unreachable: the gate skips this test too
        raise AssertionError(
            "reached with TOLAP_TEST_AWS unset, so pytest_collection_modifyitems did not "
            "apply the skip mark to this package -- the opt-in gate is not working"
        )

    own_marks = [m for m in request.node.iter_markers("skip") if m.kwargs.get("reason") == _OPT_IN_REASON]
    assert not own_marks, "the gate skipped a suite that TOLAP_TEST_AWS=1 explicitly opted in to"
    assert _HERE.name == "aws", "the gate matches on this directory; renaming it silently disables it"
