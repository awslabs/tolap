"""`storage` enforcement against real S3 (connector-spec §8).

Until now the `storage` category had **no** integration test in any SDK: `db` runs against
real Postgres and MySQL, `api` against a real socket, but every storage assertion was made
against hand-built dictionaries. Two of §8's requirements cannot be checked that way, and
they are what this file exists for.

**1. A denied prefix must never reach the provider.** §8: "The caller's requested prefix
MUST be validated before the provider call, not only after -- otherwise an unauthorized
`list` is issued and merely filtered on return, which is slower and records the request in
the provider's audit log as though it were authorized." That is an assertion about a call's
*absence*, and no fixture can make it: a wrapper that lists everything and discards the
denied rows returns exactly what one that never asked returns. Only counting real API calls
separates them.

**2. `tagRules` on a listing.** `ListObjectsV2` does not return object tags -- they need a
separate `GetObjectTagging` per key. That was documented in §8 from reading the filter
code; here it is checked against the service, because an inference about a provider's
behaviour deserves to be confirmed by the provider.

Every denial test has a paired control proving the same operation succeeds when the policy
permits it. Without the control, a client that returns nothing at all passes every denial
test in the file.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tolap_core.enforcement import (
    apply_result_pipeline,
    filter_by_tags,
    validate_access,
    validate_write,
)
from tolap_core.enums import WriteOperation
from tolap_core.models import (
    EffectivePolicy,
    FieldRules,
    MaskingRule,
    ObjectRules,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
    TagRules,
)
from tolap_core.enums import FilterOperator, MaskType


def _policy(
    *,
    can_query: bool = True,
    can_insert: bool | None = None,
    can_update: bool | None = None,
    can_delete: bool | None = None,
    read_only: bool | None = None,
    allowed_objects: list[str] | None = None,
    hidden_objects: list[str] | None = None,
    field_rules: FieldRules | None = None,
    row_filters: list[RowFilter] | None = None,
    tag_rules: TagRules | None = None,
    limits: PolicyLimits | None = None,
) -> EffectivePolicy:
    now = datetime.now(timezone.utc)
    return EffectivePolicy(
        version="1.0",
        user_id="s3-user",
        tenant_id="s3-tenant",
        source_connection_id="storage:archive:exports",
        resolved_at=now,
        expires_at=now + timedelta(hours=1),
        source_profiles=["s3-storage-test"],
        permissions=PolicyPermissions(
            can_query=can_query,
            can_insert=can_insert,
            can_update=can_update,
            can_delete=can_delete,
            read_only=read_only,
        ),
        object_rules=ObjectRules(
            allowed_objects=allowed_objects,
            hidden_objects=hidden_objects,
            field_rules=field_rules,
            row_filters=row_filters,
            tag_rules=tag_rules,
        ),
        limits=limits,
    )


def _listing_records(s3_client, bucket: str, prefix: str) -> list[dict]:
    """Turn an S3 listing into the record shape the enforcement pipeline consumes.

    Each object contributes its key, size, and user metadata (from HeadObject), because
    §8 maps a storage 'Field' to a metadata key and a 'Record' to one listing entry or
    one object's metadata. This is the enrichment §8 says a wrapper must do -- the tests
    below then run the SHIPPED pipeline over these records, so they exercise the SDK
    rather than reimplementing it.
    """
    records = []
    for obj in s3_client.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", []):
        head = s3_client.head_object(Bucket=bucket, Key=obj["Key"])
        record = {
            "key": obj["Key"],
            "sizeBytes": obj["Size"],
            **head.get("Metadata", {}),
        }
        records.append(record)
    return records


def _list_with_enforcement(s3_client, bucket: str, prefix: str, policy) -> list[dict]:
    """List a prefix the way a compliant storage wrapper must: validate, then call.

    The ordering is the whole point -- validate_access runs BEFORE list_objects_v2, so a
    denied prefix issues no request at all. Returning early rather than filtering after is
    what §8 requires, and the call_recorder tests below prove this function honours it.
    """
    decision = validate_access(prefix, policy)
    if not decision.allowed:
        return []

    response = s3_client.list_objects_v2(Bucket=bucket, Prefix=prefix)
    return [{"Key": o["Key"], "Size": o["Size"]} for o in response.get("Contents", [])]


# ---------------------------------------------------------------------------
# §8: the requested prefix is validated BEFORE the provider call
# ---------------------------------------------------------------------------


class TestDeniedPrefixNeverReachesS3:
    def test_denied_prefix_issues_no_list_call(self, s3_client, seeded_bucket, call_recorder):
        # The requirement post-hoc filtering cannot satisfy. If this fails, an
        # unauthorized listing is being recorded in CloudTrail as though it were allowed.
        policy = _policy(allowed_objects=["exports/public/*"])

        results = _list_with_enforcement(
            s3_client, seeded_bucket, "exports/private/", policy
        )

        assert results == []
        list_calls = [op for op, _ in call_recorder if op == "ListObjectsV2"]
        assert list_calls == [], (
            "a denied prefix reached S3; §8 requires validation before the call so the "
            "request is never recorded as authorized"
        )

    def test_control_permitted_prefix_does_issue_a_list_call(
        self, s3_client, seeded_bucket, call_recorder
    ):
        # The paired control. Without it, a wrapper that returns nothing for every prefix
        # would satisfy the test above while being entirely broken.
        policy = _policy(allowed_objects=["exports/public/*"])

        results = _list_with_enforcement(
            s3_client, seeded_bucket, "exports/public/", policy
        )

        assert [op for op, _ in call_recorder if op == "ListObjectsV2"], (
            "the permitted prefix issued no call, so the denial test above proves nothing"
        )
        keys = {r["Key"] for r in results}
        assert "exports/public/a.csv" in keys
        assert "exports/private/secret.csv" not in keys

    def test_hidden_prefix_also_issues_no_call(self, s3_client, seeded_bucket, call_recorder):
        # hiddenObjects takes precedence over allowedObjects (§3), and the precedence has
        # to be applied before the call too -- otherwise hidden data is fetched and then
        # discarded, which is the same audit-log problem.
        policy = _policy(
            allowed_objects=["exports/*"], hidden_objects=["exports/private/*"]
        )

        results = _list_with_enforcement(
            s3_client, seeded_bucket, "exports/private/", policy
        )

        assert results == []
        assert [op for op, _ in call_recorder if op == "ListObjectsV2"] == []


# ---------------------------------------------------------------------------
# §3.1 prefix globs, against real keys
# ---------------------------------------------------------------------------


class TestPrefixGlobsAgainstRealKeys:
    def test_prefix_glob_descends_arbitrarily(self, s3_client, seeded_bucket):
        # §3.1's worked example, now against keys S3 actually returned rather than a
        # hand-written list: exports/public/* reaches exports/public/sub/deep.csv.
        policy = _policy(allowed_objects=["exports/public/*"])

        keys = {
            r["Key"]
            for r in _list_with_enforcement(s3_client, seeded_bucket, "exports/public/", policy)
        }

        assert "exports/public/sub/deep.csv" in keys

    def test_bare_prefix_is_not_granted_by_its_own_glob(self, s3_client, seeded_bucket):
        # The boundary that makes "descends arbitrarily" safe to state: exports/public/*
        # does NOT grant the bare `exports/public`. Asserted on the real path string so a
        # glob change cannot quietly widen it.
        policy = _policy(allowed_objects=["exports/public/*"])

        assert validate_access("exports/public", policy).allowed is False
        assert validate_access("exports/public/a.csv", policy).allowed is True

    def test_every_returned_key_satisfies_the_policy(self, s3_client, seeded_bucket):
        # A whole-listing sweep: enumerate the bucket unfiltered, then assert the policy's
        # own decision agrees with the wrapper's for every real key. Catches a glob that
        # behaves differently on a key shape the corpus did not anticipate.
        policy = _policy(allowed_objects=["exports/public/*"])
        everything = s3_client.list_objects_v2(Bucket=seeded_bucket).get("Contents", [])
        assert everything, "the bucket seeded no objects; the sweep would be vacuous"

        for obj in everything:
            key = obj["Key"]
            expected = key.startswith("exports/public/")
            assert validate_access(key, policy).allowed is expected, key


# ---------------------------------------------------------------------------
# tagRules on a listing -- confirming §8's documented consequence
# ---------------------------------------------------------------------------


class TestTagRulesOnAListing:
    def test_list_objects_returns_no_tags(self, s3_client, seeded_bucket):
        # The premise §8's warning rests on, checked against the service rather than
        # assumed. Two seeded objects carry classification tags; the listing shows none.
        contents = s3_client.list_objects_v2(
            Bucket=seeded_bucket, Prefix="exports/public/"
        ).get("Contents", [])

        assert contents
        for obj in contents:
            assert "Tagging" not in obj
            assert "tags" not in obj
            assert "classification" not in obj

    def test_tags_are_only_available_via_get_object_tagging(self, s3_client, seeded_bucket):
        # And they really are retrievable -- so the gap is the listing API, not the seed.
        tagging = s3_client.get_object_tagging(
            Bucket=seeded_bucket, Key="exports/public/tagged-secret.csv"
        )
        tags = {t["Key"]: t["Value"] for t in tagging["TagSet"]}

        assert tags == {"classification": "secret"}

    def test_allowed_tags_over_a_bare_listing_drops_everything(
        self, s3_client, seeded_bucket
    ):
        # The hazard §8 now documents, demonstrated end to end. Every entry is untagged as
        # far as the pipeline can see, and an allowlist drops what it cannot prove is
        # permitted -- so the result is empty even though a permitted object exists.
        # Fail-closed, and useless: an implementation must enrich entries before filtering.
        policy = _policy(tag_rules=TagRules(allowed_tags=["public"]))
        entries = [
            {"Key": o["Key"], "Size": o["Size"]}
            for o in s3_client.list_objects_v2(
                Bucket=seeded_bucket, Prefix="exports/public/"
            ).get("Contents", [])
        ]
        assert entries

        assert filter_by_tags(entries, policy) == []

    def test_enriching_entries_with_tags_makes_the_allowlist_work(
        self, s3_client, seeded_bucket
    ):
        # The paired control, and the remedy §8 prescribes. With tags fetched per key the
        # same policy behaves as an author expects: the public object survives, the secret
        # one does not.
        policy = _policy(tag_rules=TagRules(allowed_tags=["public"]))
        entries = []
        for obj in s3_client.list_objects_v2(
            Bucket=seeded_bucket, Prefix="exports/public/"
        ).get("Contents", []):
            tagging = s3_client.get_object_tagging(Bucket=seeded_bucket, Key=obj["Key"])
            entry = {"Key": obj["Key"], "Size": obj["Size"]}
            values = [t["Value"] for t in tagging["TagSet"]]
            if values:
                entry["tags"] = values
            entries.append(entry)

        surviving = {e["Key"] for e in filter_by_tags(entries, policy)}

        assert "exports/public/tagged-public.csv" in surviving
        assert "exports/public/tagged-secret.csv" not in surviving

    def test_denylist_keeps_untagged_entries(self, s3_client, seeded_bucket):
        # The other half of the asymmetry, and the reason it is not simply a bug: a pure
        # denylist keeps an untagged entry, because it matches no denied tag. Dropping it
        # would enforce a restriction the policy never stated.
        policy = _policy(tag_rules=TagRules(denied_tags=["secret"]))
        entries = [
            {"Key": o["Key"], "Size": o["Size"]}
            for o in s3_client.list_objects_v2(
                Bucket=seeded_bucket, Prefix="exports/public/"
            ).get("Contents", [])
        ]

        surviving = {e["Key"] for e in filter_by_tags(entries, policy)}

        assert "exports/public/a.csv" in surviving
        assert len(surviving) == len(entries)


# ---------------------------------------------------------------------------
# Write path: canInsert / canUpdate / canDelete / readOnly (§4, §8)
# ---------------------------------------------------------------------------


class TestWritePath:
    def test_readonly_policy_denies_a_put_before_it_is_issued(self, s3_client, seeded_bucket, call_recorder):
        # §8 maps a PUT to canInsert/canUpdate; a read-only policy is a ceiling that denies
        # every write regardless. As with reads, the denial must precede the call: a
        # rejected PutObject that still hit S3 would have written the object.
        policy = _policy(read_only=True, allowed_objects=["exports/*"])

        decision = validate_write(WriteOperation.insert, "exports/public/new.csv", {"id": "9"}, policy)

        assert decision.allowed is False
        if decision.allowed:  # pragma: no cover - only runs on a broken decision
            s3_client.put_object(Bucket=seeded_bucket, Key="exports/public/new.csv", Body=b"x")
        assert [op for op, _ in call_recorder if op == "PutObject"] == []

    def test_control_permitted_insert_writes_and_reads_back(self, s3_client, seeded_bucket):
        # The paired control: with canInsert the same write is allowed and the object
        # really lands. Cleaned up so the shared bucket teardown is not the only guard.
        policy = _policy(read_only=False, can_insert=True, allowed_objects=["exports/*"])
        key = "exports/public/inserted.csv"

        assert validate_write(WriteOperation.insert, key, {"id": "9"}, policy).allowed is True
        s3_client.put_object(Bucket=seeded_bucket, Key=key, Body=b"id\n9\n")
        try:
            assert s3_client.get_object(Bucket=seeded_bucket, Key=key)["Body"].read() == b"id\n9\n"
        finally:
            s3_client.delete_object(Bucket=seeded_bucket, Key=key)

    def test_insert_denied_when_only_update_is_granted(self, s3_client, seeded_bucket):
        # canInsert and canUpdate are distinct: a policy granting only update must not
        # permit creating a new key. §8's "require both for an unconditional PUT" is the
        # integrator's concern; the SDK's job is to answer each operation truthfully.
        policy = _policy(read_only=False, can_update=True, allowed_objects=["exports/*"])

        assert validate_write(WriteOperation.insert, "exports/public/x.csv", {"id": "1"}, policy).allowed is False
        assert validate_write(WriteOperation.update, "exports/public/a.csv", {"id": "1"}, policy).allowed is True

    def test_delete_requires_can_delete(self, s3_client, seeded_bucket):
        policy = _policy(read_only=False, can_insert=True, allowed_objects=["exports/*"])

        # Insert granted, delete not -> delete denied.
        assert validate_write(WriteOperation.delete, "exports/public/a.csv", None, policy).allowed is False

    def test_write_to_denied_prefix_is_refused(self, s3_client, seeded_bucket):
        # allowedObjects governs the write target too, not only reads.
        policy = _policy(read_only=False, can_insert=True, allowed_objects=["exports/public/*"])

        assert validate_write(WriteOperation.insert, "exports/private/x.csv", {"id": "1"}, policy).allowed is False


# ---------------------------------------------------------------------------
# readOnlyFields on a write payload (§4.3)
# ---------------------------------------------------------------------------


class TestReadOnlyFieldsOnWrite:
    def test_writing_a_read_only_metadata_field_is_refused(self, s3_client, seeded_bucket):
        # readOnlyFields names metadata readable but not writable. A PUT whose metadata
        # payload sets one must be refused whole (§4.4: reject, never silently drop).
        policy = _policy(
            read_only=False,
            can_update=True,
            allowed_objects=["exports/*"],
            field_rules=FieldRules(read_only_fields=["owner"]),
        )

        denied = validate_write(
            WriteOperation.update, "exports/public/a.csv", {"owner": "attacker", "note": "ok"}, policy
        )
        allowed = validate_write(
            WriteOperation.update, "exports/public/a.csv", {"note": "ok"}, policy
        )

        assert denied.allowed is False
        assert allowed.allowed is True


# ---------------------------------------------------------------------------
# The full post-execution pipeline over real object metadata (§4, §8)
# ---------------------------------------------------------------------------


class TestPostExecutionPipelineOverRealMetadata:
    def test_hidden_metadata_field_is_removed(self, s3_client, seeded_bucket):
        # a.csv carries user metadata {owner, ssn}. hiddenFields must strip ssn from the
        # record the agent sees, exactly as it would a hidden column.
        records = _listing_records(s3_client, seeded_bucket, "exports/public/a.csv")
        assert records and "ssn" in records[0], "seed regressed: expected an ssn metadata key"

        policy = _policy(field_rules=FieldRules(hidden_fields=["ssn"]))
        out = apply_result_pipeline(records, policy)

        assert all("ssn" not in r for r in out)
        assert all("key" in r for r in out), "non-hidden fields must survive"

    def test_masked_metadata_field_is_masked(self, s3_client, seeded_bucket):
        records = _listing_records(s3_client, seeded_bucket, "exports/public/a.csv")
        original = next(r["ssn"] for r in records if "ssn" in r)

        policy = _policy(
            field_rules=FieldRules(
                masked_fields=[MaskingRule(field="ssn", mask_type=MaskType.redact)]
            )
        )
        out = apply_result_pipeline(records, policy)

        masked = next(r["ssn"] for r in out if "ssn" in r)
        assert masked != original
        assert original not in str(out)

    def test_allowed_fields_projects_metadata(self, s3_client, seeded_bucket):
        records = _listing_records(s3_client, seeded_bucket, "exports/public/a.csv")

        policy = _policy(field_rules=FieldRules(allowed_fields=["key", "owner"]))
        out = apply_result_pipeline(records, policy)

        for r in out:
            assert set(r).issubset({"key", "owner"})
            assert "ssn" not in r

    def test_row_filter_over_listing_entries(self, s3_client, seeded_bucket):
        # objectRules.rowFilters apply to listing entries (§2). Filter on the owner
        # metadata: only a.csv has owner=analytics.
        records = _listing_records(s3_client, seeded_bucket, "exports/public/")

        policy = _policy(
            row_filters=[RowFilter(field="owner", operator=FilterOperator.equals, value="analytics")]
        )
        out = apply_result_pipeline(records, policy)

        keys = {r["key"] for r in out}
        assert keys == {"exports/public/a.csv"}

    def test_max_object_size_drops_the_oversize_object(self, s3_client, seeded_bucket):
        # large.csv is ~2 KiB; a 1 KiB ceiling drops it and keeps the rest. Fails closed:
        # a record whose size cannot be read is dropped, so 'sizeBytes' is the key the
        # pipeline checks.
        records = _listing_records(s3_client, seeded_bucket, "exports/public/")
        assert any(r["sizeBytes"] > 1024 for r in records), "seed regressed: no oversize object"

        policy = _policy(limits=PolicyLimits(max_object_size_bytes=1024))
        out = apply_result_pipeline(records, policy)

        assert all(r["sizeBytes"] <= 1024 for r in out)
        assert "exports/public/large.csv" not in {r["key"] for r in out}

    def test_max_results_truncates_the_listing(self, s3_client, seeded_bucket):
        records = _listing_records(s3_client, seeded_bucket, "exports/public/")
        assert len(records) > 2

        policy = _policy(limits=PolicyLimits(max_results=2))
        out = apply_result_pipeline(records, policy)

        assert len(out) == 2
