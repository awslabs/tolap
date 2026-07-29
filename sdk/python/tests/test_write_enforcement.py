"""Write-path enforcement beyond the cross-SDK corpus (connector spec section 4).

``test_write_path_parity.py`` carries the decision table the three SDKs assert
identically. This module covers what is either Python-specific or too shape-dependent
to express in a shared table:

- the ``TARGET_ROW_UNKNOWN`` sentinel and non-mapping targets
- ``payload_write_fields``'s tree walk
- the HTTP method-to-permission mapping and the ``PUT`` full-replace rule
- post-write results (section 4.5): a write's response is a *read* of that data
- the wrapper entry points
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import httpx
import pytest

from tolap_core.context import build_security_context, sign_context
from tolap_core.enforcement import (
    TARGET_ROW_UNKNOWN,
    payload_write_fields,
    validate_http_write,
    validate_write,
    write_operation_for_method,
)
from tolap_core.enums import FilterOperator, MaskType, WriteOperation
from tolap_core.models import (
    EffectivePolicy,
    EndpointRules,
    FieldRules,
    MaskingParameters,
    MaskingRule,
    ObjectRules,
    PolicyPermissions,
    RowFilter,
    SecurityContext,
)
from tolap_mcp.http_wrapper import SecureHttpToolWrapper
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper


KEY = "write-enforcement-key"


def _policy(
    *,
    can_insert: bool | None = None,
    can_update: bool | None = None,
    can_delete: bool | None = None,
    read_only: bool | None = False,
    object_rules: ObjectRules | None = None,
) -> EffectivePolicy:
    return EffectivePolicy(
        version="1.0",
        user_id="u",
        tenant_id="t",
        source_profiles=["write-tests"],
        permissions=PolicyPermissions(
            can_query=True,
            can_insert=can_insert,
            can_update=can_update,
            can_delete=can_delete,
            can_export=False,
            read_only=read_only,
        ),
        object_rules=object_rules,
    )


def _signed(policy: EffectivePolicy) -> SecurityContext:
    return sign_context(
        build_security_context("u", "t", [policy], ttl=timedelta(hours=1)), KEY
    )


class TestOperationResolution:
    """The operation argument accepts an enum or its string value."""

    @pytest.mark.parametrize(
        ("value", "expected_reason"),
        [
            ("insert", "insert not permitted"),
            ("INSERT", "insert not permitted"),
            ("update", "update not permitted"),
            ("delete", "delete not permitted"),
            ("upsert", "insert not permitted"),
        ],
    )
    def test_string_operations_resolve_case_insensitively(
        self, value: str, expected_reason: str
    ) -> None:
        result = validate_write(value, "patients", {"a": 1}, _policy())

        assert result.allowed is False
        assert result.reason == expected_reason

    def test_an_unrecognized_operation_is_denied_not_admitted(self) -> None:
        """There is no permission to consult, so there is no grant to rely on.

        A write whose kind this SDK cannot classify must not fall through to the
        field and row checks and be allowed by them: the operation *is* what selects
        the permission, so an unclassifiable operation has no grant behind it.
        """
        grants_everything = _policy(
            can_insert=True, can_update=True, can_delete=True, read_only=False
        )

        result = validate_write("truncate", "patients", None, grants_everything)

        assert result.allowed is False
        assert result.reason == "unknown write operation"


class TestTargetRowSentinel:
    """An unverifiable target is a denial, never an allow (section 4.2)."""

    FILTERED = _policy(
        can_update=True,
        can_delete=True,
        read_only=False,
        object_rules=ObjectRules(
            row_filters=[RowFilter(field="region", operator=FilterOperator.equals, value="us-east")]
        ),
    )

    def test_the_default_target_row_is_unknown_and_denies(self) -> None:
        """Omitting the argument entirely must behave as unverifiable.

        This is the load-bearing default: an integrator who calls validate_write
        without thinking about the target row gets a denial, not a pass.
        """
        result = validate_write(WriteOperation.update, "patients", {"a": 1}, self.FILTERED)

        assert result.allowed is False
        assert result.reason == "write target unverifiable"

    def test_the_sentinel_passed_explicitly_denies_identically(self) -> None:
        result = validate_write(
            WriteOperation.update,
            "patients",
            {"a": 1},
            self.FILTERED,
            target_row=TARGET_ROW_UNKNOWN,
        )

        assert result.reason == "write target unverifiable"

    @pytest.mark.parametrize("target", [None, "us-east", 42, ["us-east"]])
    def test_a_non_mapping_target_is_unverifiable_not_a_pass(self, target: Any) -> None:
        """A target the filters cannot be evaluated against is unverifiable.

        The alternative -- treating a value we cannot inspect as satisfying the
        filters -- is the fail-open this whole check exists to prevent. A bare string
        or a list is not a row, so there is nothing to compare ``region`` against.
        """
        result = validate_write(
            WriteOperation.delete, "patients", None, self.FILTERED, target_row=target
        )

        assert result.allowed is False
        assert result.reason == "write target unverifiable"

    def test_an_empty_mapping_target_is_evaluated_and_fails_closed(self) -> None:
        """{} is a row, not an absent target, so the filters run and drop it.

        The distinction matters: an empty row is missing the filtered field, which
        canonical spec section 7 drops -- so the reason is the row denial, not the
        unverifiable one. An integrator seeing "target row not permitted" knows the
        row was checked; "write target unverifiable" means it was not.
        """
        result = validate_write(
            WriteOperation.update, "patients", {"a": 1}, self.FILTERED, target_row={}
        )

        assert result.allowed is False
        assert result.reason == "target row not permitted"

    def test_a_mapping_subclass_is_accepted_as_a_row(self) -> None:
        """Any Mapping is a row, not just dict -- drivers return varied types."""
        from collections import OrderedDict

        result = validate_write(
            WriteOperation.update,
            "patients",
            {"a": 1},
            self.FILTERED,
            target_row=OrderedDict(region="us-east"),
        )

        assert result.allowed is True

    @pytest.mark.parametrize(
        "operation", [WriteOperation.update, WriteOperation.delete, WriteOperation.upsert]
    )
    def test_a_policy_with_no_object_rules_has_no_filters_to_verify(
        self, operation: WriteOperation
    ) -> None:
        """No objectRules block at all means no row filters, so nothing is unverifiable.

        The check is vacuous rather than fail-closed: a policy that never expressed a
        row constraint cannot have one violated. Distinct from the case where
        objectRules exists but carries no rowFilters, and from a filtered policy with
        no target row -- which denies.
        """
        unfiltered = _policy(
            can_update=True, can_insert=True, can_delete=True, read_only=False
        )

        result = validate_write(operation, "patients", {"a": 1}, unfiltered)

        assert result.allowed is True
        assert result.reason is None


class TestPayloadWriteFields:
    """The tree walk that decides which fields a payload names."""

    def test_keys_are_collected_at_every_depth(self) -> None:
        fields = payload_write_fields(
            {"outer": {"inner": {"ssn": "1"}}, "sibling": 2}
        )

        assert fields == ["outer", "inner", "ssn", "sibling"]

    def test_keys_inside_a_list_of_records_are_collected(self) -> None:
        """A bulk insert names the fields of every record it carries."""
        fields = payload_write_fields([{"a": 1}, {"b": 2}])

        assert fields == ["a", "b"]

    def test_a_list_nested_under_a_key_is_walked(self) -> None:
        fields = payload_write_fields({"encounters": [{"ssn": "1"}]})

        assert fields == ["encounters", "ssn"]

    def test_duplicate_keys_appear_once(self) -> None:
        """Deduplicated so a denial names a field once, not per occurrence."""
        fields = payload_write_fields([{"a": 1}, {"a": 2}])

        assert fields == ["a"]

    @pytest.mark.parametrize("payload", [None, "a string", 42, True])
    def test_a_non_record_payload_names_no_fields(self, payload: Any) -> None:
        """Only a mapping names fields; a scalar body has none to check.

        Note this is not a fail-open: a scalar payload cannot carry a hidden field,
        and the permission, object and row checks all still run.
        """
        assert payload_write_fields(payload) == []

    def test_non_string_keys_are_stringified(self) -> None:
        """A JSON body cannot produce these, but a hand-built dict can."""
        assert payload_write_fields({1: "a", None: "b"}) == ["1", "None"]

    def test_resource_fields_extend_the_set_without_duplicating(self) -> None:
        fields = payload_write_fields({"a": 1}, ["a", "b"])

        assert fields == ["a", "b"]


class TestHttpMethodMapping:
    """Method-to-permission mapping (connector spec section 6)."""

    @pytest.mark.parametrize(
        ("method", "operation"),
        [
            ("POST", WriteOperation.insert),
            ("PUT", WriteOperation.update),
            ("PATCH", WriteOperation.update),
            ("DELETE", WriteOperation.delete),
            ("post", WriteOperation.insert),
            ("Delete", WriteOperation.delete),
        ],
    )
    def test_write_methods_map_to_their_operation(
        self, method: str, operation: WriteOperation
    ) -> None:
        assert write_operation_for_method(method) is operation

    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "get"])
    def test_read_methods_map_to_no_operation(self, method: str) -> None:
        """A read is governed by canQuery, which validate_endpoint already gates."""
        assert write_operation_for_method(method) is None

    def test_an_unknown_method_maps_to_no_operation(self) -> None:
        """Not silently a read: allowedMethods denies it, whose default is read-only.

        Returning None here does not admit the verb -- validate_endpoint refuses it
        because an omitted allowedMethods defaults to GET/HEAD/OPTIONS and an explicit
        list would have to name TRACE for it to pass.
        """
        assert write_operation_for_method("TRACE") is None

        policy = _policy(
            can_insert=True,
            can_update=True,
            can_delete=True,
            object_rules=ObjectRules(
                endpoint_rules=EndpointRules(allowed_endpoints=["/*"])
            ),
        )
        result = validate_http_write("TRACE", "/patients", None, policy)

        assert result.allowed is False
        assert result.reason == "method not allowed"


class TestValidateHttpWrite:
    """Endpoint rules and the write checks both run, and neither substitutes."""

    ALLOW_WRITE_METHODS = ObjectRules(
        endpoint_rules=EndpointRules(
            allowed_endpoints=["/patients*"],
            allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        ),
        field_rules=FieldRules(read_only_fields=["patients.created_at"]),
    )

    def test_a_read_method_returns_the_endpoint_decision_unchanged(self) -> None:
        """A GET is not a write, so no write permission is invented for it."""
        policy = _policy(read_only=True, object_rules=self.ALLOW_WRITE_METHODS)

        assert validate_http_write("GET", "/patients", None, policy).allowed is True

    def test_an_allowed_method_is_not_a_write_grant(self) -> None:
        """POST in allowedMethods says nothing about canInsert.

        The two controls are independent by design (connector spec section 6): one
        says which verbs reach which paths, the other says which operations the
        principal may perform.
        """
        policy = _policy(object_rules=self.ALLOW_WRITE_METHODS)

        result = validate_http_write("POST", "/patients", {"a": 1}, policy)

        assert result.allowed is False
        assert result.reason == "insert not permitted"

    def test_a_write_permission_does_not_make_a_path_reachable(self) -> None:
        """The converse: canInsert says nothing about which endpoints exist."""
        policy = _policy(
            can_insert=True,
            object_rules=ObjectRules(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/patients*"], allowed_methods=["POST"]
                )
            ),
        )

        result = validate_http_write("POST", "/admin/audit", {"a": 1}, policy)

        assert result.allowed is False
        assert result.reason == "endpoint not in allowed set"

    def test_the_endpoint_check_precedes_the_write_checks(self) -> None:
        """Both would deny; the endpoint reason wins because it runs first."""
        policy = _policy(object_rules=self.ALLOW_WRITE_METHODS)

        result = validate_http_write("POST", "/admin/audit", {"created_at": "x"}, policy)

        assert result.reason == "endpoint not in allowed set"

    def test_patch_validates_only_the_keys_present(self) -> None:
        """A PATCH is a partial update, so an unmentioned field is not written."""
        policy = _policy(can_update=True, object_rules=self.ALLOW_WRITE_METHODS)

        result = validate_http_write("PATCH", "/patients/1", {"full_name": "x"}, policy)

        assert result.allowed is True

    def test_put_treats_an_omitted_protected_field_as_written(self) -> None:
        """The full-replace rule (connector spec section 6).

        A PUT replaces the whole resource, so omitting ``created_at`` is not
        "leaving it alone" -- it is an attempt to overwrite it with absent. The
        identical body through PATCH is permitted (above); the only difference is the
        method's replace semantics.
        """
        policy = _policy(can_update=True, object_rules=self.ALLOW_WRITE_METHODS)

        result = validate_http_write("PUT", "/patients/1", {"full_name": "x"}, policy)

        assert result.allowed is False
        assert result.reason == "field is read-only: patients.created_at"

    def test_put_is_permitted_when_the_policy_protects_no_fields(self) -> None:
        """A replace adds nothing when there is nothing to protect."""
        policy = _policy(
            can_update=True,
            object_rules=ObjectRules(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/patients*"], allowed_methods=["PUT"]
                )
            ),
        )

        assert (
            validate_http_write("PUT", "/patients/1", {"full_name": "x"}, policy).allowed
            is True
        )

    def test_resource_fields_extend_a_put_to_an_allow_list(self) -> None:
        """allowedFields needs the resource's field list to be checked on a replace.

        The policy alone cannot say which resource fields an allow-list omits -- that
        is knowable only from the resource's shape -- so an integrator combining
        allowedFields with full-resource replaces supplies it.
        """
        policy = _policy(
            can_update=True,
            object_rules=ObjectRules(
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/patients*"], allowed_methods=["PUT"]
                ),
                field_rules=FieldRules(allowed_fields=["full_name"]),
            ),
        )

        without = validate_http_write("PUT", "/patients/1", {"full_name": "x"}, policy)
        with_resource = validate_http_write(
            "PUT", "/patients/1", {"full_name": "x"}, policy, resource_fields=["ssn"]
        )

        assert without.allowed is True
        assert with_resource.allowed is False
        assert with_resource.reason == "field not in allowed set: ssn"

    def test_the_object_name_is_checked_when_supplied(self) -> None:
        policy = _policy(
            can_insert=True,
            object_rules=ObjectRules(
                hidden_objects=["audit_log"],
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/*"], allowed_methods=["POST"]
                ),
            ),
        )

        result = validate_http_write(
            "POST", "/anything", {"a": 1}, policy, object_name="audit_log"
        )

        assert result.reason == "object is hidden"

    def test_the_target_row_reaches_the_row_check(self) -> None:
        policy = _policy(
            can_delete=True,
            object_rules=ObjectRules(
                row_filters=[
                    RowFilter(field="region", operator=FilterOperator.equals, value="us-east")
                ],
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/*"], allowed_methods=["DELETE"]
                ),
            ),
        )

        assert (
            validate_http_write(
                "DELETE", "/patients/1", None, policy, target_row={"region": "us-east"}
            ).allowed
            is True
        )
        assert (
            validate_http_write(
                "DELETE", "/patients/1", None, policy, target_row={"region": "eu-west"}
            ).reason
            == "target row not permitted"
        )


class TestMcpWrapperWritePath:
    """The wrapper entry points an integrator actually calls."""

    WRITE_POLICY = _policy(
        can_insert=True,
        can_update=True,
        read_only=False,
        object_rules=ObjectRules(
            allowed_objects=["patients"],
            field_rules=FieldRules(
                hidden_fields=["patients.ssn"],
                read_only_fields=["patients.created_at"],
                masked_fields=[
                    MaskingRule(
                        field="patients.email",
                        mask_type=MaskType.partial,
                        parameters=MaskingParameters(show_first=1),
                    )
                ],
            ),
        ),
    )

    def _wrapper(self) -> SecureMcpToolWrapper:
        return SecureMcpToolWrapper(SecureMcpServerOptions(signing_key=KEY))

    def test_pre_write_validates_the_context_before_the_policy(self) -> None:
        """A forged context is a signature failure, not a policy decision.

        The context has to be trustworthy before its policy means anything; checking
        the policy first would let an attacker's own policy answer the question.
        """
        forged = _signed(self.WRITE_POLICY)
        forged.signature = "not-the-real-signature"

        result = self._wrapper().pre_write(
            forged, WriteOperation.insert, "patients", {"full_name": "x"}
        )

        assert result.allowed is False
        assert result.reason == "invalid signature"

    def test_pre_write_permits_a_writable_payload(self) -> None:
        context = _signed(self.WRITE_POLICY)

        result = self._wrapper().pre_write(
            context, WriteOperation.insert, "patients", {"full_name": "x"}
        )

        assert result.allowed is True

    def test_pre_write_denies_a_read_only_field(self) -> None:
        context = _signed(self.WRITE_POLICY)

        result = self._wrapper().pre_write(
            context, WriteOperation.insert, "patients", {"created_at": "x"}
        )

        assert result.reason == "field is read-only: created_at"

    def test_a_denied_write_never_reaches_the_write_function(self) -> None:
        """The whole point of pre-write validation: nothing to filter afterwards.

        If the function ran and then we denied, the row would already be committed.
        """
        context = _signed(self.WRITE_POLICY)
        calls: list[dict] = []

        def write_fn(**kwargs: Any) -> dict:
            calls.append(kwargs)
            return {"id": 1}

        with pytest.raises(PermissionError, match="field is hidden: ssn"):
            self._wrapper().execute_write_with_enforcement(
                context,
                WriteOperation.insert,
                write_fn,
                {"row": {"ssn": "1"}},
                object_name="patients",
                payload={"ssn": "1"},
            )

        assert calls == []

    def test_a_write_returning_data_runs_the_read_pipeline(self) -> None:
        """Section 4.5: a write's response IS a read of the data it returns.

        The caller wrote ``email`` itself and gets it back masked, because what comes
        back is a read and every read is masked. A hidden field it did not write does
        not appear at all -- an INSERT ... RETURNING * would otherwise disclose it.
        """
        context = _signed(self.WRITE_POLICY)

        returned = self._wrapper().execute_write_with_enforcement(
            context,
            WriteOperation.insert,
            lambda: {"id": 1, "email": "alice@example.com", "ssn": "111-22-3333"},
            object_name="patients",
            payload={"email": "alice@example.com"},
        )

        assert returned["email"] == "a****************"
        assert "ssn" not in returned
        assert returned["id"] == 1

    def test_a_write_returning_a_list_runs_the_pipeline_over_every_record(self) -> None:
        """A multi-row INSERT ... RETURNING is a read of every row it returns."""
        context = _signed(self.WRITE_POLICY)

        returned = self._wrapper().execute_write_with_enforcement(
            context,
            WriteOperation.insert,
            lambda: [
                {"id": 1, "ssn": "1", "email": "a@b.c"},
                {"id": 2, "ssn": "2", "email": "d@e.f"},
            ],
            object_name="patients",
            payload={"email": "a@b.c"},
        )

        assert all("ssn" not in record for record in returned)
        assert [record["email"] for record in returned] == ["a****", "d****"]

    def test_a_write_returning_nothing_is_not_denied_as_an_unenforceable_shape(
        self,
    ) -> None:
        """There is no data to enforce a policy over, so None is not a violation.

        Denying here would make every ``DELETE`` fail: a delete legitimately returns
        nothing, and the shape rules exist to stop *data* escaping unenforced.
        """
        context = _signed(self.WRITE_POLICY)

        returned = self._wrapper().execute_write_with_enforcement(
            context,
            WriteOperation.insert,
            lambda: None,
            object_name="patients",
            payload={"full_name": "x"},
        )

        assert returned is None

    def test_a_write_returning_a_scalar_is_still_denied(self) -> None:
        """A non-None unenforceable shape is denied exactly as on the read path.

        A row count is fine to return, but the wrapper cannot tell a count from a
        leaked value, so canonical spec section 5 applies unchanged.
        """
        context = _signed(self.WRITE_POLICY)

        with pytest.raises(PermissionError, match="cannot be policy-enforced"):
            self._wrapper().execute_write_with_enforcement(
                context,
                WriteOperation.insert,
                lambda: "1 row inserted",
                object_name="patients",
                payload={"full_name": "x"},
            )

    def test_full_replace_does_not_duplicate_a_field_the_payload_already_names(
        self,
    ) -> None:
        """A replace whose body *does* name a protected field denies on that name.

        The reason has to be the payload's own spelling (``patients.ssn`` as written
        here matches the rule exactly), not a second copy appended by the replace
        expansion -- otherwise a caller could see the same field reported twice, or
        reported under the policy's spelling rather than their own.
        """
        context = _signed(self.WRITE_POLICY)

        result = self._wrapper().pre_write(
            context,
            WriteOperation.update,
            "patients",
            {"patients.ssn": "1", "full_name": "x"},
            full_replace=True,
        )

        assert result.allowed is False
        assert result.reason == "field is hidden: patients.ssn"

    def test_full_replace_reaches_the_wrapper(self) -> None:
        context = _signed(self.WRITE_POLICY)

        partial = self._wrapper().pre_write(
            context, WriteOperation.update, "patients", {"full_name": "x"}
        )
        replace = self._wrapper().pre_write(
            context,
            WriteOperation.update,
            "patients",
            {"full_name": "x"},
            full_replace=True,
        )

        assert partial.allowed is True
        assert replace.allowed is False
        assert replace.reason == "field is hidden: patients.ssn"


class TestHttpWrapperWritePath:
    """SecureHttpToolWrapper over a mock transport."""

    def _wrapper(self, handler: Any) -> SecureHttpToolWrapper:
        client = httpx.Client(
            base_url="https://api.example.test",
            transport=httpx.MockTransport(handler),
        )
        return SecureHttpToolWrapper(SecureMcpServerOptions(signing_key=KEY), client)

    @staticmethod
    def _echo(request: httpx.Request) -> httpx.Response:
        import json as _json

        body = _json.loads(request.content) if request.content else {}
        return httpx.Response(
            201,
            json={"id": 7, "email": "alice@example.com", "ssn": "111", **body},
        )

    POLICY = _policy(
        can_insert=True,
        read_only=False,
        object_rules=ObjectRules(
            endpoint_rules=EndpointRules(
                allowed_endpoints=["/patients*"], allowed_methods=["GET", "POST", "PUT"]
            ),
            field_rules=FieldRules(
                hidden_fields=["ssn"],
                read_only_fields=["created_at"],
                masked_fields=[
                    MaskingRule(
                        field="email",
                        mask_type=MaskType.partial,
                        parameters=MaskingParameters(show_first=1),
                    )
                ],
            ),
        ),
    )

    def test_a_denied_write_never_puts_bytes_on_the_transport(self) -> None:
        """The denial has to happen before the request leaves the process."""
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(201, json={})

        context = _signed(self.POLICY)

        with pytest.raises(PermissionError, match="field is read-only: created_at"):
            self._wrapper(handler).request(
                context, "POST", "/patients", json={"created_at": "x"}
            )

        assert seen == []

    def test_a_201_body_is_masked_and_stripped_like_any_read(self) -> None:
        """Section 4.5 over HTTP: the created resource's body is a read of it."""
        context = _signed(self.POLICY)

        body = self._wrapper(self._echo).request(
            context, "POST", "/patients", json={"email": "alice@example.com"}
        )

        assert body["email"] == "a****************"
        assert "ssn" not in body
        assert body["id"] == 7

    def test_a_put_full_replace_is_denied_for_an_omitted_protected_field(self) -> None:
        """The PUT rule reaches the HTTP wrapper, and PATCH is unaffected.

        canUpdate is granted here and the method is allowed, so the only thing
        refusing this is the replace semantics treating ``ssn``/``created_at`` as
        written.
        """
        policy = _policy(
            can_update=True,
            read_only=False,
            object_rules=self.POLICY.object_rules,
        )
        context = _signed(policy)

        with pytest.raises(PermissionError, match="field is hidden: ssn"):
            self._wrapper(self._echo).request(
                context, "PUT", "/patients/1", json={"full_name": "x"}
            )

    def test_the_target_row_and_object_name_reach_the_write_checks(self) -> None:
        policy = _policy(
            can_insert=True,
            read_only=False,
            object_rules=ObjectRules(
                hidden_objects=["audit_log"],
                endpoint_rules=EndpointRules(
                    allowed_endpoints=["/patients*"], allowed_methods=["POST"]
                ),
            ),
        )
        context = _signed(policy)

        with pytest.raises(PermissionError, match="object is hidden"):
            self._wrapper(self._echo).request(
                context, "POST", "/patients", json={"a": 1}, object_name="audit_log"
            )

    def test_a_read_is_unaffected_by_the_write_checks(self) -> None:
        """A GET under a policy granting no write permission still reads.

        Regression guard: routing reads through the same entry point as writes must
        not make canQuery depend on canInsert.
        """
        policy = _policy(read_only=True, object_rules=self.POLICY.object_rules)

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"id": 1, "ssn": "111"})

        body = self._wrapper(handler).request(_signed(policy), "GET", "/patients")

        assert body == {"id": 1}


class TestReadOnlyFieldsHaveNoEffectOnReads:
    """Section 4.3: readOnlyFields is a write control only.

    A field listed there is returned normally, subject to hidden/allowed/masking
    rules like any other. Two doc comments in a prior implementation contradicted
    each other on this point, so it is pinned here.
    """

    POLICY = _policy(
        can_update=True,
        read_only=False,
        object_rules=ObjectRules(
            field_rules=FieldRules(read_only_fields=["created_at", "id"])
        ),
    )

    def test_a_read_only_field_is_returned_by_the_pipeline(self) -> None:
        from tolap_core.enforcement import apply_result_pipeline

        rows = apply_result_pipeline(
            [{"id": 1, "created_at": "2026-01-01", "full_name": "Alice"}], self.POLICY
        )

        assert rows == [{"id": 1, "created_at": "2026-01-01", "full_name": "Alice"}]

    def test_a_read_only_field_is_not_denied_by_the_read_field_check(self) -> None:
        from tolap_core.enforcement import validate_field_access

        result = validate_field_access(["id", "created_at"], self.POLICY)

        assert result.denied == []
        assert result.allowed == ["id", "created_at"]

    def test_the_same_field_is_denied_on_the_write_path(self) -> None:
        """The asymmetry is the whole feature: readable, not writable."""
        result = validate_write(
            WriteOperation.update, None, {"created_at": "x"}, self.POLICY
        )

        assert result.reason == "field is read-only: created_at"
