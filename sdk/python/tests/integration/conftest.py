"""Integration-test fixtures.

Two suites share this conftest:

  - Postgres tests (test_postgres_*.py): require a running Postgres at
    localhost:5432 with a database named `tolap_integration_test`. Skip
    automatically if the DB isn't reachable.

        createdb tolap_integration_test
        psql -d tolap_integration_test -f tests/integration/schema.sql

    Override DSN via TOLAP_TEST_DB_DSN.

  - openFDA scenario tests (test_openfda_*.py): two modes.
    Default (TOLAP_TEST_LIVE unset): run offline against pre-recorded
    snapshots in fixtures/api/openfda/.
    Live mode (TOLAP_TEST_LIVE=1): refresh the recordings from api.fda.gov
    once per session, then run the SAME enforcement assertions against the
    real responses. Each live session = 3 actual GETs against api.fda.gov
    plus full TOLAP enforcement coverage on the responses.
"""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

import httpx
import psycopg
import pymysql
import pymysql.cursors
import pytest

from tolap_core.context import build_security_context, sign_context
from tolap_core.enums import MaskType
from tolap_core.models import (
    EffectivePolicy,
    EndpointRules,
    FieldRules,
    FilterOperator,
    MaskingParameters,
    MaskingRule,
    ObjectRules,
    PolicyLimits,
    PolicyPermissions,
    RowFilter,
    SecurityContext,
)


DEFAULT_DSN = "postgresql:///tolap_integration_test"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"
SIGNING_KEY = "integration-test-signing-key"

MYSQL_SCHEMA_PATH = Path(__file__).parent / "schema_mysql.sql"
MYSQL_DEFAULT_HOST = "127.0.0.1"
MYSQL_DEFAULT_USER = "root"
MYSQL_DEFAULT_DB = "tolap_integration_test"

OPENFDA_FIXTURES = Path(__file__).parents[4] / "fixtures" / "api" / "openfda"
OPENFDA_SIGNING_KEY = "openfda-integration-key"
OPENFDA_ROUTES: dict[tuple[str, str], str] = {
    ("GET", "/drug/event.json"): "drug_event_limit3.json",
    ("GET", "/drug/label.json"): "drug_label_limit3.json",
    ("GET", "/food/enforcement.json"): "food_enforcement_limit2.json",
}


def _dsn() -> str:
    return os.environ.get("TOLAP_TEST_DB_DSN", DEFAULT_DSN)


@pytest.fixture(scope="session")
def db_dsn() -> str:
    dsn = _dsn()
    try:
        with psycopg.connect(dsn, connect_timeout=2) as conn:
            conn.execute("SELECT 1")
    except psycopg.Error as exc:
        pytest.skip(f"Postgres not reachable at {dsn}: {exc}")
    return dsn


@pytest.fixture(scope="session")
def _seed_database(db_dsn: str) -> None:
    """Reload schema.sql once per session so the test data is deterministic.

    Deliberately **not** ``autouse``. An autouse session fixture is requested by
    every test in this package, so its ``pytest.skip`` skipped the whole
    integration session — the Postgres tests never ran for anyone without MySQL
    installed, and vice versa. Seeding is pulled in by ``db_conn`` instead, so a
    missing Postgres skips only the tests that actually need Postgres.
    """
    sql = SCHEMA_PATH.read_text()
    with psycopg.connect(db_dsn, autocommit=True) as conn:
        conn.execute(sql)


@pytest.fixture
def db_conn(db_dsn: str, _seed_database: None):
    with psycopg.connect(db_dsn, row_factory=psycopg.rows.dict_row) as conn:
        yield conn


# ----- MySQL fixtures -----


def _mysql_connect_kwargs() -> dict:
    return {
        "host": os.environ.get("TOLAP_TEST_MYSQL_HOST", MYSQL_DEFAULT_HOST),
        "user": os.environ.get("TOLAP_TEST_MYSQL_USER", MYSQL_DEFAULT_USER),
        "password": os.environ.get("TOLAP_TEST_MYSQL_PASSWORD", ""),
        "database": os.environ.get("TOLAP_TEST_MYSQL_DB", MYSQL_DEFAULT_DB),
        "port": int(os.environ.get("TOLAP_TEST_MYSQL_PORT", "3306")),
        "connect_timeout": 2,
    }


@pytest.fixture(scope="session")
def mysql_conn_kwargs() -> dict:
    kwargs = _mysql_connect_kwargs()
    try:
        conn = pymysql.connect(**kwargs)
        conn.ping()
        conn.close()
    except pymysql.MySQLError as exc:
        pytest.skip(f"MySQL not reachable: {exc}")
    return kwargs


@pytest.fixture(scope="session")
def _seed_mysql_database(mysql_conn_kwargs: dict) -> None:
    """Reload schema_mysql.sql once per session.

    Not ``autouse``, for the same reason as ``_seed_database``: as an autouse
    session fixture its skip took the Postgres tests and the DB-independent
    KB/openFDA tests down with it whenever MySQL was unreachable. Pulled in by
    ``mysql_conn`` so only MySQL tests depend on MySQL.
    """
    raw = MYSQL_SCHEMA_PATH.read_text()
    # Strip line comments so we can naively split on ';'. Block comments are
    # not used in our schema file.
    lines = [ln for ln in raw.splitlines() if not ln.lstrip().startswith("--")]
    cleaned = "\n".join(lines)
    statements = [s.strip() for s in cleaned.split(";") if s.strip()]
    conn = pymysql.connect(**mysql_conn_kwargs)
    try:
        with conn.cursor() as cur:
            for stmt in statements:
                cur.execute(stmt)
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def mysql_conn(mysql_conn_kwargs: dict, _seed_mysql_database: None):
    conn = pymysql.connect(**mysql_conn_kwargs, cursorclass=pymysql.cursors.DictCursor)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def signing_key() -> str:
    return SIGNING_KEY


@pytest.fixture
def healthcare_analyst_context(signing_key: str) -> SecurityContext:
    """The README-canonical healthcare-analyst policy, as a signed SecurityContext."""
    policy = EffectivePolicy(
        version="1.0",
        user_id="analyst-001",
        tenant_id="hospital-001",
        source_profiles=["healthcare-analyst"],
        permissions=PolicyPermissions(can_query=True, can_export=False, read_only=True),
        object_rules=ObjectRules(
            allowed_objects=["patients", "encounters", "diagnoses"],
            hidden_objects=["billing_internal", "audit_log"],
            field_rules=FieldRules(
                hidden_fields=["patients.ssn", "patients.date_of_birth"],
                masked_fields=[
                    MaskingRule(
                        field="patients.email",
                        mask_type=MaskType.hash,
                        parameters=MaskingParameters(algorithm="sha256"),
                    ),
                    MaskingRule(
                        field="patients.full_name",
                        mask_type=MaskType.partial,
                        parameters=MaskingParameters(show_first=1, mask_char="*"),
                    ),
                ],
            ),
            row_filters=[
                RowFilter(field="region", operator=FilterOperator.in_, values=["us-east", "us-west"]),
                RowFilter(field="status", operator=FilterOperator.not_equals, value="deleted"),
            ],
        ),
        limits=PolicyLimits(max_results=5000, max_query_time_seconds=30),
    )

    context = build_security_context(
        user_id="analyst-001",
        tenant_id="hospital-001",
        policies=[policy],
        ttl=timedelta(hours=1),
    )
    return sign_context(context, signing_key)


# ----- openFDA API fixtures (offline replay or live network) -----


def is_live_mode() -> bool:
    return os.environ.get("TOLAP_TEST_LIVE") == "1"


# Map (METHOD, path) -> (fixture filename, query params used to record).
OPENFDA_LIVE_PARAMS: dict[tuple[str, str], dict[str, int]] = {
    ("GET", "/drug/event.json"): {"limit": 3},
    ("GET", "/drug/label.json"): {"limit": 3},
    ("GET", "/food/enforcement.json"): {"limit": 2},
}


def _openfda_replay_handler(request: httpx.Request) -> httpx.Response:
    key = (request.method.upper(), request.url.path)
    fixture_name = OPENFDA_ROUTES.get(key)
    if fixture_name is None:
        return httpx.Response(404, json={"error": f"no fixture for {key}"})
    body = (OPENFDA_FIXTURES / fixture_name).read_text()
    return httpx.Response(200, content=body, headers={"content-type": "application/json"})


@pytest.fixture(scope="session", autouse=True)
def _refresh_openfda_recordings_if_live() -> None:
    """In live mode, re-fetch each recording from api.fda.gov once per session.

    Subsequent assertions in the live tests (e.g. "the hashed safetyreportid
    matches sha256(<original>)") read the freshly-saved recording for the
    canonical pre-mask value. If the live API is unreachable, fall through —
    individual tests will surface the failure.
    """
    if not is_live_mode():
        return

    OPENFDA_FIXTURES.mkdir(parents=True, exist_ok=True)
    with httpx.Client(
        base_url="https://api.fda.gov",
        timeout=15.0,
        headers={"User-Agent": "tolap-sdk-tests/1.0"},
    ) as client:
        for (method, path), params in OPENFDA_LIVE_PARAMS.items():
            fixture_name = OPENFDA_ROUTES[(method, path)]
            response = client.request(method, path, params=params)
            response.raise_for_status()
            (OPENFDA_FIXTURES / fixture_name).write_text(response.text)


@pytest.fixture
def openfda_replay_client() -> httpx.Client:
    """An httpx.Client wired to either the on-disk recordings or live api.fda.gov.

    In live mode the client performs real GETs; everything else (the
    SecureHttpToolWrapper, the policy, the assertions) is unchanged.
    """
    if is_live_mode():
        with httpx.Client(
            base_url="https://api.fda.gov",
            timeout=15.0,
            headers={"User-Agent": "tolap-sdk-tests/1.0"},
        ) as client:
            yield client
        return

    transport = httpx.MockTransport(_openfda_replay_handler)
    with httpx.Client(base_url="https://api.fda.gov", transport=transport) as client:
        yield client


@pytest.fixture
def openfda_signing_key() -> str:
    return OPENFDA_SIGNING_KEY


def _build_signed(policy: EffectivePolicy, signing_key: str, user: str = "fda-analyst-001",
                  tenant: str = "fda-program-001") -> SecurityContext:
    ctx = build_security_context(
        user_id=user,
        tenant_id=tenant,
        policies=[policy],
        ttl=timedelta(hours=1),
    )
    return sign_context(ctx, signing_key)


@pytest.fixture
def openfda_analyst_context(openfda_signing_key: str) -> SecurityContext:
    """Allow drug endpoints, hide food endpoints, mask report id and patient age,
    drop patientsex entirely (hidden), and limit results to 2."""
    policy = EffectivePolicy(
        version="1.0",
        user_id="fda-analyst-001",
        tenant_id="fda-program-001",
        source_profiles=["openfda-analyst"],
        permissions=PolicyPermissions(can_query=True, can_export=False, read_only=True),
        object_rules=ObjectRules(
            endpoint_rules=EndpointRules(
                allowed_endpoints=["/drug/*"],
                hidden_endpoints=["/food/*"],
                allowed_methods=["GET"],
            ),
            field_rules=FieldRules(
                hidden_fields=["results.patient.patientsex"],
                masked_fields=[
                    MaskingRule(
                        field="results.safetyreportid",
                        mask_type=MaskType.hash,
                        parameters=MaskingParameters(algorithm="sha256"),
                    ),
                    MaskingRule(
                        field="results.patient.patientonsetage",
                        mask_type=MaskType.redact,
                    ),
                ],
            ),
        ),
        limits=PolicyLimits(max_results=2),
    )
    return _build_signed(policy, openfda_signing_key)


@pytest.fixture
def openfda_deny_query_context(openfda_signing_key: str) -> SecurityContext:
    policy = EffectivePolicy(
        version="1.0",
        user_id="fda-analyst-001",
        tenant_id="fda-program-001",
        source_profiles=["openfda-deny"],
        permissions=PolicyPermissions(can_query=False, can_export=False, read_only=True),
    )
    return _build_signed(policy, openfda_signing_key)


@pytest.fixture
def openfda_post_only_context(openfda_signing_key: str) -> SecurityContext:
    policy = EffectivePolicy(
        version="1.0",
        user_id="fda-analyst-001",
        tenant_id="fda-program-001",
        source_profiles=["openfda-post-only"],
        permissions=PolicyPermissions(can_query=True, can_export=False, read_only=True),
        object_rules=ObjectRules(
            endpoint_rules=EndpointRules(
                allowed_endpoints=["/drug/*"],
                allowed_methods=["POST"],
            ),
        ),
    )
    return _build_signed(policy, openfda_signing_key)


@pytest.fixture
def openfda_expired_context(openfda_signing_key: str) -> SecurityContext:
    policy = EffectivePolicy(
        version="1.0",
        user_id="fda-analyst-001",
        tenant_id="fda-program-001",
        source_profiles=["openfda-expired"],
        permissions=PolicyPermissions(can_query=True, can_export=False, read_only=True),
        object_rules=ObjectRules(
            endpoint_rules=EndpointRules(allowed_endpoints=["/drug/*"], allowed_methods=["GET"]),
        ),
    )
    ctx = build_security_context(
        user_id="fda-analyst-001",
        tenant_id="fda-program-001",
        policies=[policy],
        ttl=timedelta(hours=-1),  # already expired
    )
    return sign_context(ctx, openfda_signing_key)
