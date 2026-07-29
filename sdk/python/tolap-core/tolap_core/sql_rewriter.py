"""Push a TOLAP policy's field and row restrictions into a SQL query.

**There is no portable SQL, so the dialect is an explicit parameter.** An earlier
version of this module claimed to target "the ANSI-ish intersection of Postgres,
MySQL, and Athena/Trino: double-quoted identifiers". That intersection does not
exist. MySQL's default identifier quote is the backtick, and without
``ANSI_QUOTES`` it reads ``"region"`` as a *string literal* -- so the emitted
``WHERE "region" = 'us-east'`` evaluated ``'region' = 'us-east'`` and matched no
row at all, with no error reported by the engine. Against the six-row integration
fixture the policy-filtered query returned 0 rows where backticks return 2.

Callers therefore name their engine with :class:`SqlDialect` (connector spec
section 5.1). The dialect is *never* inferred and is *never* read from the policy:
a signed security artifact must not depend on deployment detail, and
``sourceConnectionId``'s ``db`` category deliberately does not distinguish
engines. An omitted dialect selects :attr:`SqlDialect.ansi` -- not a guess at the
engine, but the subset most engines accept. An *unrecognized* dialect is not
guessed at either: nothing is rewritten and every filter is reported unpushable,
because guessing a profile is how the MySQL defect above happened.

Only the emitted *text* is dialect-specific. The set of pushable operators, the
fail-closed rules, and the post-fetch pipeline are identical under every profile,
so choosing a profile never changes which rows a policy admits -- only where the
work happens.

**Never a substitute for :func:`tolap_core.enforcement.apply_result_pipeline`**,
which stays mandatory and normative (canonical spec section 4). Rewriting is a
*resource optimization*: it stops the database producing a row the policy
excludes, so the row is never transferred or materialized (threat-model D2). It
cannot replace the post-fetch pass, because:

- Not every filter has a portable SQL form. ``contains``, ``startsWith`` and
  ``matches`` are never pushed, and any value carrying a backslash is refused.
  :func:`unpushable_filters` reports them; the post pass is what enforces them.
- Masking has no SQL form here at all. Masked fields are deliberately **kept** in
  the rewritten SELECT so the post pass still has a value to mask.
- ``SELECT *`` cannot be expanded without an ``allowedFields`` list, so hidden
  fields can still arrive from the database and must still be stripped.

Every path is built to *narrow or leave alone*, never to widen. When a construct
cannot be handled the query is returned untouched and the post pass does the work.

Parsing is regex- and depth-scan-based, not a full SQL grammar. Keyword matches
are restricted to parenthesis depth zero and skip string literals and quoted
identifiers, so a subquery's ``WHERE`` or ``LIMIT`` is not mistaken for the
statement's own. Constructs beyond that -- CTEs, set operations, lateral joins --
are recognized well enough to be declined, not to be rewritten.

Stdlib only: ``tolap-core`` ships zero runtime dependencies, so there is no
``sqlparse``/``sqlglot`` here and there must not be.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field as dataclass_field
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any

from tolap_core.enforcement import _field_name_matches
from tolap_core.enums import FilterOperator
from tolap_core.models import EffectivePolicy, RowFilter


_LOG = logging.getLogger(__name__)


# -- SQL dialects (connector spec section 5.1) --


class SqlDialect(Enum):
    """The engine a rewritten statement is destined for.

    Supplied by the integrator, because the dialect is a property of *their*
    connection and only they know it -- they already chose ``psycopg`` or
    ``pymysql``. It is deliberately not derivable from the policy.
    """

    #: The strict intersection: double-quoted identifiers, ``LIMIT n``. The
    #: default, chosen when no dialect is named. Not a guess at the engine -- the
    #: subset most engines accept.
    ansi = "ansi"

    #: PostgreSQL, and the Redshift/Greenplum forks that share its quoting.
    postgres = "postgres"

    #: Trino, Presto, and Athena.
    trino = "trino"

    #: MySQL and MariaDB. Backtick identifiers, because ``"region"`` is a string
    #: literal here unless ``ANSI_QUOTES`` is set.
    mysql = "mysql"

    #: Microsoft SQL Server and Azure SQL. Bracket identifiers, and ``TOP n``
    #: after ``SELECT`` rather than ``LIMIT n`` at the end.
    sqlserver = "sqlserver"


#: How a profile spells its row limit. ``LIMIT n`` is a suffix; ``TOP n`` is an
#: infix that binds to a single ``SELECT``, which is a structural difference
#: rather than a token swap -- see :func:`_clamp_top`.
_LIMIT_SUFFIX = "limit"
_TOP_PREFIX = "top"


@dataclass(frozen=True)
class _DialectProfile:
    """The emitted-text rules for one engine.

    Only *text* lives here. Which operators are pushable, which values are
    refused, and every fail-closed rule are profile-independent by design
    (connector spec section 5.1): a filter unpushable in one profile is
    unpushable in all of them, so selecting a profile never changes which rows a
    policy admits.
    """

    dialect: SqlDialect
    quote_open: str
    quote_close: str
    row_limit: str

    @property
    def quote_chars(self) -> frozenset[str]:
        """The characters this profile uses to delimit an identifier.

        An identifier containing one of them is *declined* rather than escaped by
        doubling (connector spec section 5.1 rule 4). Declining costs an
        optimization; mis-escaping emits author-controlled text into a statement.
        """
        return frozenset({self.quote_open, self.quote_close})


_DIALECT_PROFILES: dict[SqlDialect, _DialectProfile] = {
    SqlDialect.ansi: _DialectProfile(SqlDialect.ansi, '"', '"', _LIMIT_SUFFIX),
    SqlDialect.postgres: _DialectProfile(SqlDialect.postgres, '"', '"', _LIMIT_SUFFIX),
    SqlDialect.trino: _DialectProfile(SqlDialect.trino, '"', '"', _LIMIT_SUFFIX),
    SqlDialect.mysql: _DialectProfile(SqlDialect.mysql, "`", "`", _LIMIT_SUFFIX),
    SqlDialect.sqlserver: _DialectProfile(SqlDialect.sqlserver, "[", "]", _TOP_PREFIX),
}

#: What an omitted dialect selects.
DEFAULT_DIALECT = SqlDialect.ansi


def _resolve_profile(dialect: SqlDialect | str | None) -> _DialectProfile | None:
    """The profile for a dialect, or None when it is not recognized.

    ``None`` means "omitted", which selects :data:`DEFAULT_DIALECT`. A string is
    accepted so an integrator can plumb a config value straight through.

    An **unrecognized** dialect returns None *without raising*, and every caller
    treats that as "do not rewrite at all" (connector spec section 5.1 rule 2).
    Neither guessing a profile nor throwing is acceptable: guessing is how the
    MySQL backtick defect happened, and throwing would turn a deployment typo
    into an outage on a path that is only ever an optimization.
    """
    if dialect is None:
        return _DIALECT_PROFILES[DEFAULT_DIALECT]

    if isinstance(dialect, SqlDialect):
        # A SqlDialect member with no profile is unreachable today; the lookup is
        # a .get so adding a member without a profile declines rather than raises.
        profile = _DIALECT_PROFILES.get(dialect)
    else:
        try:
            profile = _DIALECT_PROFILES[SqlDialect(dialect)]
        except ValueError:
            profile = None

    if profile is None:
        _LOG.debug(
            "unrecognized SQL dialect %r: nothing is pushed down and the post-fetch "
            "pass enforces the policy in full",
            dialect,
        )
    return profile


# -- Keyword patterns --
#
# Each is matched against the whole query and then filtered to occurrences at
# parenthesis depth zero and outside string literals, so a subquery cannot supply
# the match that governs the outer statement.

_SELECT_KEYWORD = re.compile(r"\bSELECT\b", re.IGNORECASE)
_FROM_KEYWORD = re.compile(r"\bFROM\b", re.IGNORECASE)
_WHERE_KEYWORD = re.compile(r"\bWHERE\b", re.IGNORECASE)
_LIMIT_CLAUSE = re.compile(r"\bLIMIT\s+(\d+)", re.IGNORECASE)

# -- sqlserver TOP placement --
#
# Individually matched keywords, so the shapes in which `TOP n` cannot be placed
# correctly can be recognised and declined rather than approximated.

_LIMIT_KEYWORD = re.compile(r"\bLIMIT\b", re.IGNORECASE)
_OFFSET_KEYWORD = re.compile(r"\bOFFSET\b", re.IGNORECASE)
_FETCH_KEYWORD = re.compile(r"\bFETCH\b", re.IGNORECASE)
_UNION_KEYWORD = re.compile(r"\bUNION\b", re.IGNORECASE)
_INTERSECT_KEYWORD = re.compile(r"\bINTERSECT\b", re.IGNORECASE)
_EXCEPT_KEYWORD = re.compile(r"\bEXCEPT\b", re.IGNORECASE)

# `SELECT DISTINCT`/`SELECT ALL`: TOP goes *after* the quantifier, since
# "SELECT DISTINCT TOP 5" is a syntax error and "SELECT TOP 5 DISTINCT" would
# count rows before duplicates are removed.
_SELECT_QUANTIFIER = re.compile(r"\s+(?:DISTINCT|ALL)\b", re.IGNORECASE)

# An existing `TOP n` or `TOP (n)`, with the modifiers that make it not a plain row
# count. `PERCENT` is a proportion rather than a count and `WITH TIES` returns more
# rows than the number given, so neither can be clamped to a row limit.
#
# The count alternatives are separate branches rather than one `\(?\s*(\d+)\s*\)?`:
# a trailing `\s*` would swallow the space before `PERCENT` and hide the modifier,
# which made `TOP 5 PERCENT` look like a plain `TOP 5`.
_TOP_CLAUSE = re.compile(
    r"\s+TOP\s*(?:\(\s*(?P<paren_count>\d+)\s*\)|(?P<count>\d+))"
    r"(?P<modifier>\s+PERCENT\b|\s+WITH\s+TIES\b)?",
    re.IGNORECASE,
)

# Clauses that may follow the FROM/join list. An injected WHERE goes before
# whichever of them appears earliest.
_POST_FROM_CLAUSES = [
    re.compile(r"\bGROUP\s+BY\b", re.IGNORECASE),
    re.compile(r"\bHAVING\b", re.IGNORECASE),
    re.compile(r"\bWINDOW\b", re.IGNORECASE),
    re.compile(r"\bORDER\s+BY\b", re.IGNORECASE),
    re.compile(r"\bLIMIT\b", re.IGNORECASE),
    re.compile(r"\bOFFSET\b", re.IGNORECASE),
    re.compile(r"\bFETCH\b", re.IGNORECASE),
    re.compile(r"\bUNION\b", re.IGNORECASE),
    re.compile(r"\bINTERSECT\b", re.IGNORECASE),
    re.compile(r"\bEXCEPT\b", re.IGNORECASE),
]

# The table reference immediately after FROM: a bare, dotted, or quoted name.
_FROM_TABLE_PATTERN = re.compile(
    r'\bFROM\s+((?:"[^"]+"|\w+)(?:\.(?:"[^"]+"|\w+))*)', re.IGNORECASE
)

# -- Clause-body patterns, used only by validate_query's field extraction --

_WHERE_CLAUSE_PATTERN = re.compile(
    r"\bWHERE\s+(.+?)(?:\bORDER\s+BY\b|\bGROUP\s+BY\b|\bHAVING\b|\bLIMIT\b|\bOFFSET\b|\bUNION\b|;|$)",
    re.IGNORECASE | re.DOTALL,
)
_ORDER_BY_CLAUSE_PATTERN = re.compile(
    r"\bORDER\s+BY\s+(.+?)(?:\bLIMIT\b|\bOFFSET\b|\bUNION\b|;|$)", re.IGNORECASE | re.DOTALL
)
_GROUP_BY_CLAUSE_PATTERN = re.compile(
    r"\bGROUP\s+BY\s+(.+?)(?:\bHAVING\b|\bORDER\s+BY\b|\bLIMIT\b|\bOFFSET\b|\bUNION\b|;|$)",
    re.IGNORECASE | re.DOTALL,
)
_HAVING_CLAUSE_PATTERN = re.compile(
    r"\bHAVING\s+(.+?)(?:\bORDER\s+BY\b|\bLIMIT\b|\bOFFSET\b|\bUNION\b|;|$)",
    re.IGNORECASE | re.DOTALL,
)

_COMPARISON_OPERATORS = (
    r"(?:=|!=|<>|<=|>=|<|>|\bLIKE\b|\bIN\b|\bIS\b|\bBETWEEN\b|\bNOT\s+LIKE\b|\bNOT\s+IN\b)"
)

# Unqualified field references on the left of a comparison operator.
_COLUMN_COMPARISON_PATTERN = re.compile(
    r"(?<![.\"'`\w])(\w+)\s*" + _COMPARISON_OPERATORS, re.IGNORECASE
)

# Table-qualified field references on the left of a comparison operator.
_QUALIFIED_COLUMN_COMPARISON_PATTERN = re.compile(
    r'(?:"[^"]+"|\w+)\.(?:"([^"]+)"|(\w+))\s*' + _COMPARISON_OPERATORS, re.IGNORECASE
)

# A function call and its argument list, used to reach field references that are
# not on the left of a comparison operator. Without this, `HAVING max(ssn) > '1'`
# yields no field name at all -- the token left of `>` is `)` -- so a hidden field
# can choose which rows come back while passing validation.
_FUNCTION_CALL_PATTERN = re.compile(r"\b(\w+)\s*\(([^()]*)\)")

# A bare word token, for pulling field names out of a function's arguments.
_WORD_PATTERN = re.compile(r"\w+")

# A quoted string literal, whose contents are values rather than field names.
_STRING_LITERAL_PATTERN = re.compile(r"'(?:[^']|'')*'")

_ORDER_BY_SUFFIX_PATTERN = re.compile(
    r"\s+(ASC|DESC)(\s+NULLS\s+(FIRST|LAST))?\s*$", re.IGNORECASE
)

# A field name safe to emit as a quoted SQL identifier: a letter or underscore
# followed by letters, digits, underscores, or dollars. Deliberately excludes the
# quote characters, dots, whitespace, and control characters, so a name that could
# alter the statement's structure is declined rather than escaped and hoped for.
_SAFE_IDENTIFIER_PATTERN = re.compile(r"^[^\W\d]\w*\$?[\w$]*$", re.UNICODE)

# Keywords that must never be mistaken for a field name during extraction.
_SQL_KEYWORDS = frozenset(
    word.upper()
    for word in (
        "SELECT FROM WHERE AND OR NOT IN IS NULL LIKE BETWEEN EXISTS HAVING ORDER BY "
        "GROUP ASC DESC LIMIT OFFSET UNION ALL DISTINCT AS ON JOIN LEFT RIGHT INNER "
        "OUTER CROSS FULL CASE WHEN THEN ELSE END CAST TRUE FALSE INSERT UPDATE DELETE "
        "SET VALUES INTO CREATE ALTER DROP TABLE INDEX WITH RECURSIVE OVER PARTITION "
        "ROW ROWS RANGE UNBOUNDED PRECEDING FOLLOWING CURRENT FETCH FIRST LAST NEXT "
        "ONLY NULLS FILTER WITHIN ARRAY ANY SOME EVERY ESCAPE ILIKE SIMILAR TO "
        # Type names, which appear as a bare word inside CAST(x AS type) and would
        # otherwise be extracted as a field and refused under an allow-list.
        "TEXT VARCHAR CHAR INT INTEGER BIGINT SMALLINT DECIMAL NUMERIC REAL DOUBLE "
        "PRECISION FLOAT BOOLEAN BOOL DATE TIME TIMESTAMP TIMESTAMPTZ INTERVAL JSON "
        "JSONB UUID BYTEA BLOB SERIAL ZONE VARYING UNSIGNED SIGNED"
    ).split()
)

# A condition that admits every row, for a filter that restricts nothing, and one
# that admits none, for a filter no row can satisfy. Neither is ever emitted in
# place of a condition that failed to build (spec section 4): a filter we could
# not render is declined and left to the post pass, never neutralised.
_ALWAYS_TRUE = "1 = 1"
_ALWAYS_FALSE = "1 = 0"

# Operators with no portable SQL form. `contains`/`startsWith` compare a value's
# string form regardless of declared type, and the SQL equivalent needs a cast
# whose spelling differs by engine ("AS TEXT" vs "AS CHAR") -- getting it wrong
# makes the query fail rather than over-return. `matches` has no portable regex
# operator at all (Postgres "~", MySQL "REGEXP", Trino "regexp_like") and its
# pattern dialect differs even where an operator exists.
_UNPUSHABLE_OPERATORS = frozenset(
    {FilterOperator.contains, FilterOperator.starts_with, FilterOperator.matches}
)


# -- Lightweight SQL structure scanning --


class _SqlScan:
    """A per-character map of a query's paren depth and literal spans.

    Restricts keyword matches to the outermost statement. Without this a subquery
    donates the match that governs the outer statement: the ``WHERE`` in
    ``SELECT * FROM t WHERE id IN (SELECT id FROM u WHERE x = 1)`` is found twice,
    and injecting into the wrong one filters the subquery while leaving the
    caller's result set unrestricted. String literals and quoted identifiers are
    skipped so a parenthesis, or the word ``where``, inside a literal changes
    nothing.
    """

    __slots__ = ("_query", "_depth", "_in_literal")

    def __init__(self, query: str) -> None:
        self._query = query
        length = len(query)
        self._depth = [0] * length
        self._in_literal = [False] * length

        depth = 0
        in_string = False
        in_quoted_identifier = False
        index = 0

        while index < length:
            char = query[index]

            if in_string:
                self._in_literal[index] = True
                self._depth[index] = depth
                if char == "'":
                    # '' is an escaped quote, not the end of the literal.
                    if index + 1 < length and query[index + 1] == "'":
                        index += 1
                        self._in_literal[index] = True
                        self._depth[index] = depth
                    else:
                        in_string = False
                index += 1
                continue

            if in_quoted_identifier:
                self._in_literal[index] = True
                self._depth[index] = depth
                if char == '"':
                    if index + 1 < length and query[index + 1] == '"':
                        index += 1
                        self._in_literal[index] = True
                        self._depth[index] = depth
                    else:
                        in_quoted_identifier = False
                index += 1
                continue

            if char == "'":
                in_string = True
                self._in_literal[index] = True
            elif char == '"':
                in_quoted_identifier = True
                self._in_literal[index] = True
            elif char == "(":
                depth += 1
            elif char == ")":
                # Guarded so an unbalanced query cannot drive the depth negative
                # and make an inner keyword look top-level.
                depth = max(0, depth - 1)

            self._depth[index] = depth
            index += 1

    def is_top_level(self, index: int) -> bool:
        """Whether the character at an offset is outside every paren and literal."""
        return 0 <= index < len(self._depth) and self._depth[index] == 0 and not self._in_literal[index]

    def first_top_level(self, pattern: re.Pattern[str], start_at: int = 0) -> re.Match[str] | None:
        """The first top-level match of a pattern at or after an offset."""
        if start_at >= len(self._query):
            return None
        for match in pattern.finditer(self._query, start_at):
            if self.is_top_level(match.start()):
                return match
        return None

    def last_top_level(self, pattern: re.Pattern[str]) -> re.Match[str] | None:
        """The last top-level match of a pattern."""
        found = None
        for match in pattern.finditer(self._query):
            if self.is_top_level(match.start()):
                found = match
        return found


# -- Identifiers and literals --


def _leaf_identifier(field_name: str, profile: _DialectProfile) -> str | None:
    """The unqualified, emit-safe form of a policy field reference, or None.

    The qualifier is stripped rather than emitted as ``"table"."column"``: TOLAP's
    own field matching already treats ``patients.region`` and ``region`` as the
    same field (spec section 4), and a qualifier naming the table would not
    resolve against a query that aliases it (``FROM patients p``). A bare column
    resolves under either spelling, and is ambiguous only in a join -- where the
    database reports the ambiguity rather than silently filtering the wrong column.

    A *wrapping* quote character is unwrapped first, in any engine's style, so a
    policy may spell a field as ``"region"``, ```region``` or ``[region]`` and
    still resolve: those characters are delimiters, not part of the name.

    What remains is then checked against the profile's **own** quote characters
    and declined if it contains one (connector spec section 5.1 rule 4). Declining
    costs an optimization; escaping by doubling would emit author-controlled text
    into the statement, and the doubling rule is not even the same in every engine.
    Anything else that is not a plain identifier -- a space, a dot, a control
    character -- is declined by the pattern for the same reason.
    """
    if not field_name or not field_name.strip():
        return None

    leaf = field_name.strip()
    if "." in leaf:
        leaf = leaf.rsplit(".", 1)[1]
    leaf = leaf.strip('"`[] ')

    if any(char in leaf for char in profile.quote_chars):
        _LOG.debug(
            "field name %r declined for the %s dialect: it contains that profile's own "
            "identifier quote character, which is never escaped by doubling",
            field_name,
            profile.dialect.value,
        )
        return None

    return leaf if _SAFE_IDENTIFIER_PATTERN.fullmatch(leaf) else None


def _quote(identifier: str, profile: _DialectProfile) -> str:
    """Quote an identifier already validated by :func:`_leaf_identifier`.

    Plain delimiting, with no escaping: :func:`_leaf_identifier` has already
    declined any name carrying the profile's quote character, so there is nothing
    here to escape. That is deliberate -- doubling the quote is exactly what
    connector spec section 5.1 rule 4 forbids, because a name that needs escaping
    is a name we should be refusing to emit.
    """
    return profile.quote_open + identifier + profile.quote_close


def _format_string_literal(value: str) -> str | None:
    """Render a string as a quoted literal, or None when it cannot be made safe.

    Doubling ``'`` is correct ANSI escaping but is *not sufficient on its own*:
    MySQL, by default, also treats ``\\`` as an escape inside a string literal, so
    ``'\\''`` leaves the literal open and the rest of the policy value becomes
    statement text. Rather than emit a dialect-conditional escape, a string
    containing a backslash is refused outright and the filter falls back to the
    post-fetch pass.

    **The refusal is uniform across every profile, including the ones where ``\\``
    is not an escape** (connector spec section 5.1 rule 5). Two reasons: a policy
    must behave identically on every engine, so a filter that is unpushable on
    MySQL must be unpushable on Postgres too; and a single profile treating ``\\``
    as an escape is enough to make escaping unsafe to generalize. The profile is
    deliberately not a parameter here.

    Control characters are refused for the same reason -- NUL truncates the
    statement for some client libraries, and a newline ends a ``--`` comment.
    """
    for char in value:
        if char == "\\" or (char.isprintable() is False and char not in ""):
            _LOG.debug(
                "string value refused as a SQL literal: it contains a backslash or a "
                "control character, which do not escape identically across engines; "
                "filter left to the post-fetch pass"
            )
            return None

    return "'" + value.replace("'", "''") + "'"


def _format_literal(value: Any) -> str | None:
    """Render a policy value as a SQL literal, or None when it has no safe form.

    Numbers are rendered with ``repr``/explicit formatting rather than a
    locale-sensitive conversion: under a locale whose decimal separator is a
    comma, a naive rendering of ``1.5`` becomes ``"1,5"``, which inside an ``IN``
    list silently becomes two values. Python's ``repr`` is locale-independent, but
    saying so explicitly keeps the guarantee from resting on that.
    """
    if value is None:
        return "NULL"

    # bool before int: bool is an int subclass, and TRUE is not 1 here.
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"

    if isinstance(value, str):
        return _format_string_literal(value)

    if isinstance(value, int):
        return repr(int(value))

    if isinstance(value, float):
        if not math.isfinite(value):
            _LOG.debug(
                "value %r has no SQL literal form; filter left to the post-fetch pass", value
            )
            return None
        return repr(value)

    if isinstance(value, Decimal):
        if not value.is_finite():
            _LOG.debug(
                "value %r has no SQL literal form; filter left to the post-fetch pass", value
            )
            return None
        return format(value, "f")

    # datetime before date: datetime is a date subclass.
    if isinstance(value, datetime):
        return "'" + value.strftime("%Y-%m-%d %H:%M:%S") + "'"

    if isinstance(value, date):
        return "'" + value.strftime("%Y-%m-%d") + "'"

    # A driver-specific or policy-specific type. Its str() form is not known to be
    # a valid literal in any dialect, so it is not guessed at.
    _LOG.debug(
        "value of type %s has no known SQL literal form; filter left to the post-fetch pass",
        type(value).__name__,
    )
    return None


# -- Row filter conditions --


def _compare(column: str, operator: str, value: Any) -> str | None:
    """Render a binary comparison, or None when the operand has no literal form."""
    if value is None:
        # Post-fetch, an ordering comparison against null is not satisfiable by
        # any row, so the SQL must select none either.
        return _ALWAYS_FALSE

    literal = _format_literal(value)
    if literal is None:
        return None
    return f"{column} {operator} {literal}"


def _build_in_condition(column: str, rf: RowFilter, *, negated: bool) -> str | None:
    """Render an ``IN``/``NOT IN`` condition from ``rf.values``.

    Mirrors the post-fetch pass exactly, including its degenerate cases: a null
    ``values`` array satisfies neither operator and admits no row, while an empty
    array admits no row for ``in`` and every row for ``notIn``. A list containing
    null is declined, because SQL's ``NOT IN (NULL, ...)`` is never true and would
    drop rows the post-fetch pass keeps.
    """
    values = rf.values

    if values is None:
        return _ALWAYS_FALSE

    if len(values) == 0:
        return _ALWAYS_TRUE if negated else _ALWAYS_FALSE

    literals: list[str] = []
    for value in values:
        if value is None:
            _LOG.debug(
                "row filter on %r not pushed into SQL: a null entry in values has no SQL IN "
                "equivalent; it is enforced after the fetch instead",
                rf.field,
            )
            return None
        literal = _format_literal(value)
        if literal is None:
            return None
        literals.append(literal)

    rendered = ", ".join(literals)
    if negated:
        # NOT IN drops a null-valued row; the post-fetch pass keeps it.
        return f"({column} NOT IN ({rendered}) OR {column} IS NULL)"
    return f"{column} IN ({rendered})"


def _build_like_condition(column: str, value: Any, *, negated: bool) -> str | None:
    """Render a ``LIKE``/``NOT LIKE`` condition.

    The pattern is already a SQL ``LIKE`` pattern, so it passes through as a
    literal with no wildcard translation. A pattern containing a backslash is
    declined by :func:`_format_string_literal`, because MySQL treats one as an
    escape inside a string literal by default while Postgres does not, so the same
    text would mean different things in the two engines.

    ``NOT LIKE`` needs no ``IS NULL`` arm: it and the post-fetch pass agree that a
    null-valued row is dropped.
    """
    if value is None:
        return _ALWAYS_FALSE

    literal = _format_literal(value)
    if literal is None:
        return None
    return f"{column} NOT LIKE {literal}" if negated else f"{column} LIKE {literal}"


def _build_between_condition(column: str, rf: RowFilter) -> str | None:
    """Render an inclusive ``BETWEEN`` from the first two entries of ``rf.values``.

    A malformed range is satisfiable by no row post-fetch, so it renders as a
    never-true condition rather than a neutral one -- emitting ``1=1`` for a
    filter that failed to build is the fail-open bug spec section 4 forbids.

    Bounds are emitted in the order written. An inverted range matches nothing, in
    SQL and post-fetch alike; silently reordering it would turn an author's typo
    into a wider grant than the policy states.
    """
    values = rf.values

    if values is None or len(values) < 2:
        _LOG.debug(
            "row filter on %r uses between with fewer than two bounds; no row can satisfy it",
            rf.field,
        )
        return _ALWAYS_FALSE

    if values[0] is None or values[1] is None:
        return _ALWAYS_FALSE

    low = _format_literal(values[0])
    high = _format_literal(values[1])
    if low is None or high is None:
        return None

    return f"{column} BETWEEN {low} AND {high}"


def build_condition(
    rf: RowFilter, *, dialect: SqlDialect | str | None = None
) -> str | None:
    """Render one row filter as a SQL condition, or None if it cannot be pushed.

    ``dialect`` names the engine the text is destined for; an omitted one selects
    :data:`DEFAULT_DIALECT` and an unrecognized one returns None, declining to
    push the filter at all (connector spec section 5.1). It affects only how the
    column is quoted -- which operators and values are pushable is identical under
    every profile.

    Every condition is built to mean exactly what
    :func:`tolap_core.enforcement.apply_row_filters` means, including where SQL's
    three-valued logic would otherwise differ. **The negative operators are the
    important case**: post-fetch, a field present with a null value satisfies
    ``notEquals 'x'`` and the row is kept, whereas plain SQL ``col <> 'x'``
    evaluates to NULL and drops it. An explicit ``OR col IS NULL`` keeps the two
    paths agreeing, so pushing a filter down never changes which rows the caller
    sees.

    Returns None -- leaving the filter to the post-fetch pass -- for a field name
    that is not a safe identifier, a value with no portable literal form, and the
    operators with no portable SQL form. That is the safe direction: an omitted
    condition costs transfer, never disclosure.
    """
    profile = _resolve_profile(dialect)
    if profile is None:
        return None

    leaf = _leaf_identifier(rf.field, profile)
    if leaf is None:
        _LOG.debug(
            "row filter on %r not pushed into SQL: the field name is not a plain identifier; "
            "it is enforced after the fetch instead",
            rf.field,
        )
        return None

    column = _quote(leaf, profile)
    op = rf.operator

    if op is FilterOperator.equals:
        # A null comparison value means "the field is null" post-fetch, but SQL
        # "col = NULL" is NULL for every row.
        if rf.value is None:
            return f"{column} IS NULL"
        return _compare(column, "=", rf.value)

    if op is FilterOperator.not_equals:
        if rf.value is None:
            return f"{column} IS NOT NULL"
        condition = _compare(column, "<>", rf.value)
        if condition is None:
            return None
        return f"({condition} OR {column} IS NULL)"

    if op is FilterOperator.greater_than:
        return _compare(column, ">", rf.value)
    if op is FilterOperator.greater_than_or_equal:
        return _compare(column, ">=", rf.value)
    if op is FilterOperator.less_than:
        return _compare(column, "<", rf.value)
    if op is FilterOperator.less_than_or_equal:
        return _compare(column, "<=", rf.value)

    if op is FilterOperator.in_:
        return _build_in_condition(column, rf, negated=False)
    if op is FilterOperator.not_in:
        return _build_in_condition(column, rf, negated=True)

    if op is FilterOperator.like:
        return _build_like_condition(column, rf.value, negated=False)
    if op is FilterOperator.not_like:
        return _build_like_condition(column, rf.value, negated=True)

    if op is FilterOperator.is_null:
        return f"{column} IS NULL"
    if op is FilterOperator.is_not_null:
        return f"{column} IS NOT NULL"

    if op is FilterOperator.between:
        return _build_between_condition(column, rf)

    if op in _UNPUSHABLE_OPERATORS:
        _LOG.debug(
            "row filter on %r with operator %s has no portable SQL form; it is enforced "
            "after the fetch instead",
            rf.field,
            op.value,
        )
        return None

    # An operator from a newer schema version. Declining to push it leaves
    # enforcement with the post-fetch pass, which fails closed on an operator it
    # does not recognise.
    _LOG.debug(
        "row filter on %r uses unrecognized operator %r; it is enforced after the fetch instead",
        rf.field,
        op,
    )
    return None


def build_where_clause(
    filters: list[RowFilter], *, dialect: SqlDialect | str | None = None
) -> str:
    """Build a ``WHERE`` clause body (without the keyword) from row filters.

    Conditions are combined with ``AND``, matching the most-restrictive-wins
    semantics of the post-fetch pass. Filters with no portable SQL form are
    omitted; use :func:`unpushable_filters` to enumerate them. Returns the empty
    string when no filter could be expressed -- including for an unrecognized
    ``dialect``, which declines every filter.
    """
    conditions = [
        condition
        for rf in filters
        if (condition := build_condition(rf, dialect=dialect)) is not None
    ]
    return " AND ".join(conditions)


def unpushable_filters(
    policy: EffectivePolicy, *, dialect: SqlDialect | str | None = None
) -> list[RowFilter]:
    """The policy's row filters that cannot be pushed into SQL.

    Exposed so an integrator can assert this is empty for a policy whose filtering
    must happen entirely in the database -- a non-empty result means the query will
    return rows that the post-fetch pipeline still has to discard.

    An unrecognized ``dialect`` reports **every** filter, since nothing is
    rewritten at all in that case (connector spec section 5.1 rule 2).
    """
    if not policy.object_rules or not policy.object_rules.row_filters:
        return []
    return [
        rf
        for rf in policy.object_rules.row_filters
        if build_condition(rf, dialect=dialect) is None
    ]


# -- Select-list rewriting --


def _find_select_list_span(query: str) -> tuple[int, int] | None:
    """The offset and length of the statement's select list.

    Everything between the top-level ``SELECT`` and the top-level ``FROM``, with
    surrounding whitespace excluded so a replacement need not reproduce it.
    """
    scan = _SqlScan(query)

    select = scan.first_top_level(_SELECT_KEYWORD)
    if select is None:
        return None

    list_start = select.end()
    from_match = scan.first_top_level(_FROM_KEYWORD, list_start)
    if from_match is None:
        return None

    start = list_start
    while start < from_match.start() and query[start].isspace():
        start += 1

    end = from_match.start()
    while end > start and query[end - 1].isspace():
        end -= 1

    return None if end <= start else (start, end - start)


def _split_top_level(entries: str) -> list[str]:
    """Split a comma-separated list on commas at paren depth zero.

    A function call's own arguments must not be split apart.
    """
    scan = _SqlScan(entries)
    result: list[str] = []
    current: list[str] = []

    for index, char in enumerate(entries):
        if char == "," and scan.is_top_level(index):
            result.append("".join(current).strip())
            current = []
            continue
        current.append(char)

    if current:
        result.append("".join(current).strip())

    return result


def _extract_field_name(expression: str) -> str:
    """The field name a select-list or clause entry refers to.

    Alias and table qualifier removed, quotes stripped. A call expression is
    returned whole: splitting it on its last dot yields a fragment rather than a
    field name -- ``round(1.5)`` would become ``5)``, which matches no policy field
    and made :func:`validate_query` refuse an ordinary query. Fields inside a call
    are reached by :func:`_add_fields_from_function_arguments` instead.
    """
    expr = expression.strip()

    lowered = expr.lower()
    as_index = lowered.find(" as ")
    if as_index > 0:
        expr = expr[:as_index].strip()

    if "(" in expr:
        return expr

    if "." in expr:
        dot_index = expr.rfind(".")
        if dot_index > 0:
            expr = expr[dot_index + 1 :].strip()

    return expr.strip("\"'` ")


def _expand_select_star(
    allowed: list[str] | None, hidden: list[str] | None, profile: _DialectProfile
) -> str | None:
    """The explicit field list replacing ``*``, or None when it cannot be built.

    **Requires ``allowedFields``.** Without it the set of columns the table
    actually has is unknown, so hidden fields cannot be subtracted from ``*``
    without schema access the SDK deliberately does not assume.

    In that case ``*`` is left alone and the post-fetch
    :func:`tolap_core.enforcement.strip_hidden_fields` removes the hidden columns
    after the fetch. **The disclosure outcome is identical; the transfer cost is
    not.** This is a real and deliberate limitation: a policy that only lists
    hidden fields gets no projection pushdown at all. a prior implementation returned the query
    unchanged here *and* had no post-fetch pass to fall back on, which made the
    same code path an outright leak; here it is only a missed optimization.
    """
    if allowed is None:
        _LOG.debug(
            "SELECT * with hiddenFields but no allowedFields: the table's column list is "
            "unknown, so hidden columns are removed after the fetch instead"
        )
        return None

    # A glob cannot be emitted as an identifier, and dropping the entries it
    # stands for would narrow the projection below what the policy grants.
    if any("*" in entry for entry in allowed):
        _LOG.debug(
            "SELECT * not expanded: allowedFields contains a wildcard pattern, which has no "
            "column list to expand to"
        )
        return None

    columns: list[str] = []
    seen: set[str] = set()
    for entry in allowed:
        if hidden is not None and any(_field_name_matches(h, entry) for h in hidden):
            continue
        leaf = _leaf_identifier(entry, profile)
        if leaf is None or leaf.lower() in seen:
            continue
        seen.add(leaf.lower())
        columns.append(leaf)

    if not columns:
        # No field is permitted. Selecting a constant keeps the statement valid
        # and matches the post-fetch outcome, where projecting to an empty
        # allow-list leaves each surviving row with no fields.
        _LOG.debug("no field permitted after filtering; projecting a constant")
        return "1"

    return ", ".join(_quote(column, profile) for column in columns)


def _filter_select_list(
    select_list: str, allowed: list[str] | None, hidden: list[str] | None
) -> str | None:
    """Remove hidden and non-allowed entries from an explicit select list.

    Returns None when the list should be left alone (nothing was removed).

    **Masked fields are deliberately not removed.** Masking happens after the
    fetch, so a masked column must survive into the executed query or there is
    nothing left to mask and the field silently disappears from the result instead
    of appearing masked.
    """
    entries = _split_top_level(select_list)
    kept: list[str] = []

    for entry in entries:
        name = _extract_field_name(entry)

        if hidden is not None and any(_field_name_matches(h, name) for h in hidden):
            _LOG.debug("removing hidden field from select list: %s", name)
            continue

        if allowed is not None and not any(_field_name_matches(a, name) for a in allowed):
            _LOG.debug("removing non-allowed field from select list: %s", name)
            continue

        kept.append(entry.strip())

    if len(kept) == len(entries):
        return None

    if not kept:
        _LOG.debug("every selected field was removed; projecting a constant")
        return "1"

    return ", ".join(kept)


def _rewrite_select_list(
    query: str, policy: EffectivePolicy, profile: _DialectProfile
) -> str:
    """Expand ``SELECT *`` or strip hidden/non-allowed fields from the select list."""
    field_rules = None
    if policy.object_rules and policy.object_rules.field_rules:
        field_rules = policy.object_rules.field_rules
    allowed = field_rules.allowed_fields if field_rules else None
    hidden = field_rules.hidden_fields if field_rules else None

    # Nothing to do: an absent allow-list is unrestricted and there is nothing to
    # hide. Tested against None, not emptiness -- an empty allow-list denies every
    # field (spec section 3).
    if allowed is None and not hidden:
        return query

    span = _find_select_list_span(query)
    if span is None:
        _LOG.debug("select list not located; leaving the projection to the post-fetch pass")
        return query

    start, length = span
    select_list = query[start : start + length]

    if select_list.strip() == "*":
        replacement = _expand_select_star(allowed, hidden, profile)
    else:
        replacement = _filter_select_list(select_list, allowed, hidden)

    if replacement is None:
        return query

    return query[:start] + replacement + query[start + length :]


# -- WHERE injection --


def _find_where_insert_point(query: str, scan: _SqlScan) -> int:
    """The offset at which a fresh ``WHERE`` clause belongs.

    The **earliest** top-level clause that must follow ``WHERE``, or the end of
    the statement with any trailing semicolon and whitespace excluded. Taking the
    earliest rather than the first pattern to match is what keeps
    ``GROUP BY x ORDER BY y`` from producing the syntactically invalid
    ``GROUP BY x WHERE ... ORDER BY y`` -- A prior implementation iterated a fixed pattern list and
    emitted exactly that.
    """
    earliest = None
    for pattern in _POST_FROM_CLAUSES:
        match = scan.first_top_level(pattern)
        if match is not None and (earliest is None or match.start() < earliest):
            earliest = match.start()

    if earliest is not None:
        # Back up over the whitespace before the clause. The injected text carries
        # its own leading space, so inserting at the clause's own offset would
        # strand the original separator on the left and leave none on the right.
        while earliest > 0 and query[earliest - 1].isspace():
            earliest -= 1
        return earliest

    return len(query.rstrip().rstrip(";").rstrip())


def _inject_row_filters(
    query: str, policy: EffectivePolicy, profile: _DialectProfile
) -> str:
    """Inject the policy's row filters as a ``WHERE`` condition."""
    if not policy.object_rules or not policy.object_rules.row_filters:
        return query

    clause = build_where_clause(policy.object_rules.row_filters, dialect=profile.dialect)
    if not clause:
        return query

    scan = _SqlScan(query)

    existing = scan.first_top_level(_WHERE_KEYWORD)
    if existing is not None:
        # The original WHERE body ends at the next top-level clause, not at the end
        # of the statement. Taking the rest of the text would pull ORDER BY/GROUP
        # BY/LIMIT inside the parentheses added below and emit invalid SQL.
        body_start = existing.end()
        body_end = len(query.rstrip().rstrip(";").rstrip())
        for pattern in _POST_FROM_CLAUSES:
            match = scan.first_top_level(pattern, body_start)
            if match is not None and match.start() < body_end:
                body_end = match.start()

        # Parenthesise BOTH sides. The injected conditions must be grouped so an
        # existing OR cannot widen them, and the original must be grouped too:
        # "WHERE (filters) AND a OR b" binds as "((filters) AND a) OR b" and
        # admits every row matching b. a prior implementation parenthesised only the injected half.
        # Back up over the whitespace so the tail keeps its own separator; the
        # parenthesised body is stripped, so otherwise ") ORDER BY" would run
        # together as ")ORDER BY".
        while body_end > body_start and query[body_end - 1].isspace():
            body_end -= 1

        original = query[body_start:body_end].strip()
        return (
            f"{query[: existing.start()]}WHERE ({clause}) AND ({original})"
            + query[body_end:]
        )

    insert_at = _find_where_insert_point(query, scan)
    return query[:insert_at] + f" WHERE {clause}" + query[insert_at:]


# -- Row-limit clamping --


def _clamp_limit_suffix(query: str, max_results: int) -> str:
    """Clamp or append a trailing ``LIMIT n``."""
    scan = _SqlScan(query)

    # The statement's own LIMIT is the last one at top level; an earlier top-level
    # LIMIT belongs to a set operand ("... UNION SELECT ... LIMIT 5"), and clamping
    # that would alter which rows the operand contributes rather than how many the
    # caller receives.
    match = scan.last_top_level(_LIMIT_CLAUSE)
    if match is None:
        trimmed = query.rstrip()
        had_semicolon = trimmed.endswith(";")
        body = trimmed[:-1].rstrip() if had_semicolon else trimmed
        return f"{body} LIMIT {max_results}" + (";" if had_semicolon else "")

    existing = int(match.group(1))
    effective = min(existing, max_results)
    return query[: match.start()] + f"LIMIT {effective}" + query[match.end() :]


def _clamp_limit_top(query: str, max_results: int) -> str:
    """Clamp or insert a ``TOP n``, or return the query unchanged.

    ``TOP n`` is **not a token swap for ``LIMIT n``**: it sits immediately after
    ``SELECT`` (and after ``DISTINCT``/``ALL``), not at the end of the statement,
    and it binds to one ``SELECT`` rather than to the statement's final result. So
    this is a structural placement, and where it cannot be placed *correctly* the
    limit is simply **not pushed** -- never rendered as ``LIMIT n`` instead
    (connector spec section 5.1 rule 3). An unpushed limit costs a transfer that
    :func:`tolap_core.enforcement.apply_result_limit` then trims; a misplaced or
    mis-spelled one is a broken statement or a wrong row count.

    Declined shapes, each for a reason that is not a parser limitation:

    - **A top-level set operation.** In ``SELECT ... UNION SELECT ...``, a ``TOP``
      on the first operand limits that operand, not the union, so the caller would
      receive more rows than the policy allows.
    - **``OFFSET``/``FETCH``.** T-SQL rejects ``TOP`` combined with
      ``OFFSET ... FETCH`` outright.
    - **An existing ``TOP n PERCENT`` or ``WITH TIES``.** A percentage is not a row
      count, and ``WITH TIES`` returns more rows than the number given.
    - **An existing top-level ``LIMIT``.** The statement is already not valid
      T-SQL; clamping around a clause this profile does not emit would be guessing
      at what the caller meant.
    """
    scan = _SqlScan(query)

    for pattern, reason in (
        (_UNION_KEYWORD, "a top-level set operation, where TOP would bind to one operand"),
        (_INTERSECT_KEYWORD, "a top-level set operation, where TOP would bind to one operand"),
        (_EXCEPT_KEYWORD, "a top-level set operation, where TOP would bind to one operand"),
        (_OFFSET_KEYWORD, "an OFFSET clause, which T-SQL forbids alongside TOP"),
        (_FETCH_KEYWORD, "a FETCH clause, which T-SQL forbids alongside TOP"),
        (_LIMIT_KEYWORD, "a LIMIT clause, which is not valid T-SQL to begin with"),
    ):
        if scan.first_top_level(pattern) is not None:
            _LOG.debug(
                "row limit not pushed as TOP: the statement contains %s; "
                "apply_result_limit truncates the result instead",
                reason,
            )
            return query

    select = scan.first_top_level(_SELECT_KEYWORD)
    if select is None:
        _LOG.debug(
            "row limit not pushed as TOP: no top-level SELECT to place it after; "
            "apply_result_limit truncates the result instead"
        )
        return query

    existing_top = _TOP_CLAUSE.match(query, select.end())
    if existing_top is not None:
        if existing_top.group("modifier"):
            _LOG.debug(
                "row limit not pushed as TOP: the statement already uses TOP ... %s, "
                "which is not a plain row count; apply_result_limit truncates the result "
                "instead",
                existing_top.group("modifier").strip(),
            )
            return query
        written = existing_top.group("count") or existing_top.group("paren_count")
        effective = min(int(written), max_results)
        return (
            query[: existing_top.start()]
            + f" TOP {effective}"
            + query[existing_top.end() :]
        )

    # DISTINCT and ALL bind to the SELECT, so TOP goes after them: "SELECT DISTINCT
    # TOP 5" is a syntax error where "SELECT TOP 5 DISTINCT" changes which rows are
    # counted -- TOP would apply before duplicates are removed.
    insert_at = select.end()
    quantifier = _SELECT_QUANTIFIER.match(query, insert_at)
    if quantifier is not None:
        insert_at = quantifier.end()

    return query[:insert_at] + f" TOP {max_results}" + query[insert_at:]


def _clamp_limit(query: str, policy: EffectivePolicy, profile: _DialectProfile) -> str:
    """Push ``maxResults`` into the statement's row limit, in the profile's form."""
    if not policy.limits or policy.limits.max_results is None:
        return query

    max_results = policy.limits.max_results
    if max_results < 0:
        _LOG.debug(
            "negative maxResults (%d) is not a row limit; leaving the query alone",
            max_results,
        )
        return query

    if profile.row_limit == _TOP_PREFIX:
        return _clamp_limit_top(query, max_results)
    return _clamp_limit_suffix(query, max_results)


# -- Public API --


def rewrite_query(
    query: str, policy: EffectivePolicy, *, dialect: SqlDialect | str | None = None
) -> str:
    """Rewrite a SQL query to push a policy's restrictions into the database.

    Applies, in order: ``SELECT *`` expansion to allowed-minus-hidden fields;
    removal of hidden and non-allowed fields from an explicit select list;
    injection of row filters as ``WHERE`` conditions; and clamping of the row limit
    to ``min(existing, maxResults)`` in the profile's own form. Masked fields are
    preserved so the post-fetch pass can still mask them.

    ``dialect`` names the engine the text is destined for (connector spec section
    5.1). An omitted one selects :data:`DEFAULT_DIALECT`; an **unrecognized** one
    returns the query untouched rather than guessing a profile.

    A null, empty, or whitespace query is returned unchanged. **The post-execution
    pipeline still MUST run on the results** (spec section 4); this only reduces
    what the database produces.
    """
    if not query or not query.strip():
        return query

    profile = _resolve_profile(dialect)
    if profile is None:
        return query

    rewritten = query.strip()
    rewritten = _rewrite_select_list(rewritten, policy, profile)
    rewritten = _inject_row_filters(rewritten, policy, profile)
    rewritten = _clamp_limit(rewritten, policy, profile)

    _LOG.debug(
        "query rewritten for the %s dialect from %r to %r",
        profile.dialect.value,
        _truncate_for_log(query),
        _truncate_for_log(rewritten),
    )
    return rewritten


_WHITESPACE_RUN = re.compile(r"\s+")


def _truncate_for_log(value: str, max_length: int = 200) -> str:
    """Collapse whitespace and truncate a query for a single-line log record.

    Newlines are collapsed *before* truncating: a log backend that splits on ``\\n``
    turns every line of a multi-line statement into its own record with its own
    timestamp, so "query rewritten from ... to ..." becomes a dozen unrelated
    events per call.
    """
    if not value:
        return value
    one_line = _WHITESPACE_RUN.sub(" ", value).strip()
    return one_line if len(one_line) <= max_length else one_line[:max_length] + "..."


def _add_fields_from_function_arguments(body: str, fields: set[str]) -> None:
    """Add the field names appearing inside a function call's argument list.

    A field wrapped in an aggregate is not on the left of any comparison operator,
    so the comparison patterns never see it: ``HAVING max(ssn) > '1'`` presents
    ``)`` as the left operand. Left unextracted, a hidden field can be used to
    choose which rows are returned -- the aggregate's value is disclosed by the row
    set even though the field is absent from the projection. A prior implementation had this bug.

    String literals are removed first so a value is not mistaken for a field name.
    """
    without_literals = _STRING_LITERAL_PATTERN.sub(" ", body)

    for call in _FUNCTION_CALL_PATTERN.finditer(without_literals):
        for word in _WORD_PATTERN.finditer(call.group(2)):
            name = word.group(0)
            # A numeric argument is a literal, not a field.
            if name.upper() not in _SQL_KEYWORDS and not name[0].isdigit():
                fields.add(name)


def _add_fields_from_condition_clause(
    query: str, clause_pattern: re.Pattern[str], fields: set[str]
) -> None:
    """Add field names on the left of a comparison in a WHERE or HAVING clause."""
    clause_match = clause_pattern.search(query)
    if clause_match is None:
        return

    body = clause_match.group(1)

    for match in _QUALIFIED_COLUMN_COMPARISON_PATTERN.finditer(body):
        name = match.group(1) or match.group(2) or ""
        if name and name.upper() not in _SQL_KEYWORDS:
            fields.add(name)

    for match in _COLUMN_COMPARISON_PATTERN.finditer(body):
        name = match.group(1)
        if name.upper() not in _SQL_KEYWORDS:
            fields.add(name)

    _add_fields_from_function_arguments(body, fields)


def _add_fields_from_order_by(query: str, fields: set[str]) -> None:
    """Add ORDER BY field names, discarding ASC/DESC and NULLS suffixes."""
    clause_match = _ORDER_BY_CLAUSE_PATTERN.search(query)
    if clause_match is None:
        return

    for part in clause_match.group(1).split(","):
        trimmed = _ORDER_BY_SUFFIX_PATTERN.sub("", part.strip()).strip()
        if not trimmed:
            continue
        name = _extract_field_name(trimmed)
        if name and name.upper() not in _SQL_KEYWORDS:
            fields.add(name)


def _add_fields_from_comma_separated_clause(
    query: str, clause_pattern: re.Pattern[str], fields: set[str]
) -> None:
    """Add field names from a comma-separated clause of plain references."""
    clause_match = clause_pattern.search(query)
    if clause_match is None:
        return

    for part in clause_match.group(1).split(","):
        trimmed = part.strip()
        if not trimmed:
            continue
        name = _extract_field_name(trimmed)
        if name and name.upper() not in _SQL_KEYWORDS:
            fields.add(name)


def extract_referenced_fields(query: str) -> set[str]:
    """Every field name a query mentions in SELECT, WHERE, ORDER BY, GROUP BY, HAVING.

    Regex-based, so the result is a best effort: it is used to *refuse* a query,
    and a name it misses is still caught by the post-fetch pass.
    """
    fields: set[str] = set()

    span = _find_select_list_span(query)
    if span is not None:
        start, length = span
        select_list = query[start : start + length]
        for entry in _split_top_level(select_list):
            fields.add(_extract_field_name(entry))
        # A field wrapped in an aggregate would otherwise be extracted as the
        # whole expression ("max(ssn)"), which matches no policy field and is then
        # skipped by the allow-list check for containing a parenthesis.
        _add_fields_from_function_arguments(select_list, fields)

    _add_fields_from_condition_clause(query, _WHERE_CLAUSE_PATTERN, fields)
    _add_fields_from_order_by(query, fields)
    _add_fields_from_comma_separated_clause(query, _GROUP_BY_CLAUSE_PATTERN, fields)
    _add_fields_from_condition_clause(query, _HAVING_CLAUSE_PATTERN, fields)

    return fields


def validate_query(query: str, policy: EffectivePolicy) -> bool:
    """Whether a query references only fields the policy permits.

    A pre-execution check intended to reject a query outright rather than silently
    narrow it, so an agent learns its query was refused. Returns False for an
    empty query, for any reference to a hidden field, and -- when ``allowedFields``
    is specified -- for any reference outside it.

    Because field extraction is regex-based, **a False result is authoritative but
    a True result is not a guarantee**: the post-fetch pass, not this function, is
    what makes hidden fields unreachable.
    """
    if not query or not query.strip():
        return False

    field_rules = None
    if policy.object_rules and policy.object_rules.field_rules:
        field_rules = policy.object_rules.field_rules
    hidden = field_rules.hidden_fields if field_rules else None
    allowed = field_rules.allowed_fields if field_rules else None

    referenced = extract_referenced_fields(query)

    if hidden:
        for name in referenced:
            if any(_field_name_matches(h, name) for h in hidden):
                _LOG.debug("query references hidden field: %s", name)
                return False

    # Tested for None, not for emptiness: an empty allow-list denies every field
    # (spec section 3), so treating it as "no restriction" would invert the rule.
    if allowed is not None:
        for name in referenced:
            # A wildcard discloses nothing by itself and an aggregate has no
            # single field name; both are settled by the post-fetch projection.
            if name == "*" or "(" in name:
                continue
            if not any(_field_name_matches(a, name) for a in allowed):
                _LOG.debug("query references non-allowed field: %s", name)
                return False

    return True


def extract_table_name(query: str) -> str | None:
    """The primary table name from a query's ``FROM`` clause, or None.

    Handles bare (``patients``), qualified (``public.patients``), and quoted
    (``"schema"."table"``) forms, returning the unqualified table name so it can
    be passed to :func:`tolap_core.enforcement.validate_access`.
    """
    if not query or not query.strip():
        return None

    match = _FROM_TABLE_PATTERN.search(query)
    if match is None:
        return None

    reference = match.group(1)

    # "schema"."table": split on the quote-dot-quote seam so a dot inside either
    # identifier is not mistaken for the separator.
    if '"."' in reference:
        return reference.split('"."')[-1].strip("\"' ")

    name = reference.strip("\"' ")

    # schema.table, including the "schema.table" form where the whole dotted name
    # was written inside one pair of quotes.
    if "." in name:
        return name.split(".")[-1]

    return name


@dataclass
class SqlQueryPreparation:
    """The outcome of preparing a SQL query for execution under a policy.

    ``query`` is the text to execute. When ``allowed`` is False it is the caller's
    original and MUST NOT be executed.
    """

    allowed: bool
    query: str
    denial_reason: str | None = None
    rewritten: bool = False
    unpushable_filters: list[RowFilter] = dataclass_field(default_factory=list)

    @property
    def fully_pushed_down(self) -> bool:
        """Whether every row filter in the policy reached the database.

        Useful as an assertion for an integrator whose result sets are large enough
        that post-fetch filtering is not an acceptable fallback. False means the
        database will return rows the post-fetch pipeline still has to discard.
        """
        return not self.unpushable_filters

    @classmethod
    def denied(cls, reason: str, query: str) -> SqlQueryPreparation:
        return cls(allowed=False, query=query, denial_reason=reason)


def prepare_sql_query(
    query: str,
    policy: EffectivePolicy,
    *,
    object_name: str | None = None,
    dialect: SqlDialect | str | None = None,
) -> SqlQueryPreparation:
    """Run the pre-execution checks and rewrite a query for execution.

    Combines the four steps an integrator needs in order:

    1. Refuse an empty query and a policy that cannot query at all.
    2. Check the target object against ``allowedObjects``/``hiddenObjects``. The
       name comes from the query's own ``FROM`` clause when ``object_name`` is not
       given, so the rule applies to the table the query actually reads.
    3. Refuse a query referencing a hidden or non-allowed field, rather than
       silently narrowing it.
    4. Rewrite what remains, reporting the filters that could not be pushed.

    ``dialect`` names the engine, and is the integrator's to supply: pass
    ``SqlDialect.mysql`` alongside a ``pymysql`` connection and
    ``SqlDialect.postgres`` alongside a ``psycopg`` one. An omitted dialect selects
    :data:`DEFAULT_DIALECT`; an unrecognized one skips rewriting entirely and
    reports every filter in :attr:`SqlQueryPreparation.unpushable_filters`. The
    pre-execution *checks* above run either way -- declining to rewrite never
    relaxes a denial.

    **The post-execution pipeline still MUST run on the results.** This function
    reduces what the database produces; it is not the enforcement boundary
    (spec section 4). Typical use::

        prep = prepare_sql_query(sql, policy, dialect=SqlDialect.mysql)
        if not prep.allowed:
            raise PermissionError(prep.denial_reason)
        rows = cursor.execute(prep.query).fetchall()
        rows = apply_result_pipeline(rows, policy)   # still mandatory

    A caveat worth pinning: a pushed-down filter on a field the query does not
    project returns **zero** rows. The database filters correctly, then the
    post-fetch pass drops every row because the field is absent from the result
    (spec section 7 fails closed on a missing field). That is fail-closed rather
    than a disclosure, but it surprises, so check
    :attr:`SqlQueryPreparation.unpushable_filters` and the projection together.
    """
    # Imported here rather than at module scope: enforcement imports nothing from
    # this module, and keeping the dependency one-directional at import time avoids
    # a cycle if that ever changes.
    from tolap_core.enforcement import validate_access

    if not query or not query.strip():
        return SqlQueryPreparation.denied("query is empty", query)

    if not policy.permissions.can_query:
        return SqlQueryPreparation.denied("query not permitted", query)

    target = object_name if object_name is not None else extract_table_name(query)
    if target is not None:
        access = validate_access(target, policy)
        if not access.allowed:
            return SqlQueryPreparation.denied(access.reason or "access denied", query)

    if not validate_query(query, policy):
        return SqlQueryPreparation.denied(
            "query references fields you do not have permission to access", query
        )

    rewritten = rewrite_query(query, policy, dialect=dialect)

    return SqlQueryPreparation(
        allowed=True,
        query=rewritten,
        denial_reason=None,
        rewritten=rewritten != query,
        unpushable_filters=unpushable_filters(policy, dialect=dialect),
    )
