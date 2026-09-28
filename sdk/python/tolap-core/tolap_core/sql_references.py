"""Validate every table and column a SQL query references, before it runs.

:func:`validate_query_references` is one of the pre-execution checks
:func:`tolap_core.sql_rewriter.prepare_sql_query` runs. It resolves the tables a
query reads -- ``FROM`` and ``JOIN`` items, comma-joined tables and derived
tables -- into an alias map, checks each table with
:func:`tolap_core.enforcement.validate_access`, and resolves each column
reference through that map so the field rules apply to the table the column
actually belongs to.

The check is deliberately conservative. It does not parse SQL in general; it
recognises a common subset of ``SELECT`` and refuses, with a reason, any
construct it cannot resolve (common table expressions, set operations,
subqueries outside ``FROM``, ``LATERAL``, table-valued functions and so on).
Refusing is the safe answer: a construct the check cannot see into is one whose
tables it cannot vouch for.

A query that reads exactly one table still goes through the existing single-table
checks (the object check and :func:`tolap_core.sql_rewriter.validate_query`). This
check adds to them: it validates that table's access and checks every column the
query references, so it can refuse a query they allow but never allow one they refuse.

Lexing differs between engines: a backslash escapes a quote in MySQL but not in
standard SQL, ``#`` starts a comment only in MySQL, and block comments nest only
in PostgreSQL. So the query is tokenized under each of those conventions and
must pass under every one of them. A query whose meaning depends on the engine
is therefore allowed only if it is allowed whichever way the engine reads it.

The TypeScript (``sql-references.ts``) and .NET (``SqlQueryReferences.cs``)
counterparts implement the same rules, pinned by
``fixtures/enforcement/sql-multi-table.json``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from tolap_core.enforcement import (
    AccessResult,
    _allowed_field_matches,
    _field_name_matches,
    validate_access,
)
from tolap_core.models import EffectivePolicy

FIELD_DENIAL_REASON = "query references fields you do not have permission to access"
"""The reason given when a column reference is refused, shared with ``validate_query``."""

UNSUPPORTED_REASON_PREFIX = "query uses a construct the pre-execution check cannot resolve: "
"""Prefix of the reason given when the query uses a construct the check refuses."""

OBJECT_MISMATCH_REASON = "object name does not match the table the query reads"
"""The reason given when a supplied object name and the query's one table differ."""

# Derived tables nest; each level recurses once. Real queries stay far below this.
_MAX_NESTING = 32

_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
# Keywords are ASCII to every engine, so words are upper-cased ASCII-only: a
# Unicode case mapping would read "\u017felect" (long s) as SELECT.
_ASCII_UPPER = str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")

_WHITESPACE = frozenset(" \t\n\r\f\v")

# Unicode whitespace some engines accept as a separator. Treating one as part of a
# word would hide a keyword, so its presence outside a literal is refused.
_UNICODE_SPACES = frozenset(
    "\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008"
    "\u2009\u200a\u200b\u2028\u2029\u202f\u205f\u3000\ufeff"
)

_MODES = ("ansi", "mysql", "postgres")

# Words never taken for a column when bare. Deliberately narrow: an unrecognised
# word is checked as a column, which can refuse a query but never admits one.
_KEYWORDS = frozenset(
    (
        "ALL AND ANY ARRAY AS ASC AT BETWEEN BOTH BY CASE CAST COLLATE CROSS CURRENT "
        "CURRENT_CATALOG CURRENT_DATE CURRENT_ROLE CURRENT_SCHEMA CURRENT_TIME "
        "CURRENT_TIMESTAMP CURRENT_USER DEFAULT DESC DISTINCT DIV ELSE END ESCAPE "
        "EVERY EXCLUDE EXISTS FALSE FETCH FILTER FIRST FOLLOWING FROM FULL GLOB "
        "GROUP GROUPS HAVING ILIKE IN INNER INTERVAL IS ISNULL JOIN LAST LEADING "
        "LEFT LIKE LIMIT LOCALTIME LOCALTIMESTAMP MOD NATURAL NEXT NO NOT NOTNULL "
        "NULL NULLS OFFSET ON ONLY OR ORDER ORDINALITY OTHERS OUTER OVER PARTITION "
        "PRECEDING PRECISION RANGE REGEXP RLIKE ROW ROWS SELECT SEPARATOR "
        "SESSION_USER SIGNED SIMILAR SOME TABLE THEN TIES TO TRAILING TRUE UNBOUNDED "
        "UNKNOWN UNSIGNED USING VALUES VARYING WHEN WHERE WITH WITHIN WITHOUT XOR ZONE "
        "ROLLUP CUBE SETS"
    ).split()
)

# Units that may follow INTERVAL or precede FROM inside EXTRACT(...).
_DATE_PARTS = frozenset(
    (
        "CENTURY DAY DAYS DECADE DOW DOY EPOCH HOUR HOURS ISODOW ISOYEAR JULIAN "
        "MICROSECOND MICROSECONDS MILLENNIUM MILLISECOND MILLISECONDS MINUTE MINUTES "
        "MONTH MONTHS QUARTER SECOND SECONDS TIMEZONE TIMEZONE_HOUR TIMEZONE_MINUTE "
        "WEEK WEEKS YEAR YEARS"
    ).split()
)

# Reserved words that end the FROM clause and start another clause.
_TAIL_CLAUSES = frozenset(
    "WHERE GROUP HAVING ORDER LIMIT OFFSET FETCH FOR WINDOW WITH".split()
)

# Tail clauses whose content is read for column references, and those skipped.
_CHECKED_TAIL = frozenset(("WHERE", "GROUP", "HAVING", "ORDER"))
_SKIPPED_TAIL = frozenset(("LIMIT", "OFFSET", "FETCH", "FOR"))

# The words a skipped tail clause may hold: LIMIT ALL, OFFSET 5 ROWS, FETCH FIRST 5
# ROWS WITH TIES, FOR NO KEY UPDATE SKIP LOCKED, LOCK IN SHARE MODE. Anything else
# means a column was taken for the clause keyword (MySQL's WHERE offset = 7), so the
# clause is refused rather than left unread.
_SKIPPED_TAIL_WORDS = frozenset(
    (
        "ALL FIRST NEXT ROW ROWS ONLY WITH TIES PERCENT UPDATE SHARE NO KEY NOWAIT "
        "SKIP LOCKED LOCK IN MODE"
    ).split()
)

_JOIN_WORDS = frozenset(
    ("JOIN", "INNER", "LEFT", "RIGHT", "FULL", "CROSS", "NATURAL", "OUTER", "STRAIGHT_JOIN")
)

# Words refused as a table alias. Beyond the join and clause words these are the
# engine-specific table modifiers (hints, sampling, pivots, partitions); taking
# one for an alias would let what follows it go unread, so it is refused instead.
_NOT_AN_ALIAS = (
    _JOIN_WORDS
    | _TAIL_CLAUSES
    | frozenset(
        (
            "ON USING AS APPLY LATERAL USE FORCE IGNORE PARTITION QUALIFY CONNECT "
            "START LOCK PIVOT UNPIVOT MODEL SAMPLE TABLESAMPLE RETURNING OPTION "
            "PROCEDURE INTO UNION INTERSECT EXCEPT MINUS"
        ).split()
    )
)

_SET_OPERATIONS = frozenset(("UNION", "INTERSECT", "EXCEPT", "MINUS"))

_SELECT_MODIFIERS = frozenset(
    (
        "ALL DISTINCTROW SQL_CALC_FOUND_ROWS STRAIGHT_JOIN HIGH_PRIORITY SQL_NO_CACHE "
        "SQL_CACHE SQL_SMALL_RESULT SQL_BIG_RESULT SQL_BUFFER_RESULT"
    ).split()
)

# The value an operand can end with, before a bare alias.
_OPERAND_END_KEYWORDS = frozenset(("END", "NULL", "TRUE", "FALSE", "UNKNOWN"))

# Words reserved on every modelled engine, so never a bare column: skipped wherever
# they appear in an expression. Every other word is a keyword only in a position
# (see _Analysis._bare); anywhere else it is checked as a column. TRUE and FALSE are
# reserved everywhere but SQL Server, where they are identifiers: there each is also
# checked against the hidden fields, so a hidden column so named is not read unchecked.
_RESERVED = frozenset(
    (
        "AND CASE CROSS CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP CURRENT_USER "
        "DISTINCT ELSE FALSE FOR FROM GROUP HAVING IN INNER IS JOIN LEFT LIKE NOT NULL "
        "ON OR ORDER OUTER THEN TRUE WHEN WHERE WITH"
    ).split()
)

# Reserved words that are themselves a value, so a word after one is not an operand.
_RESERVED_VALUES = frozenset(
    ("CURRENT_DATE", "CURRENT_TIME", "CURRENT_TIMESTAMP", "CURRENT_USER", "NULL", "TRUE", "FALSE")
)

# Keywords that follow another keyword: ORDER BY, NULLS LAST, SIMILAR TO, WITH ROLLUP,
# AT TIME ZONE, a window frame's UNBOUNDED PRECEDING and CURRENT ROW. None of the
# first words is ever followed by an expression, so the second is never a column.
_KEYWORD_PAIRS = {
    "ORDER": frozenset(("BY",)),
    "GROUP": frozenset(("BY",)),
    "PARTITION": frozenset(("BY",)),
    "ASC": frozenset(("NULLS", "SEPARATOR", "ROWS", "RANGE", "GROUPS")),
    "DESC": frozenset(("NULLS", "SEPARATOR", "ROWS", "RANGE", "GROUPS")),
    "FIRST": frozenset(("SEPARATOR", "ROWS", "RANGE", "GROUPS")),
    "LAST": frozenset(("SEPARATOR", "ROWS", "RANGE", "GROUPS")),
    "IGNORE": frozenset(("NULLS",)),
    "RESPECT": frozenset(("NULLS",)),
    "NULLS": frozenset(("FIRST", "LAST")),
    "SIMILAR": frozenset(("TO",)),
    "WITH": frozenset(("ROLLUP", "CUBE", "TIME")),
    "WITHOUT": frozenset(("TIME",)),
    "AT": frozenset(("TIME", "LOCAL")),
    "ROWS": frozenset(("BETWEEN", "UNBOUNDED", "CURRENT")),
    "RANGE": frozenset(("BETWEEN", "UNBOUNDED", "CURRENT")),
    "GROUPS": frozenset(("BETWEEN", "UNBOUNDED", "CURRENT")),
    "UNBOUNDED": frozenset(("PRECEDING", "FOLLOWING")),
    "CURRENT": frozenset(("ROW",)),
    "EXCLUDE": frozenset(("CURRENT", "TIES", "NO")),
    "NO": frozenset(("OTHERS",)),
}

# The words that may follow an operand: infix and postfix operators, a sort order, a
# unit after a number (MySQL's INTERVAL 7 DAY_HOUR), and the rest of a cast's type
# name. A select item's alias is removed before its expression is walked, so any other
# word after an operand is read as a column: MySQL's INTERVAL zone HOUR reads zone.
_AFTER_OPERAND = frozenset(
    (
        "ILIKE REGEXP RLIKE GLOB SIMILAR BETWEEN ESCAPE DIV MOD XOR SOUNDS OVERLAPS "
        "ASC DESC NULLS AT FILTER WITHIN RESPECT IGNORE SEPARATOR PRECEDING FOLLOWING "
        "ROWS RANGE GROUPS PRECISION VARYING INTEGER INT "
        "SECOND_MICROSECOND MINUTE_MICROSECOND MINUTE_SECOND HOUR_MICROSECOND "
        "HOUR_SECOND HOUR_MINUTE DAY_MICROSECOND DAY_SECOND DAY_MINUTE DAY_HOUR YEAR_MONTH"
    ).split()
)

# Words an engine reads as an operator on the operand that follows: MySQL's BINARY
# ssn, INTERVAL year HOUR, PostgreSQL's VARIADIC arr. Checked as a column when bare,
# since they are not reserved, but never taken to end an operand: the word after one
# is the operand, so it is checked rather than skipped or taken for an alias.
_PREFIX_OPERATORS = frozenset(("BINARY", "INTERVAL", "VARIADIC"))

# Operators written as a word after NOT: a NOT LIKE b, a NOT BETWEEN b AND c.
_NEGATED_OPERATORS = frozenset(
    ("LIKE", "ILIKE", "REGEXP", "RLIKE", "GLOB", "SIMILAR", "BETWEEN", "IN")
)

# The words recognised directly before a string literal: national (N), escape (E),
# hex (X), bit or bytes (B), raw (R, RB, BR) and typed literals. A MySQL character
# set introducer (_utf8mb4) is recognised by its leading underscore. Any other word
# directly before a quote is a form the check does not model, so it is refused.
_LITERAL_PREFIXES = frozenset(("N", "E", "X", "B", "R", "RB", "BR", "DATE", "TIME", "TIMESTAMP"))

# A numeric literal: digits (with PostgreSQL's digit separators), an optional
# fraction and exponent, or a hex or binary literal. A token that starts with a digit
# and is none of these is an identifier some engines accept (MySQL's 1abc), which
# would otherwise go unread as a column.
_NUMBER = re.compile(
    r"(?:[0-9][0-9_]*(?:\.[0-9_]*)?|\.[0-9][0-9_]*)(?:[eE][+-]?[0-9]+)?"
    r"|0[xX][0-9a-fA-F]+|0[bB][01]+"
)


class _Unsupported(Exception):
    def __init__(self, construct: str) -> None:
        super().__init__(construct)
        self.construct = construct


@dataclass(frozen=True)
class _Tok:
    kind: str  # word, qident, string, number, param, punct
    text: str  # the word, the unquoted identifier, or the punctuation character

    @property
    def fold(self) -> str:
        return self.text.translate(_ASCII_LOWER)

    @property
    def upper(self) -> str:
        return self.text.translate(_ASCII_UPPER) if self.kind == "word" else ""

    def is_word(self, *words: str) -> bool:
        return self.kind == "word" and self.text.translate(_ASCII_UPPER) in words

    def is_punct(self, char: str) -> bool:
        return self.kind == "punct" and self.text == char

    @property
    def is_ident(self) -> bool:
        return self.kind in ("word", "qident")


# ---------------------------------------------------------------------------
# Lexing
# ---------------------------------------------------------------------------


def _is_word_start(ch: str) -> bool:
    return ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ch == "_" or ord(ch) >= 0x80


def _is_word_char(ch: str) -> bool:
    return _is_word_start(ch) or ("0" <= ch <= "9") or ch == "$"


def _is_digit(ch: str) -> bool:
    return "0" <= ch <= "9"


def _identifier(text: str) -> str:
    """Refuse an identifier with a non-ASCII character; engines fold those differently."""
    if any(ord(c) >= 0x80 for c in text):
        raise _Unsupported("non-ASCII identifier")
    return text


def _is_literal_prefix(word: str) -> bool:
    if word.translate(_ASCII_UPPER) in _LITERAL_PREFIXES:
        return True
    return len(word) > 1 and word[0] == "_" and all(_is_word_char(c) for c in word[1:])


def _lex(sql: str, mode: str) -> list[_Tok]:
    """Tokenize ``sql`` under one engine's lexical conventions."""
    toks: list[_Tok] = []
    n = len(sql)
    i = 0
    in_executable_comment = False
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        if ch in _WHITESPACE:
            i += 1
            continue
        if ch in _UNICODE_SPACES:
            raise _Unsupported("non-ASCII whitespace")
        # Comments.
        if ch == "-" and nxt == "-":
            after = sql[i + 2] if i + 2 < n else ""
            if mode != "mysql" or _mysql_dash_comment_follower(after):
                i = _line_comment_end(sql, i)
                continue
        if ch == "#" and mode == "mysql":
            i = _line_comment_end(sql, i)
            continue
        if ch == "/" and nxt == "*":
            if mode == "mysql" and i + 2 < n and sql[i + 2] == "!":
                # Executable comment: its body is SQL to MySQL.
                i += 3
                while i < n and _is_digit(sql[i]):
                    i += 1
                in_executable_comment = True
                continue
            i = _skip_block_comment(sql, i, nested=(mode == "postgres"))
            continue
        if ch == "*" and nxt == "/" and in_executable_comment:
            in_executable_comment = False
            i += 2
            continue
        # Literals and quoted identifiers.
        if ch == "&" and nxt in ("'", '"') and i > 0 and _is_word_char(sql[i - 1]):
            raise _Unsupported("Unicode escape")  # U&'...' and U&"..."
        if ch in ("'", '"') and sql.startswith(ch * 3, i):
            raise _Unsupported("triple-quoted literal")
        if ch == "'":
            backslash = mode == "mysql" or (
                mode == "postgres"
                and toks
                and toks[-1].kind == "word"
                and toks[-1].text in ("E", "e")
                and _adjacent(sql, i)
            )
            if toks and toks[-1].kind == "word" and _adjacent(sql, i):
                # A literal prefix (N'', E'', X'', _utf8'') belongs to the literal.
                if not _is_literal_prefix(toks[-1].text):
                    raise _Unsupported("string literal prefix")
                toks.pop()
            i = _skip_quoted(sql, i, "'", backslash=backslash)
            toks.append(_Tok("string", ""))
            continue
        if ch == '"':
            if mode == "mysql":
                i = _skip_quoted(sql, i, '"', backslash=True)
                toks.append(_Tok("string", ""))
            else:
                end = _skip_quoted(sql, i, '"', backslash=False)
                toks.append(_Tok("qident", _identifier(_unquote(sql[i + 1 : end - 1], '"'))))
                i = end
            continue
        if ch == "`":
            end = _skip_quoted(sql, i, "`", backslash=False)
            toks.append(_Tok("qident", _identifier(_unquote(sql[i + 1 : end - 1], "`"))))
            i = end
            continue
        if ch == "[" and mode == "ansi":
            end = _skip_quoted(sql, i, "]", backslash=False)
            toks.append(_Tok("qident", _identifier(_unquote(sql[i + 1 : end - 1], "]"))))
            i = end
            continue
        if ch == "$":
            if _is_digit(nxt):
                j = i + 1
                while j < n and _is_digit(sql[j]):
                    j += 1
                toks.append(_Tok("param", sql[i:j]))
                i = j
                continue
            if mode == "postgres":
                j = i + 1
                while j < n and (_is_word_start(sql[j]) or _is_digit(sql[j])):
                    j += 1
                if j < n and sql[j] == "$" and not _is_digit(nxt):
                    tag = sql[i : j + 1]
                    end = sql.find(tag, j + 1)
                    i = n if end < 0 else end + len(tag)
                    toks.append(_Tok("string", ""))
                    continue
        # Numbers, words, parameters, punctuation.
        if _is_digit(ch) or (ch == "." and _is_digit(nxt)):
            j = i + 1
            while j < n and (_is_word_char(sql[j]) or sql[j] == "."):
                if sql[j] in "eE" and j + 1 < n and sql[j + 1] in "+-":
                    j += 1
                j += 1
            if not _NUMBER.fullmatch(sql[i:j]):
                raise _Unsupported("identifier starting with a digit")
            toks.append(_Tok("number", sql[i:j]))
            i = j
            continue
        if _is_word_start(ch) or ch == "$":
            j = i + 1
            while j < n and _is_word_char(sql[j]):
                if sql[j] in _UNICODE_SPACES:
                    raise _Unsupported("non-ASCII whitespace")
                j += 1
            toks.append(_Tok("word", _identifier(sql[i:j])))
            i = j
            continue
        if ch == "?":
            toks.append(_Tok("param", "?"))
            i += 1
            continue
        toks.append(_Tok("punct", ch))
        i += 1
    return toks


def _mysql_dash_comment_follower(after: str) -> bool:
    """Whether MySQL starts a ``--`` comment given the next character: end of input,
    a space or any control character (U+0000-U+0020 and U+007F)."""
    return after == "" or ord(after) <= 0x20 or ord(after) == 0x7F


def _line_comment_end(sql: str, start: int) -> int:
    """Index just past a line comment, which ends at a line feed. Engines disagree on
    a carriage return: PostgreSQL and Trino end the comment there, MySQL does not.
    Either reading can hide SQL that the other executes, so a carriage return inside
    a line comment is refused unless it is part of a CRLF."""
    end = sql.find("\n", start)
    stop = end if end >= 0 else len(sql)
    cr = sql.find("\r", start, stop)
    while cr >= 0:
        if cr + 1 != end:
            raise _Unsupported("carriage return in comment")
        cr = sql.find("\r", cr + 1, stop)
    return end + 1 if end >= 0 else len(sql)


def _adjacent(sql: str, quote_index: int) -> bool:
    """Whether the character before the quote belongs to the preceding word."""
    return quote_index > 0 and _is_word_char(sql[quote_index - 1])


def _skip_block_comment(sql: str, start: int, *, nested: bool) -> int:
    depth = 0
    i = start
    n = len(sql)
    while i < n:
        if sql.startswith("/*", i):
            depth += 1
            i += 2
            if not nested and depth > 1:
                depth = 1
            continue
        if sql.startswith("*/", i):
            depth -= 1
            i += 2
            if depth == 0:
                return i
            continue
        i += 1
    return n


def _skip_quoted(sql: str, start: int, close: str, *, backslash: bool) -> int:
    """Index just past the literal or identifier opened at ``start``."""
    i = start + 1
    n = len(sql)
    while i < n:
        ch = sql[i]
        if backslash and ch == "\\":
            i += 2
            continue
        if ch == close:
            if i + 1 < n and sql[i + 1] == close:
                i += 2
                continue
            return i + 1
        i += 1
    return n + 1  # unterminated: runs to the end


def _unquote(body: str, close: str) -> str:
    return body.replace(close + close, close)




# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


class _FieldDenied(Exception):
    pass


@dataclass(eq=False)
class _Ref:
    """A table or derived table in a FROM clause."""

    table: str | None  # the base table's name, or None when it cannot be resolved
    names: set[str]  # the ASCII-folded names a column qualifier may use for it
    derived: bool = False
    path: tuple[str, ...] = ()  # a base table's ASCII-folded name, part by part


@dataclass
class _Scope:
    refs: list[_Ref] = field(default_factory=list)
    by_name: dict[str, _Ref] = field(default_factory=dict)

    def add(self, ref: _Ref) -> None:
        for name in ref.names:
            if name in self.by_name:
                raise _Unsupported("duplicate table name")
            self.by_name[name] = ref
        self.refs.append(ref)


@dataclass
class _From:
    """What a FROM clause holds: its tables, derived-table bodies and join conditions."""

    scope: _Scope = field(default_factory=_Scope)
    derived: list[tuple[int, int]] = field(default_factory=list)
    on: list[tuple[int, int]] = field(default_factory=list)
    using: list[tuple[list[str], list[_Ref]]] = field(default_factory=list)
    natural: bool = False


class _Analysis:
    def __init__(
        self, toks: list[_Tok], policy: EffectivePolicy, *, object_name: str | None = None
    ) -> None:
        self.toks = toks
        self.policy = policy
        self.object_name = object_name
        rules = policy.object_rules.field_rules if policy.object_rules else None
        self.hidden: list[str] = list(rules.hidden_fields or []) if rules else []
        self.allowed: list[str] | None = rules.allowed_fields if rules else None
        self.match = self._match_parens()

    def _match_parens(self) -> dict[int, int]:
        stack: list[int] = []
        match: dict[int, int] = {}
        for idx, tok in enumerate(self.toks):
            if tok.is_punct("("):
                stack.append(idx)
            elif tok.is_punct(")"):
                if not stack:
                    raise _Unsupported("unbalanced parentheses")
                match[stack.pop()] = idx
        if stack:
            raise _Unsupported("unbalanced parentheses")
        return match

    def _top_level(self, start: int, end: int):
        """Indices in [start, end) outside any parentheses opened in that range."""
        i = start
        while i < end:
            yield i
            i = self.match[i] + 1 if self.toks[i].is_punct("(") else i + 1

    # -- statement ---------------------------------------------------------

    def run(self) -> AccessResult:
        toks = self.toks
        end = len(toks)
        while end > 0 and toks[end - 1].is_punct(";"):
            end -= 1
        if any(t.is_punct(";") for t in toks[:end]):
            raise _Unsupported("multiple statements")
        if end == 0:
            return AccessResult(allowed=True)
        if toks[0].is_word("WITH"):
            raise _Unsupported("WITH")
        if not toks[0].is_word("SELECT"):
            raise _Unsupported("statement other than SELECT")
        return self._select(0, end, depth=0)

    def _select(self, start: int, end: int, *, depth: int) -> AccessResult:
        """Check the SELECT spanning [start, end); ``start`` is the SELECT keyword."""
        if depth > _MAX_NESTING:
            raise _Unsupported("nesting depth")
        toks = self.toks
        from_at = self._find_from(start, end)
        if from_at is None:
            select_end = self._tail_start(start + 1, end)
            tail_at = select_end
            clause = _From()
        else:
            select_end = from_at
            tail_at = self._tail_start(from_at + 1, end)
            clause = self._parse_from(from_at + 1, tail_at)
        tails = self._split_tail(tail_at, end)
        scope = clause.scope

        if depth == 0 and len(scope.refs) <= 1 and not clause.derived:
            # At most one table: check its access and refuse anything that reaches a
            # further table. Its columns are checked below as well as by the
            # single-table checks, so a column either check misses is still caught.
            for idx in range(start + 1, end):
                if toks[idx].is_word("SELECT", "TABLE"):
                    raise _Unsupported("subquery")
            if not scope.refs:
                return AccessResult(allowed=True)
            ref = scope.refs[0]
            access = validate_access(ref.table or "", self.policy)
            if not access.allowed:
                return access
            # A supplied object name must name the table the query reads; otherwise
            # the object checked is not the object read.
            if self.object_name is not None and not _same_object(self.object_name, ref.path):
                return AccessResult(allowed=False, reason=OBJECT_MISMATCH_REASON)

        for ref in scope.refs:
            if not ref.derived and ref.table is not None:
                access = validate_access(ref.table, self.policy)
                if not access.allowed:
                    return access
        for inner_start, inner_end in clause.derived:
            inner = self._select(inner_start, inner_end, depth=depth + 1)
            if not inner.allowed:
                return inner

        self._check_select_list(start + 1, select_end, scope)
        for a, b in clause.on:
            self._walk(a, b, scope)
        for cols, refs in clause.using:
            for col in cols:
                for ref in refs:
                    self._check_column(ref, col)
        if clause.natural and (
            self.hidden or (self.allowed is not None and not self._allows_everything())
        ):
            raise _Unsupported("NATURAL JOIN")
        aliases = self._select_aliases(start + 1, select_end)
        for word, a, b in tails:
            if a >= b:
                raise _Unsupported(f"empty {word} clause")
            if word in _SKIPPED_TAIL:
                self._check_skipped_tail(word, a, b)
            elif word == "ORDER":
                self._check_order_by(a, b, scope, aliases)
            else:
                self._walk(a, b, scope)
        return AccessResult(allowed=True)

    def _check_skipped_tail(self, word: str, start: int, end: int) -> None:
        """Refuse a LIMIT, OFFSET, FETCH or FOR clause holding anything but its own
        words, numbers and parameters (and, after FOR ... OF, table names)."""
        toks = self.toks
        names = False
        for idx in range(start, end):
            tok = toks[idx]
            if tok.is_word("SELECT", "TABLE"):
                raise _Unsupported("subquery")
            if word == "FOR" and tok.is_word("OF"):
                names = True
                continue
            if tok.kind in ("number", "param") or (tok.kind == "punct" and tok.text in ",()"):
                continue
            if tok.kind == "word" and tok.upper in _SKIPPED_TAIL_WORDS:
                continue
            if names and (tok.is_ident or tok.is_punct(".")):
                continue
            raise _Unsupported(f"{word} clause")

    def _find_from(self, start: int, end: int) -> int | None:
        """The SELECT's own FROM keyword, refusing set operations and SELECT INTO."""
        from_at = None
        for idx in self._top_level(start + 1, end):
            tok = self.toks[idx]
            if tok.kind != "word":
                continue
            word = tok.upper
            if word in _SET_OPERATIONS:
                raise _Unsupported("set operation")
            if word == "INTO":
                raise _Unsupported("SELECT INTO")
            if word == "FROM" and not self._is_distinct_from(idx, start):
                if from_at is not None:
                    raise _Unsupported("FROM clause")
                from_at = idx
        return from_at

    def _is_distinct_from(self, idx: int, start: int) -> bool:
        # "a IS [NOT] DISTINCT FROM b" is a comparison, not a FROM clause.
        return (
            idx - 2 > start
            and self.toks[idx - 1].is_word("DISTINCT")
            and self.toks[idx - 2].is_word("IS", "NOT")
        )

    def _is_tail_mark(self, idx: int) -> bool:
        tok = self.toks[idx]
        if tok.kind != "word" or tok.upper not in _TAIL_CLAUSES:
            return False
        if tok.upper == "WITH":
            # TIME WITH TIME ZONE, FETCH ... ROWS WITH TIES, GROUP BY ... WITH ROLLUP.
            before = self.toks[idx - 1] if idx > 0 else None
            after = self.toks[idx + 1] if idx + 1 < len(self.toks) else None
            if before is not None and before.is_word("TIME", "TIMESTAMP", "ROW", "ROWS"):
                return False
            if after is not None and after.is_word("TIES", "ROLLUP", "CUBE"):
                return False
        return True

    def _tail_start(self, start: int, end: int) -> int:
        for idx in self._top_level(start, end):
            if self._is_tail_mark(idx):
                return idx
        return end

    def _split_tail(self, start: int, end: int) -> list[tuple[str, int, int]]:
        """The tail clauses as (keyword, content start, content end)."""
        marks = [idx for idx in self._top_level(start, end) if self._is_tail_mark(idx)]
        tails = []
        for pos, idx in enumerate(marks):
            word = self.toks[idx].upper
            if word not in _CHECKED_TAIL and word not in _SKIPPED_TAIL:
                raise _Unsupported(word)
            content_start = idx + 1
            if word in ("GROUP", "ORDER") and content_start < end and self.toks[
                content_start
            ].is_word("BY"):
                content_start += 1
            content_end = marks[pos + 1] if pos + 1 < len(marks) else end
            tails.append((word, content_start, content_end))
        return tails

    # -- FROM --------------------------------------------------------------

    def _parse_from(self, start: int, end: int) -> _From:
        toks = self.toks
        clause = _From()
        i = self._parse_item(start, end, clause)
        while i < end:
            if toks[i].is_punct(","):
                i = self._parse_item(i + 1, end, clause)
                continue
            if toks[i].is_word("NATURAL"):
                clause.natural = True
                i += 1
            if i + 1 < end and toks[i].is_word("CROSS", "OUTER") and toks[i + 1].is_word("APPLY"):
                raise _Unsupported("APPLY")
            if i < end and toks[i].is_word("INNER", "CROSS"):
                i += 1
            elif i < end and toks[i].is_word("LEFT", "RIGHT", "FULL"):
                i += 1
                if i < end and toks[i].is_word("OUTER"):
                    i += 1
            if not (i < end and toks[i].is_word("JOIN", "STRAIGHT_JOIN")):
                raise _Unsupported("FROM clause")
            left = list(clause.scope.refs)
            i = self._parse_item(i + 1, end, clause)
            right = clause.scope.refs[-1]
            if i < end and toks[i].is_word("ON"):
                on_end = end
                for idx in self._top_level(i + 1, end):
                    tok = toks[idx]
                    if tok.is_punct(",") or self._is_join_word(idx, end):
                        on_end = idx
                        break
                clause.on.append((i + 1, on_end))
                i = on_end
            elif i < end and toks[i].is_word("USING"):
                if not (i + 1 < end and toks[i + 1].is_punct("(")):
                    raise _Unsupported("FROM clause")
                close = self.match[i + 1]
                cols: list[str] = []
                for idx in range(i + 2, close):
                    tok = toks[idx]
                    if tok.is_ident:
                        cols.append(tok.text)
                    elif not tok.is_punct(","):
                        raise _Unsupported("FROM clause")
                clause.using.append((cols, left + [right]))
                i = close + 1
        return clause

    def _is_join_word(self, idx: int, end: int) -> bool:
        # LEFT(...) and RIGHT(...) in a join condition are functions, not joins.
        tok = self.toks[idx]
        if tok.kind != "word" or tok.upper not in _JOIN_WORDS:
            return False
        return not (idx + 1 < end and self.toks[idx + 1].is_punct("("))

    def _parse_item(self, start: int, end: int, clause: _From) -> int:
        toks = self.toks
        if start >= end:
            raise _Unsupported("FROM clause")
        tok = toks[start]
        if tok.is_word("LATERAL"):
            raise _Unsupported("LATERAL")
        if tok.is_punct("("):
            close = self.match[start]
            if not (start + 1 < close and toks[start + 1].is_word("SELECT")):
                raise _Unsupported("parenthesized join")
            clause.derived.append((start + 1, close))
            alias, i = self._parse_alias(close + 1, end)
            if i < end and toks[i].is_punct("("):
                i = self.match[i] + 1  # column aliases rename the derived table's outputs
            table = self._single_base_table(start + 1, close)
            clause.scope.add(
                _Ref(table=table, names={alias.fold} if alias else set(), derived=True)
            )
            return i
        if not tok.is_ident or (
            tok.kind == "word" and (tok.upper in _KEYWORDS or tok.upper in _NOT_AN_ALIAS)
        ):
            raise _Unsupported("FROM clause")
        parts = [tok]
        i = start + 1
        while i + 1 < end and toks[i].is_punct(".") and toks[i + 1].is_ident:
            parts.append(toks[i + 1])
            i += 2
        if i < end and toks[i].is_punct("("):
            raise _Unsupported("table-valued function")
        alias, i = self._parse_alias(i, end)
        if i < end and toks[i].is_punct("("):
            raise _Unsupported("column alias list")
        leaf = parts[-1].text
        if parts[-1].kind == "qident" and "." in leaf:
            leaf = leaf.rsplit(".", 1)[1]
        if alias is not None:
            names = {alias.fold}
        else:
            folded = [p.fold for p in parts]
            names = {".".join(folded[k:]) for k in range(len(folded))}
        path = tuple(
            segment.translate(_ASCII_LOWER)
            for p in parts
            for segment in (p.text.split(".") if p.kind == "qident" else [p.text])
        )
        clause.scope.add(_Ref(table=leaf, names=names, path=path))
        return i

    def _parse_alias(self, i: int, end: int) -> tuple[_Tok | None, int]:
        toks = self.toks
        if i < end and toks[i].is_word("AS"):
            if i + 1 < end and self._can_alias(toks[i + 1]):
                return toks[i + 1], i + 2
            raise _Unsupported("FROM clause")
        if i < end and self._can_alias(toks[i]):
            return toks[i], i + 1
        return None, i

    @staticmethod
    def _can_alias(tok: _Tok) -> bool:
        if tok.kind == "qident":
            return True
        return tok.kind == "word" and tok.upper not in _NOT_AN_ALIAS and tok.upper not in _KEYWORDS

    def _single_base_table(self, start: int, end: int) -> str | None:
        """The one base table a derived table reads, or None when there is not exactly one."""
        from_at = self._find_from(start, end)
        if from_at is None:
            return None
        inner = self._parse_from(from_at + 1, self._tail_start(from_at + 1, end))
        if len(inner.scope.refs) == 1 and not inner.derived:
            return inner.scope.refs[0].table
        return None

    # -- field rules -------------------------------------------------------

    def _allows_everything(self) -> bool:
        return self.allowed is not None and any(a.strip() == "*" for a in self.allowed)

    def _check_name(self, name: str) -> None:
        """Check a table-qualified column against both field rules."""
        if any(_field_name_matches(h, name) for h in self.hidden):
            raise _FieldDenied()
        if self.allowed is not None and not any(
            _allowed_field_matches(a, name) for a in self.allowed
        ):
            raise _FieldDenied()

    def _check_unresolved(self, col: str) -> None:
        """Check a column whose table is unknown: only an unqualified entry can allow it."""
        if any(_field_name_matches(h, col) for h in self.hidden):
            raise _FieldDenied()
        if self.allowed is not None and not any(
            "." not in a and _field_name_matches(a, col) for a in self.allowed
        ):
            raise _FieldDenied()

    def _check_column(self, ref: _Ref, col: str) -> None:
        if ref.table is None:
            self._check_unresolved(col)
        else:
            self._check_name(f"{ref.table}.{col}")

    def _check_bare(self, col: str, scope: _Scope) -> None:
        if len(scope.refs) == 1:
            self._check_column(scope.refs[0], col)
        else:
            self._check_unresolved(col)

    def _check_hidden(self, col: str, scope: _Scope) -> None:
        """Refuse ``col`` if it may name a hidden column of any table in scope."""
        for ref in scope.refs:
            name = col if ref.table is None else f"{ref.table}.{col}"
            if any(_field_name_matches(h, name) for h in self.hidden):
                raise _FieldDenied()
        if not scope.refs and any(_field_name_matches(h, col) for h in self.hidden):
            raise _FieldDenied()

    def _check_star(self, ref: _Ref) -> None:
        """``t.*``: hidden fields are stripped after the fetch, but an allow-list must fit.

        The fetched keys are bare column names, so an entry qualified with another
        table would admit this table's column of the same name. The star is allowed
        only when every qualified entry names this table.
        """
        if self.allowed is None or self._allows_everything():
            return
        table = ref.table.translate(_ASCII_LOWER) if ref.table is not None else None
        for entry in self.allowed:
            dot = entry.rfind(".")
            if dot >= 0 and (table is None or entry[:dot].translate(_ASCII_LOWER) != table):
                raise _FieldDenied()

    # -- expressions -------------------------------------------------------

    def _walk(self, start: int, end: int, scope: _Scope) -> None:
        """Check every column reference in the expression tokens [start, end)."""
        toks = self.toks
        ends: set[int] = set()  # words that end an operand
        windows: set[int] = set()  # the "(" opening each OVER (...) window
        brackets: list[int] = []
        i = start
        while i < end:
            tok = toks[i]
            if tok.kind == "punct":
                if tok.text in "([":
                    brackets.append(i)
                elif tok.text in ")]" and brackets:
                    brackets.pop()
                elif tok.text == ":" and i + 2 < end and toks[i + 1].is_punct(":"):
                    if toks[i + 2].is_ident:
                        ends.add(i + 2)
                        i += 3  # a cast's target type
                        continue
                elif (
                    tok.text == ":"
                    and i + 1 < end
                    and toks[i + 1].is_ident
                    and not (brackets and toks[brackets[-1]].is_punct("["))
                ):
                    ends.add(i + 1)
                    i += 2  # a named bind parameter; inside [...] it is a slice bound
                    continue
                i += 1
                continue
            if not tok.is_ident:
                i += 1
                continue
            parts = [tok]
            j = i
            while (
                j + 2 < end
                and toks[j + 1].is_punct(".")
                and (toks[j + 2].is_ident or toks[j + 2].is_punct("*"))
            ):
                parts.append(toks[j + 2])
                j += 2
                if parts[-1].is_punct("*"):
                    break
            if j + 1 < end and toks[j + 1].is_punct("(") and not parts[-1].is_punct("*"):
                if j == i and tok.is_word("OVER") and i > start and toks[i - 1].is_punct(")"):
                    windows.add(i + 1)
                i = j + 1  # a function name; its arguments are walked
                continue
            if len(parts) == 1:
                in_window = bool(brackets) and brackets[-1] in windows
                i = self._bare(i, start, end, scope, ends, windows, in_window)
                continue
            qualifier = ".".join(p.fold for p in parts[:-1])
            ref = scope.by_name.get(qualifier)
            if ref is None:
                raise _Unsupported("unresolved qualifier")
            if parts[-1].is_punct("*"):
                self._check_star(ref)
            else:
                self._check_column(ref, parts[-1].text)
                ends.add(j)
            i = j + 1

    def _ends_operand(self, k: int, start: int, ends: set[int]) -> bool:
        """Whether token ``k`` of the walk that began at ``start`` ends an operand."""
        if k < start:
            return False
        tok = self.toks[k]
        return (
            tok.kind in ("qident", "string", "number", "param")
            or tok.is_punct(")")
            or tok.is_punct("]")
            or k in ends
        )

    def _bare(
        self,
        i: int,
        start: int,
        end: int,
        scope: _Scope,
        ends: set[int],
        windows: set[int],
        in_window: bool,
    ) -> int:
        """Handle a lone identifier at ``i``; return the index to continue from.

        A word is skipped only where it cannot be a column: a reserved word, a word
        directly after an operand (an operator, ASC, an alias), the second word of a
        keyword pair, or a window's frame words. Anywhere else it is checked, so a
        column named like a keyword (``zone``, ``first``) is still read as one.
        """
        toks = self.toks
        tok = toks[i]
        following = toks[i + 1] if i + 1 < end else None
        prev = toks[i - 1] if i - 1 >= start else None
        prev2 = toks[i - 2] if i - 2 >= start else None
        if tok.kind == "word":
            word = tok.upper
            if word in ("SELECT", "TABLE"):
                raise _Unsupported("subquery")
            if word in ("AS", "COLLATE"):
                # An alias or cast type, or a collation.
                if following is not None and following.is_ident:
                    ends.add(i + 1)
                    return i + 2
                return i + 1
            if word in _RESERVED:
                if word in ("TRUE", "FALSE"):
                    self._check_hidden(tok.text, scope)
                if word in _RESERVED_VALUES:
                    ends.add(i)
                return i + 1
            if word == "OVER" and prev is not None and prev.is_punct(")"):
                if following is not None and following.is_ident:
                    ends.add(i + 1)
                    return i + 2  # a named window
                return i + 1
            if self._ends_operand(i - 1, start, ends):
                if word in _OPERAND_END_KEYWORDS or word in ("ISNULL", "NOTNULL"):
                    ends.add(i)
                    return i + 1
                if word in _AFTER_OPERAND or word in _DATE_PARTS:
                    return i + 1  # an operator or modifier: DIV, ASC, BETWEEN, AT
            if prev is not None and prev.kind == "word":
                before = prev.upper
                if word in _KEYWORD_PAIRS.get(before, ()):
                    if word == "TIME" and not (following is not None and following.is_word("ZONE")):
                        pass  # WITH TIME is only a keyword pair ahead of ZONE
                    else:
                        return i + 1
                if (
                    word == "ZONE"
                    and before == "TIME"
                    and prev2 is not None
                    and prev2.is_word("WITH", "WITHOUT", "AT")
                ):
                    return i + 1
                if before == "IS" or (
                    before == "NOT" and prev2 is not None and prev2.is_word("IS")
                ):
                    ends.add(i)
                    return i + 1  # IS [NOT] UNKNOWN, IS JSON, IS DISTINCT FROM
                if (
                    before == "NOT"
                    and word in _NEGATED_OPERATORS
                    and self._ends_operand(i - 2, start, ends)
                ):
                    return i + 1  # a NOT BETWEEN b; a prefix NOT is followed by a value
            if in_window and self._frame_word(i, following, prev):
                return i + 1
            if prev is not None and prev.is_punct("(") and prev2 is not None:
                if word in _DATE_PARTS and prev2.is_word("EXTRACT"):
                    return i + 1  # EXTRACT(YEAR FROM ...)
                if word in ("BOTH", "LEADING", "TRAILING") and prev2.is_word("TRIM"):
                    return i + 1  # TRIM(LEADING 'x' FROM ...)
            if word == "INTERVAL":
                k = self._interval_literal_end(i, end)
                if k is not None:
                    ends.add(k - 1)
                    return k
                if (
                    following is not None
                    and following.is_ident
                    and i + 2 < end
                    and toks[i + 2].kind == "word"
                    and toks[i + 2].upper in _DATE_PARTS
                ):
                    return i + 1  # MySQL's INTERVAL n DAY
            if word in ("DATE", "TIME", "TIMESTAMP"):
                if following is not None and following.kind == "string":
                    return i + 1  # a typed literal: DATE '2024-01-01'
                if (
                    following is not None
                    and following.is_word("WITH", "WITHOUT")
                    and i + 3 < end
                    and toks[i + 2].is_word("TIME")
                    and toks[i + 3].is_word("ZONE")
                ):
                    return i + 4  # TIMESTAMP WITH TIME ZONE '...'
            if word == "ARRAY" and following is not None and following.is_punct("["):
                return i + 1  # an array constructor: ARRAY[1, 2]
            if word == "GROUPING" and following is not None and following.is_word("SETS"):
                return i + 1
        self._check_bare(tok.text, scope)
        if not (tok.kind == "word" and tok.upper in _PREFIX_OPERATORS):
            ends.add(i)
        return i + 1

    def _frame_word(self, i: int, following: _Tok | None, prev: _Tok | None) -> bool:
        """Whether the word at ``i``, directly inside OVER (...), is a frame keyword."""
        word = self.toks[i].upper
        nxt = following.upper if following is not None and following.kind == "word" else ""
        opens = prev is not None and prev.is_punct("(")
        if word == "PARTITION":
            return opens and nxt == "BY"
        if word in ("ROWS", "RANGE", "GROUPS"):
            return opens and (
                nxt in ("BETWEEN", "UNBOUNDED", "CURRENT")
                or (following is not None and following.kind in ("number", "param", "string"))
            )
        if word == "UNBOUNDED":
            return nxt in ("PRECEDING", "FOLLOWING")
        if word == "CURRENT":
            return nxt == "ROW"
        if word == "EXCLUDE":
            return nxt in ("CURRENT", "GROUP", "TIES", "NO")
        return False

    def _interval_literal_end(self, i: int, end: int) -> int | None:
        """The index past ``INTERVAL [-]'1' [DAY [TO SECOND]]`` at ``i``, or None."""
        toks = self.toks
        k = i + 1
        if k < end and (toks[k].is_punct("-") or toks[k].is_punct("+")):
            k += 1
        if not (k < end and toks[k].kind in ("string", "number", "param")):
            return None
        k += 1
        if k < end and toks[k].kind == "word" and toks[k].upper in _DATE_PARTS:
            k += 1
            if (
                k + 1 < end
                and toks[k].is_word("TO")
                and toks[k + 1].kind == "word"
                and toks[k + 1].upper in _DATE_PARTS
            ):
                k += 2
        return k

    # -- select list and ORDER BY -----------------------------------------

    def _entries(self, start: int, end: int) -> list[tuple[int, int]]:
        entries = []
        entry_start = start
        for idx in self._top_level(start, end):
            if self.toks[idx].is_punct(","):
                entries.append((entry_start, idx))
                entry_start = idx + 1
        entries.append((entry_start, end))
        return [(a, b) for a, b in entries if a < b]

    def _skip_modifiers(self, start: int, end: int, scope: _Scope) -> int:
        """Step past DISTINCT [ON (...)], TOP n and the like, checking DISTINCT ON."""
        toks = self.toks
        i = start
        while i < end:
            tok = toks[i]
            if tok.is_word("DISTINCT"):
                i += 1
                if i + 1 < end and toks[i].is_word("ON") and toks[i + 1].is_punct("("):
                    close = self.match[i + 1]
                    self._walk(i + 2, close, scope)
                    i = close + 1
                continue
            if tok.is_word("TOP"):
                i += 1
                if i < end and toks[i].is_punct("("):
                    i = self.match[i] + 1
                elif i < end and toks[i].kind in ("number", "param"):
                    i += 1
                if i < end and toks[i].is_word("PERCENT"):
                    i += 1
                if i + 1 < end and toks[i].is_word("WITH") and toks[i + 1].is_word("TIES"):
                    i += 2
                continue
            if tok.kind == "word" and tok.upper in _SELECT_MODIFIERS:
                i += 1
                continue
            break
        return i

    def _entry_alias(self, a: int, b: int) -> tuple[int, _Tok | None]:
        """Where an entry's expression ends, and its alias if it has one."""
        toks = self.toks
        if b - a >= 3 and toks[b - 2].is_word("AS") and toks[b - 1].is_ident:
            return b - 2, toks[b - 1]
        if b - a >= 2 and self._can_be_output_alias(toks[b - 1]):
            prev = toks[b - 2]
            prev_ends_operand = (
                prev.kind in ("qident", "string", "number", "param")
                or prev.is_punct(")")
                or (
                    prev.kind == "word"
                    and prev.upper not in _PREFIX_OPERATORS
                    and (prev.upper not in _KEYWORDS or prev.upper in _OPERAND_END_KEYWORDS)
                )
            )
            if prev_ends_operand:
                return b - 1, toks[b - 1]
        return b, None

    @staticmethod
    def _can_be_output_alias(tok: _Tok) -> bool:
        """Whether ``tok`` may be an alias written without AS.

        A unit or operator word is not: in ``dob + INTERVAL year HOUR`` the HOUR is
        the interval's unit, and taking it for an alias would leave ``year`` unread.
        """
        if tok.kind == "qident":
            return True
        return (
            tok.kind == "word"
            and tok.upper not in _KEYWORDS
            and tok.upper not in _AFTER_OPERAND
            and tok.upper not in _DATE_PARTS
        )

    def _check_select_list(self, start: int, end: int, scope: _Scope) -> None:
        body = self._skip_modifiers(start, end, scope)
        for a, b in self._entries(body, end):
            if b - a == 1 and self.toks[a].is_punct("*"):
                for ref in scope.refs:
                    self._check_star(ref)
                continue
            expr_end, alias = self._entry_alias(a, b)
            if alias is not None and expr_end == b - 1:
                # An alias without AS cannot be told from an unknown prefix operator
                # applied to a column (MySQL's BINARY ssn), so it must not name a
                # hidden column. An allow-list is not applied: the alias is not read.
                self._check_hidden(alias.text, scope)
            self._walk(a, expr_end, scope)

    def _select_aliases(self, start: int, end: int) -> set[str]:
        aliases: set[str] = set()
        for a, b in self._entries(start, end):
            _expr_end, alias = self._entry_alias(a, b)
            if alias is not None:
                aliases.add(alias.fold)
        return aliases

    def _check_order_by(self, start: int, end: int, scope: _Scope, aliases: set[str]) -> None:
        for a, b in self._entries(start, end):
            k = b
            while k > a and self.toks[k - 1].is_word("ASC", "DESC", "FIRST", "LAST", "NULLS"):
                k -= 1
            if k - a == 1 and self.toks[a].is_ident and self.toks[a].fold in aliases:
                continue  # an output column's alias, which ORDER BY resolves first
            self._walk(a, b, scope)


def _same_object(object_name: str, path: tuple[str, ...]) -> bool:
    """Whether a supplied object name and a table's name can name the same object.

    Both are compared part by part, ASCII case-insensitively, from the right. A name
    with fewer parts matches one qualified further (``patients`` and
    ``public.patients``); names whose shared parts differ do not (``db1.patients``
    and ``db2.patients``).
    """
    given = tuple(s.translate(_ASCII_LOWER) for s in object_name.split("."))
    k = min(len(given), len(path))
    return k > 0 and given[-k:] == path[-k:]


def validate_query_references(
    query: str, policy: EffectivePolicy, *, object_name: str | None = None
) -> AccessResult:
    """Check every table and column a query references against the policy.

    Every table the query reads must pass :func:`validate_access`, and every column
    reference is resolved to its table and checked against ``hiddenFields`` and
    ``allowedFields``. A bare column in a query over several tables is allowed only
    by an unqualified ``allowedFields`` entry (or ``*``), because the table it
    belongs to cannot be known without the schema. Constructs the check cannot
    resolve are refused with a reason beginning with
    :data:`UNSUPPORTED_REASON_PREFIX`.

    A query that reads a single table has its columns checked here as well as by
    :func:`tolap_core.sql_rewriter.validate_query`. When the caller supplies ``object_name`` it is checked with
    :func:`validate_access` as well, and a query over one table must read that object:
    a different table is refused with :data:`OBJECT_MISMATCH_REASON`. Every table of
    a query is checked whether or not an object name is supplied.

    Identifier and literal forms the check does not model are refused rather than
    guessed at: Unicode-escape forms (``U&"..."``, ``U&'...'``), string literal
    prefixes other than the recognised ones (such as Oracle's ``q'[...]'``),
    triple-quoted literals, identifiers with a non-ASCII character and identifiers
    that start with a digit.
    """
    if object_name is not None:
        named = validate_access(object_name, policy)
        if not named.allowed:
            return named
    if not query:
        return AccessResult(allowed=True)
    seen: list[list[_Tok]] = []
    for mode in _MODES:
        try:
            toks = _lex(query, mode)
            if toks in seen:
                continue
            seen.append(toks)
            result = _Analysis(toks, policy, object_name=object_name).run()
        except _Unsupported as unsupported:
            return AccessResult(
                allowed=False, reason=UNSUPPORTED_REASON_PREFIX + unsupported.construct
            )
        except _FieldDenied:
            return AccessResult(allowed=False, reason=FIELD_DENIAL_REASON)
        if not result.allowed:
            return result
    return AccessResult(allowed=True)
