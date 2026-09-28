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

A query that reads exactly one table is left to the existing single-table checks
(the object check and :func:`tolap_core.sql_rewriter.validate_query`), so their
decisions are unchanged. This check only validates that table's access, which
those checks already did when the table name came from the query itself.

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
            if mode != "mysql" or after == "" or after in _WHITESPACE:
                end = sql.find("\n", i)
                i = n if end < 0 else end + 1
                continue
        if ch == "#" and mode == "mysql":
            end = sql.find("\n", i)
            i = n if end < 0 else end + 1
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
            # At most one table: the single-table checks own the field rules. Only its
            # access is checked here, and the query must not reach further tables.
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
            return access

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
            if word in _SKIPPED_TAIL:
                for idx in range(a, b):
                    if toks[idx].is_word("SELECT", "TABLE"):
                        raise _Unsupported("subquery")
            elif word == "ORDER":
                self._check_order_by(a, b, scope, aliases)
            else:
                self._walk(a, b, scope)
        return AccessResult(allowed=True)

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
        i = start
        while i < end:
            tok = toks[i]
            if tok.kind == "punct":
                if tok.text in (":", "@") and i + 1 < end and toks[i + 1].is_ident:
                    i += 2  # a cast's target type, a bind parameter, or a variable
                else:
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
                i = j + 1  # a function name; its arguments are walked
                continue
            if len(parts) == 1:
                i = self._bare(i, end, scope)
                continue
            qualifier = ".".join(p.fold for p in parts[:-1])
            ref = scope.by_name.get(qualifier)
            if ref is None:
                raise _Unsupported("unresolved qualifier")
            if parts[-1].is_punct("*"):
                self._check_star(ref)
            else:
                self._check_column(ref, parts[-1].text)
            i = j + 1

    def _bare(self, i: int, end: int, scope: _Scope) -> int:
        """Handle a lone identifier at ``i``; return the index to continue from."""
        toks = self.toks
        tok = toks[i]
        following = toks[i + 1] if i + 1 < end else None
        if tok.kind == "word":
            word = tok.upper
            if word in ("SELECT", "TABLE"):
                raise _Unsupported("subquery")
            if word in ("AS", "COLLATE", "OVER"):
                # An alias or cast type, a collation, a named window.
                return i + 2 if following is not None and following.is_ident else i + 1
            if word == "INTERVAL":
                k = i + 1
                if k < end and toks[k].kind in ("string", "number"):
                    k += 1
                if k < end and toks[k].kind == "word" and toks[k].upper in _DATE_PARTS:
                    k += 1
                return k
            if word in _KEYWORDS:
                return i + 1
            if following is not None and following.kind == "string":
                return i + 1  # a typed literal: DATE '2024-01-01'
            if (
                word in ("TIME", "TIMESTAMP")
                and following is not None
                and following.is_word("WITH", "WITHOUT")
            ):
                return i + 1
            if word in _DATE_PARTS and following is not None and following.is_word("FROM"):
                return i + 1  # EXTRACT(YEAR FROM ...)
        self._check_bare(tok.text, scope)
        return i + 1

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
                    and (prev.upper not in _KEYWORDS or prev.upper in _OPERAND_END_KEYWORDS)
                )
            )
            if prev_ends_operand:
                return b - 1, toks[b - 1]
        return b, None

    @staticmethod
    def _can_be_output_alias(tok: _Tok) -> bool:
        return tok.kind == "qident" or (tok.kind == "word" and tok.upper not in _KEYWORDS)

    def _check_select_list(self, start: int, end: int, scope: _Scope) -> None:
        body = self._skip_modifiers(start, end, scope)
        for a, b in self._entries(body, end):
            if b - a == 1 and self.toks[a].is_punct("*"):
                for ref in scope.refs:
                    self._check_star(ref)
                continue
            expr_end, _alias = self._entry_alias(a, b)
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

    A query that reads a single table returns that table's :func:`validate_access`
    result and leaves the field checks to
    :func:`tolap_core.sql_rewriter.validate_query`, so single-table decisions are
    unchanged. When the caller supplies ``object_name`` it is checked with
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
