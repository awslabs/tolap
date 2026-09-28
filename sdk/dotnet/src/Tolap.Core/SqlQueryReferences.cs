using System.Text;

namespace Tolap.Core;

/// <summary>
/// Validates every table and column a SQL query references, before it runs.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Validate"/> is one of the pre-execution checks the SQL prepare paths run.
/// It resolves the tables a query reads -- <c>FROM</c> and <c>JOIN</c> items,
/// comma-joined tables and derived tables -- into an alias map, checks each table with
/// <see cref="EnforcementEngine.ValidateAccess"/>, and resolves each column reference
/// through that map so the field rules apply to the table the column actually belongs to.
/// </para>
/// <para>
/// The check is deliberately conservative. It does not parse SQL in general; it
/// recognises a common subset of <c>SELECT</c> and refuses, with a reason, any construct
/// it cannot resolve (common table expressions, set operations, subqueries outside
/// <c>FROM</c>, <c>LATERAL</c>, table-valued functions and so on). Refusing is the safe
/// answer: a construct the check cannot see into is one whose tables it cannot vouch for.
/// </para>
/// <para>
/// A query that reads exactly one table still goes through the existing single-table checks
/// (the object check and <see cref="SqlQueryRewriter.ValidateQuery"/>). This check adds to
/// them: it validates that table's access and checks every column the query references, so
/// it can refuse a query they allow but never allow one they refuse.
/// </para>
/// <para>
/// Lexing differs between engines: a backslash escapes a quote in MySQL but not in
/// standard SQL, <c>#</c> starts a comment only in MySQL, and block comments nest only in
/// PostgreSQL. So the query is tokenized under each of those conventions and must pass
/// under every one of them.
/// </para>
/// <para>
/// The Python (<c>sql_references.py</c>) and TypeScript (<c>sql-references.ts</c>)
/// counterparts implement the same rules, pinned by
/// <c>fixtures/enforcement/sql-multi-table.json</c>.
/// </para>
/// </remarks>
public static class SqlQueryReferences
{
    /// <summary>The reason given when a column reference is refused, shared with ValidateQuery.</summary>
    public const string FieldDenialReason =
        "query references fields you do not have permission to access";

    /// <summary>Prefix of the reason given when the query uses a construct the check refuses.</summary>
    public const string UnsupportedReasonPrefix =
        "query uses a construct the pre-execution check cannot resolve: ";

    /// <summary>The reason given when a supplied object name and the query's one table differ.</summary>
    public const string ObjectMismatchReason = "object name does not match the table the query reads";

    // Derived tables nest; each level recurses once. Real queries stay far below this.
    private const int MaxNesting = 32;

    private static readonly HashSet<char> Whitespace = [' ', '\t', '\n', '\r', '\f', '\v'];

    // Unicode whitespace some engines accept as a separator. Treating one as part of a
    // word would hide a keyword, so its presence outside a literal is refused.
    private static readonly HashSet<char> UnicodeSpaces =
    [
        '\u0085', '\u00a0', '\u1680', '\u2000', '\u2001', '\u2002', '\u2003', '\u2004',
        '\u2005', '\u2006', '\u2007', '\u2008', '\u2009', '\u200a', '\u200b', '\u2028',
        '\u2029', '\u202f', '\u205f', '\u3000', '\ufeff',
    ];

    private enum Mode { Ansi, MySql, Postgres }

    private static readonly Mode[] Modes = [Mode.Ansi, Mode.MySql, Mode.Postgres];

    private static HashSet<string> Words(string text) =>
        new(text.Split(' ', StringSplitOptions.RemoveEmptyEntries), StringComparer.Ordinal);

    // Words never taken for a column when bare. Deliberately narrow: an unrecognised
    // word is checked as a column, which can refuse a query but never admits one.
    private static readonly HashSet<string> Keywords = Words(
        "ALL AND ANY ARRAY AS ASC AT BETWEEN BOTH BY CASE CAST COLLATE CROSS CURRENT " +
        "CURRENT_CATALOG CURRENT_DATE CURRENT_ROLE CURRENT_SCHEMA CURRENT_TIME " +
        "CURRENT_TIMESTAMP CURRENT_USER DEFAULT DESC DISTINCT DIV ELSE END ESCAPE " +
        "EVERY EXCLUDE EXISTS FALSE FETCH FILTER FIRST FOLLOWING FROM FULL GLOB " +
        "GROUP GROUPS HAVING ILIKE IN INNER INTERVAL IS ISNULL JOIN LAST LEADING " +
        "LEFT LIKE LIMIT LOCALTIME LOCALTIMESTAMP MOD NATURAL NEXT NO NOT NOTNULL " +
        "NULL NULLS OFFSET ON ONLY OR ORDER ORDINALITY OTHERS OUTER OVER PARTITION " +
        "PRECEDING PRECISION RANGE REGEXP RLIKE ROW ROWS SELECT SEPARATOR " +
        "SESSION_USER SIGNED SIMILAR SOME TABLE THEN TIES TO TRAILING TRUE UNBOUNDED " +
        "UNKNOWN UNSIGNED USING VALUES VARYING WHEN WHERE WITH WITHIN WITHOUT XOR ZONE " +
        "ROLLUP CUBE SETS");

    // Units that may follow INTERVAL or precede FROM inside EXTRACT(...).
    private static readonly HashSet<string> DateParts = Words(
        "CENTURY DAY DAYS DECADE DOW DOY EPOCH HOUR HOURS ISODOW ISOYEAR JULIAN " +
        "MICROSECOND MICROSECONDS MILLENNIUM MILLISECOND MILLISECONDS MINUTE MINUTES " +
        "MONTH MONTHS QUARTER SECOND SECONDS TIMEZONE TIMEZONE_HOUR TIMEZONE_MINUTE " +
        "WEEK WEEKS YEAR YEARS");

    // Reserved words that end the FROM clause and start another clause.
    private static readonly HashSet<string> TailClauses =
        Words("WHERE GROUP HAVING ORDER LIMIT OFFSET FETCH FOR WINDOW WITH");

    // Tail clauses whose content is read for column references, and those skipped.
    private static readonly HashSet<string> CheckedTail = Words("WHERE GROUP HAVING ORDER");
    private static readonly HashSet<string> SkippedTail = Words("LIMIT OFFSET FETCH FOR");

    // The words a skipped tail clause may hold: LIMIT ALL, OFFSET 5 ROWS, FETCH FIRST 5
    // ROWS WITH TIES, FOR NO KEY UPDATE SKIP LOCKED, LOCK IN SHARE MODE. Anything else
    // means a column was taken for the clause keyword (MySQL's WHERE offset = 7), so the
    // clause is refused rather than left unread.
    private static readonly HashSet<string> SkippedTailWords = Words(
        "ALL FIRST NEXT ROW ROWS ONLY WITH TIES PERCENT UPDATE SHARE NO KEY NOWAIT "
        + "SKIP LOCKED LOCK IN MODE");

    private static readonly HashSet<string> JoinWords =
        Words("JOIN INNER LEFT RIGHT FULL CROSS NATURAL OUTER STRAIGHT_JOIN");

    // Words refused as a table alias. Beyond the join and clause words these are the
    // engine-specific table modifiers (hints, sampling, pivots, partitions); taking
    // one for an alias would let what follows it go unread, so it is refused instead.
    private static readonly HashSet<string> NotAnAlias = new(
        JoinWords
            .Concat(TailClauses)
            .Concat(Words(
                "ON USING AS APPLY LATERAL USE FORCE IGNORE PARTITION QUALIFY CONNECT " +
                "START LOCK PIVOT UNPIVOT MODEL SAMPLE TABLESAMPLE RETURNING OPTION " +
                "PROCEDURE INTO UNION INTERSECT EXCEPT MINUS")),
        StringComparer.Ordinal);

    private static readonly HashSet<string> SetOperations = Words("UNION INTERSECT EXCEPT MINUS");

    private static readonly HashSet<string> SelectModifiers = Words(
        "ALL DISTINCTROW SQL_CALC_FOUND_ROWS STRAIGHT_JOIN HIGH_PRIORITY SQL_NO_CACHE " +
        "SQL_CACHE SQL_SMALL_RESULT SQL_BIG_RESULT SQL_BUFFER_RESULT");

    // The value an operand can end with, before a bare alias.
    private static readonly HashSet<string> OperandEndKeywords = Words("END NULL TRUE FALSE UNKNOWN");

    // Words reserved on every modelled engine, so never a bare column: skipped wherever
    // they appear in an expression. Every other word is a keyword only in a position
    // (see Analysis.Bare); anywhere else it is checked as a column. TRUE and FALSE are
    // reserved everywhere but SQL Server, where they are identifiers: there each is also
    // checked against the hidden fields, so a hidden column so named is not read unchecked.
    private static readonly HashSet<string> Reserved = Words(
        "AND CASE CROSS CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP CURRENT_USER "
        + "DISTINCT ELSE FALSE FOR FROM GROUP HAVING IN INNER IS JOIN LEFT LIKE NOT NULL "
        + "ON OR ORDER OUTER THEN TRUE WHEN WHERE WITH");

    // Reserved words that are themselves a value, so a word after one is not an operand.
    private static readonly HashSet<string> ReservedValues = Words(
        "CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP CURRENT_USER NULL TRUE FALSE");

    // Keywords that follow another keyword: ORDER BY, NULLS LAST, SIMILAR TO, WITH ROLLUP,
    // AT TIME ZONE, a window frame's UNBOUNDED PRECEDING and CURRENT ROW. None of the
    // first words is ever followed by an expression, so the second is never a column.
    private static readonly Dictionary<string, HashSet<string>> KeywordPairs = new(StringComparer.Ordinal)
    {
        ["ORDER"] = Words("BY"),
        ["GROUP"] = Words("BY"),
        ["PARTITION"] = Words("BY"),
        ["ASC"] = Words("NULLS SEPARATOR ROWS RANGE GROUPS"),
        ["DESC"] = Words("NULLS SEPARATOR ROWS RANGE GROUPS"),
        ["FIRST"] = Words("SEPARATOR ROWS RANGE GROUPS"),
        ["LAST"] = Words("SEPARATOR ROWS RANGE GROUPS"),
        ["IGNORE"] = Words("NULLS"),
        ["RESPECT"] = Words("NULLS"),
        ["NULLS"] = Words("FIRST LAST"),
        ["SIMILAR"] = Words("TO"),
        ["WITH"] = Words("ROLLUP CUBE TIME"),
        ["WITHOUT"] = Words("TIME"),
        ["AT"] = Words("TIME LOCAL"),
        ["ROWS"] = Words("BETWEEN UNBOUNDED CURRENT"),
        ["RANGE"] = Words("BETWEEN UNBOUNDED CURRENT"),
        ["GROUPS"] = Words("BETWEEN UNBOUNDED CURRENT"),
        ["UNBOUNDED"] = Words("PRECEDING FOLLOWING"),
        ["CURRENT"] = Words("ROW"),
        ["EXCLUDE"] = Words("CURRENT TIES NO"),
        ["NO"] = Words("OTHERS"),
    };

    // The words that may follow an operand: infix and postfix operators, a sort order, a
    // unit after a number (MySQL's INTERVAL 7 DAY_HOUR), and the rest of a cast's type
    // name. A select item's alias is removed before its expression is walked, so any other
    // word after an operand is read as a column: MySQL's INTERVAL zone HOUR reads zone.
    private static readonly HashSet<string> AfterOperand = Words(
        "ILIKE REGEXP RLIKE GLOB SIMILAR BETWEEN ESCAPE DIV MOD XOR SOUNDS OVERLAPS "
        + "ASC DESC NULLS AT FILTER WITHIN RESPECT IGNORE SEPARATOR PRECEDING FOLLOWING "
        + "ROWS RANGE GROUPS PRECISION VARYING INTEGER INT "
        + "SECOND_MICROSECOND MINUTE_MICROSECOND MINUTE_SECOND HOUR_MICROSECOND "
        + "HOUR_SECOND HOUR_MINUTE DAY_MICROSECOND DAY_SECOND DAY_MINUTE DAY_HOUR YEAR_MONTH");

    // Words an engine reads as an operator on the operand that follows: MySQL's BINARY
    // ssn, INTERVAL year HOUR, PostgreSQL's VARIADIC arr. Checked as a column when bare,
    // since they are not reserved, but never taken to end an operand: the word after one
    // is the operand, so it is checked rather than skipped or taken for an alias.
    private static readonly HashSet<string> PrefixOperators = Words("BINARY INTERVAL VARIADIC");

    // Operators written as a word after NOT: a NOT LIKE b, a NOT BETWEEN b AND c.
    private static readonly HashSet<string> NegatedOperators =
        Words("LIKE ILIKE REGEXP RLIKE GLOB SIMILAR BETWEEN IN");

    // The words recognised directly before a string literal: national (N), escape (E),
    // hex (X), bit or bytes (B), raw (R, RB, BR) and typed literals. A MySQL character
    // set introducer (_utf8mb4) is recognised by its leading underscore. Any other word
    // directly before a quote is a form the check does not model, so it is refused.
    private static readonly HashSet<string> LiteralPrefixes = Words("N E X B R RB BR DATE TIME TIMESTAMP");

    /// <summary>
    /// Checks every table and column <paramref name="sql"/> references against the policy.
    /// </summary>
    /// <remarks>
    /// Every table the query reads must pass <see cref="EnforcementEngine.ValidateAccess"/>,
    /// and every column reference is resolved to its table and checked against
    /// <c>hiddenFields</c> and <c>allowedFields</c>. A bare column in a query over several
    /// tables is allowed only by an unqualified <c>allowedFields</c> entry (or <c>*</c>),
    /// because the table it belongs to cannot be known without the schema. Constructs the
    /// check cannot resolve are refused with a reason beginning with
    /// <see cref="UnsupportedReasonPrefix"/>.
    /// <para>
    /// A query that reads a single table has its columns checked here as well as by
    /// <c>ValidateQuery</c>. When the caller supplies <paramref name="objectName"/> it is checked with
    /// <see cref="EnforcementEngine.ValidateAccess"/> as well, and a query over one table
    /// must read that object: a different table is refused with
    /// <see cref="ObjectMismatchReason"/>. Every table of a query is checked whether or not
    /// an object name is supplied.
    /// </para>
    /// <para>
    /// Identifier and literal forms the check does not model are refused rather than
    /// guessed at: Unicode-escape forms (<c>U&amp;"..."</c>, <c>U&amp;'...'</c>), string
    /// literal prefixes other than the recognised ones (such as Oracle's <c>q'[...]'</c>),
    /// triple-quoted literals, identifiers with a non-ASCII character and identifiers that
    /// start with a digit.
    /// </para>
    /// </remarks>
    public static AccessResult Validate(string sql, EffectivePolicy policy, string? objectName = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (objectName is not null)
        {
            var named = EnforcementEngine.ValidateAccess(objectName, policy);
            if (!named.Allowed)
            {
                return named;
            }
        }
        if (string.IsNullOrEmpty(sql))
        {
            return new AccessResult(true);
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var mode in Modes)
        {
            AccessResult result;
            try
            {
                var toks = Lex(sql, mode);
                if (!seen.Add(TokensKey(toks)))
                {
                    continue;
                }
                result = new Analysis(toks, policy, objectName).Run();
            }
            catch (UnsupportedException unsupported)
            {
                return new AccessResult(false, UnsupportedReasonPrefix + unsupported.Construct);
            }
            catch (FieldDeniedException)
            {
                return new AccessResult(false, FieldDenialReason);
            }

            if (!result.Allowed)
            {
                return result;
            }
        }

        return new AccessResult(true);
    }

    private sealed class UnsupportedException(string construct) : Exception(construct)
    {
        public string Construct { get; } = construct;
    }

    private sealed class FieldDeniedException : Exception;

    private enum TokKind { Word, QIdent, String, Number, Param, Punct }

    private sealed class Tok(TokKind kind, string text)
    {
        public TokKind Kind { get; } = kind;

        // The word, the unquoted identifier, or the punctuation character.
        public string Text { get; } = text;

        public string Fold => AsciiLower(Text);

        public string Upper => Kind == TokKind.Word ? AsciiUpper(Text) : "";

        public bool IsWord(params string[] words) =>
            Kind == TokKind.Word && Array.IndexOf(words, AsciiUpper(Text)) >= 0;

        public bool IsPunct(char ch) => Kind == TokKind.Punct && Text.Length == 1 && Text[0] == ch;

        public bool IsIdent => Kind is TokKind.Word or TokKind.QIdent;
    }

    private static string AsciiLower(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            sb.Append(c is >= 'A' and <= 'Z' ? (char)(c + 32) : c);
        }
        return sb.ToString();
    }

    // Keywords are ASCII to every engine, so words are upper-cased ASCII-only: a Unicode
    // case mapping would read "ſelect" (long s) as SELECT.
    private static string AsciiUpper(string text)
    {
        var sb = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            sb.Append(c is >= 'a' and <= 'z' ? (char)(c - 32) : c);
        }
        return sb.ToString();
    }

    private static string TokensKey(List<Tok> toks)
    {
        var sb = new StringBuilder();
        foreach (var t in toks)
        {
            sb.Append((int)t.Kind).Append(':').Append(t.Text.Length).Append(':').Append(t.Text).Append('\u0000');
        }
        return sb.ToString();
    }

    // -----------------------------------------------------------------------
    // Lexing
    // -----------------------------------------------------------------------

    private static bool IsWordStart(char ch) =>
        ch is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or '_' || ch >= 0x80;

    private static bool IsDigit(char ch) => ch is >= '0' and <= '9';

    private static bool IsWordChar(char ch) => IsWordStart(ch) || IsDigit(ch) || ch == '$';

    // Refuses an identifier with a non-ASCII character; engines fold those differently.
    private static string Identifier(string text)
    {
        foreach (var c in text)
        {
            if (c >= 0x80)
            {
                throw new UnsupportedException("non-ASCII identifier");
            }
        }
        return text;
    }

    private static bool IsLiteralPrefix(string word)
    {
        if (LiteralPrefixes.Contains(AsciiUpper(word)))
        {
            return true;
        }
        return word.Length > 1 && word[0] == '_' && word.Skip(1).All(IsWordChar);
    }

    // A numeric literal: digits (with PostgreSQL's digit separators), an optional fraction
    // and exponent, or a hex or binary literal. A token that starts with a digit and is
    // none of these is an identifier some engines accept (MySQL's 1abc), which would
    // otherwise go unread as a column.
    private static bool IsNumericLiteral(string t)
    {
        var n = t.Length;
        if (n > 2 && t[0] == '0' && t[1] is 'x' or 'X')
        {
            return t.Skip(2).All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');
        }
        if (n > 2 && t[0] == '0' && t[1] is 'b' or 'B')
        {
            return t.Skip(2).All(c => c is '0' or '1');
        }
        int k;
        if (n > 0 && IsDigit(t[0]))
        {
            k = 1;
            while (k < n && (IsDigit(t[k]) || t[k] == '_'))
            {
                k++;
            }
            if (k < n && t[k] == '.')
            {
                k++;
                while (k < n && (IsDigit(t[k]) || t[k] == '_'))
                {
                    k++;
                }
            }
        }
        else if (n > 1 && t[0] == '.' && IsDigit(t[1]))
        {
            k = 2;
            while (k < n && (IsDigit(t[k]) || t[k] == '_'))
            {
                k++;
            }
        }
        else
        {
            return false;
        }
        if (k < n && t[k] is 'e' or 'E')
        {
            k++;
            if (k < n && t[k] is '+' or '-')
            {
                k++;
            }
            var digits = k;
            while (k < n && IsDigit(t[k]))
            {
                k++;
            }
            if (k == digits)
            {
                return false;
            }
        }
        return k == n;
    }

    // Whether a supplied object name and a table's name can name the same object. Both
    // are compared part by part, ASCII case-insensitively, from the right. A name with
    // fewer parts matches one qualified further (patients and public.patients); names
    // whose shared parts differ do not (db1.patients and db2.patients).
    private static bool SameObject(string objectName, string[] path)
    {
        var given = objectName.Split('.').Select(AsciiLower).ToArray();
        var k = Math.Min(given.Length, path.Length);
        if (k == 0)
        {
            return false;
        }
        for (var m = 1; m <= k; m++)
        {
            if (!string.Equals(given[^m], path[^m], StringComparison.Ordinal))
            {
                return false;
            }
        }
        return true;
    }

    private static List<Tok> Lex(string sql, Mode mode)
    {
        var toks = new List<Tok>();
        var n = sql.Length;
        var i = 0;
        var inExecutableComment = false;
        while (i < n)
        {
            var ch = sql[i];
            var nxt = i + 1 < n ? sql[i + 1] : '\0';
            var hasNext = i + 1 < n;
            if (Whitespace.Contains(ch))
            {
                i++;
                continue;
            }
            if (UnicodeSpaces.Contains(ch))
            {
                throw new UnsupportedException("non-ASCII whitespace");
            }

            // Comments.
            if (ch == '-' && hasNext && nxt == '-')
            {
                if (mode != Mode.MySql || i + 2 >= n || MySqlDashCommentFollower(sql[i + 2]))
                {
                    i = LineCommentEnd(sql, i);
                    continue;
                }
            }
            if (ch == '#' && mode == Mode.MySql)
            {
                i = LineCommentEnd(sql, i);
                continue;
            }
            if (ch == '/' && hasNext && nxt == '*')
            {
                if (mode == Mode.MySql && i + 2 < n && sql[i + 2] == '!')
                {
                    // Executable comment: its body is SQL to MySQL.
                    i += 3;
                    while (i < n && IsDigit(sql[i]))
                    {
                        i++;
                    }
                    inExecutableComment = true;
                    continue;
                }
                i = SkipBlockComment(sql, i, mode == Mode.Postgres);
                continue;
            }
            if (ch == '*' && hasNext && nxt == '/' && inExecutableComment)
            {
                inExecutableComment = false;
                i += 2;
                continue;
            }

            // Literals and quoted identifiers.
            if (ch == '&' && hasNext && nxt is '\'' or '"' && i > 0 && IsWordChar(sql[i - 1]))
            {
                throw new UnsupportedException("Unicode escape"); // U&'...' and U&"..."
            }
            if (ch is '\'' or '"' && i + 2 < n && sql[i + 1] == ch && sql[i + 2] == ch)
            {
                throw new UnsupportedException("triple-quoted literal");
            }
            if (ch == '\'')
            {
                var prev = toks.Count > 0 ? toks[^1] : null;
                var backslash = mode == Mode.MySql
                    || (mode == Mode.Postgres
                        && prev is { Kind: TokKind.Word }
                        && prev.Text is "E" or "e"
                        && Adjacent(sql, i));
                if (prev is { Kind: TokKind.Word } && Adjacent(sql, i))
                {
                    // A literal prefix (N'', E'', X'', _utf8'') belongs to the literal.
                    if (!IsLiteralPrefix(prev.Text))
                    {
                        throw new UnsupportedException("string literal prefix");
                    }
                    toks.RemoveAt(toks.Count - 1);
                }
                i = SkipQuoted(sql, i, '\'', backslash);
                toks.Add(new Tok(TokKind.String, ""));
                continue;
            }
            if (ch == '"')
            {
                if (mode == Mode.MySql)
                {
                    i = SkipQuoted(sql, i, '"', true);
                    toks.Add(new Tok(TokKind.String, ""));
                }
                else
                {
                    var end = SkipQuoted(sql, i, '"', false);
                    toks.Add(new Tok(TokKind.QIdent, Identifier(Unquote(Body(sql, i, end), '"'))));
                    i = end;
                }
                continue;
            }
            if (ch == '`')
            {
                var end = SkipQuoted(sql, i, '`', false);
                toks.Add(new Tok(TokKind.QIdent, Identifier(Unquote(Body(sql, i, end), '`'))));
                i = end;
                continue;
            }
            if (ch == '[' && mode == Mode.Ansi)
            {
                var end = SkipQuoted(sql, i, ']', false);
                toks.Add(new Tok(TokKind.QIdent, Identifier(Unquote(Body(sql, i, end), ']'))));
                i = end;
                continue;
            }
            if (ch == '$')
            {
                if (hasNext && IsDigit(nxt))
                {
                    var j = i + 1;
                    while (j < n && IsDigit(sql[j]))
                    {
                        j++;
                    }
                    toks.Add(new Tok(TokKind.Param, sql[i..j]));
                    i = j;
                    continue;
                }
                if (mode == Mode.Postgres)
                {
                    var j = i + 1;
                    while (j < n && (IsWordStart(sql[j]) || IsDigit(sql[j])))
                    {
                        j++;
                    }
                    if (j < n && sql[j] == '$' && !(hasNext && IsDigit(nxt)))
                    {
                        var tag = sql[i..(j + 1)];
                        var end = sql.IndexOf(tag, j + 1, StringComparison.Ordinal);
                        i = end < 0 ? n : end + tag.Length;
                        toks.Add(new Tok(TokKind.String, ""));
                        continue;
                    }
                }
            }

            // Numbers, words, parameters, punctuation.
            if (IsDigit(ch) || (ch == '.' && hasNext && IsDigit(nxt)))
            {
                var j = i + 1;
                while (j < n && (IsWordChar(sql[j]) || sql[j] == '.'))
                {
                    if (sql[j] is 'e' or 'E' && j + 1 < n && sql[j + 1] is '+' or '-')
                    {
                        j++;
                    }
                    j++;
                }
                if (!IsNumericLiteral(sql[i..j]))
                {
                    throw new UnsupportedException("identifier starting with a digit");
                }
                toks.Add(new Tok(TokKind.Number, sql[i..j]));
                i = j;
                continue;
            }
            if (IsWordStart(ch) || ch == '$')
            {
                var j = i + 1;
                while (j < n && IsWordChar(sql[j]))
                {
                    if (UnicodeSpaces.Contains(sql[j]))
                    {
                        throw new UnsupportedException("non-ASCII whitespace");
                    }
                    j++;
                }
                toks.Add(new Tok(TokKind.Word, Identifier(sql[i..j])));
                i = j;
                continue;
            }
            if (ch == '?')
            {
                toks.Add(new Tok(TokKind.Param, "?"));
                i++;
                continue;
            }
            toks.Add(new Tok(TokKind.Punct, ch.ToString()));
            i++;
        }
        return toks;
    }

    // The text between an opening quote at start and the index just past its close,
    // which is one past the end of the input when the literal is unterminated.
    private static string Body(string sql, int start, int end) =>
        sql.Substring(start + 1, Math.Min(end - 1, sql.Length) - (start + 1));

    // Whether MySQL starts a `--` comment given the next character: a space or any
    // control character (U+0000-U+0020 and U+007F). End of input is checked by the caller.
    private static bool MySqlDashCommentFollower(char after) => after <= '\u0020' || after == '\u007f';

    // Index just past a line comment, which ends at a line feed. Engines disagree on a
    // carriage return: PostgreSQL and Trino end the comment there, MySQL does not.
    // Either reading can hide SQL that the other executes, so a carriage return inside
    // a line comment is refused unless it is part of a CRLF.
    private static int LineCommentEnd(string sql, int start)
    {
        var end = sql.IndexOf('\n', start);
        var stop = end < 0 ? sql.Length : end;
        for (var k = start; k < stop; k++)
        {
            if (sql[k] == '\r' && k + 1 != end)
            {
                throw new UnsupportedException("carriage return in comment");
            }
        }
        return end < 0 ? sql.Length : end + 1;
    }

    // Whether the character before the quote belongs to the preceding word.
    private static bool Adjacent(string sql, int quoteIndex) =>
        quoteIndex > 0 && IsWordChar(sql[quoteIndex - 1]);

    private static int SkipBlockComment(string sql, int start, bool nested)
    {
        var depth = 0;
        var i = start;
        var n = sql.Length;
        while (i < n)
        {
            if (i + 1 < n && sql[i] == '/' && sql[i + 1] == '*')
            {
                depth++;
                i += 2;
                if (!nested && depth > 1)
                {
                    depth = 1;
                }
                continue;
            }
            if (i + 1 < n && sql[i] == '*' && sql[i + 1] == '/')
            {
                depth--;
                i += 2;
                if (depth == 0)
                {
                    return i;
                }
                continue;
            }
            i++;
        }
        return n;
    }

    // Index just past the literal or identifier opened at start.
    private static int SkipQuoted(string sql, int start, char close, bool backslash)
    {
        var i = start + 1;
        var n = sql.Length;
        while (i < n)
        {
            var ch = sql[i];
            if (backslash && ch == '\\')
            {
                i += 2;
                continue;
            }
            if (ch == close)
            {
                if (i + 1 < n && sql[i + 1] == close)
                {
                    i += 2;
                    continue;
                }
                return i + 1;
            }
            i++;
        }
        return n + 1;
    }

    private static string Unquote(string body, char close) =>
        body.Replace(new string(close, 2), close.ToString(), StringComparison.Ordinal);

    // -----------------------------------------------------------------------
    // Structure
    // -----------------------------------------------------------------------

    // A table or derived table in a FROM clause. Table is the base table's name, or null
    // when it cannot be resolved; Names are the ASCII-folded names a column qualifier
    // may use for it; Path is a base table's ASCII-folded name, part by part.
    private sealed class Ref(string? table, HashSet<string> names, bool derived, string[]? path = null)
    {
        public string? Table { get; } = table;
        public HashSet<string> Names { get; } = names;
        public bool Derived { get; } = derived;
        public string[] Path { get; } = path ?? [];
    }

    private sealed class Scope
    {
        public List<Ref> Refs { get; } = [];
        public Dictionary<string, Ref> ByName { get; } = new(StringComparer.Ordinal);

        public void Add(Ref r)
        {
            foreach (var name in r.Names)
            {
                if (!ByName.TryAdd(name, r))
                {
                    throw new UnsupportedException("duplicate table name");
                }
            }
            Refs.Add(r);
        }
    }

    // What a FROM clause holds: its tables, derived-table bodies and join conditions.
    private sealed class FromClause
    {
        public Scope Scope { get; } = new();
        public List<(int Start, int End)> Derived { get; } = [];
        public List<(int Start, int End)> On { get; } = [];
        public List<(List<string> Cols, List<Ref> Refs)> Using { get; } = [];
        public bool Natural { get; set; }
    }

    private sealed class Analysis
    {
        private readonly List<Tok> _toks;
        private readonly EffectivePolicy _policy;
        private readonly string? _objectName;
        private readonly string[] _hidden;
        private readonly string[]? _allowed;
        private readonly Dictionary<int, int> _match;

        public Analysis(List<Tok> toks, EffectivePolicy policy, string? objectName)
        {
            _toks = toks;
            _policy = policy;
            _objectName = objectName;
            var rules = policy.ObjectRules?.FieldRules;
            _hidden = rules?.HiddenFields ?? [];
            _allowed = rules?.AllowedFields;
            _match = MatchParens();
        }

        private Dictionary<int, int> MatchParens()
        {
            var stack = new Stack<int>();
            var match = new Dictionary<int, int>();
            for (var idx = 0; idx < _toks.Count; idx++)
            {
                if (_toks[idx].IsPunct('('))
                {
                    stack.Push(idx);
                }
                else if (_toks[idx].IsPunct(')'))
                {
                    if (stack.Count == 0)
                    {
                        throw new UnsupportedException("unbalanced parentheses");
                    }
                    match[stack.Pop()] = idx;
                }
            }
            if (stack.Count > 0)
            {
                throw new UnsupportedException("unbalanced parentheses");
            }
            return match;
        }

        // Indices in [start, end) outside any parentheses opened in that range.
        private IEnumerable<int> TopLevel(int start, int end)
        {
            var i = start;
            while (i < end)
            {
                yield return i;
                i = _toks[i].IsPunct('(') ? _match[i] + 1 : i + 1;
            }
        }

        // -- statement -----------------------------------------------------

        public AccessResult Run()
        {
            var end = _toks.Count;
            while (end > 0 && _toks[end - 1].IsPunct(';'))
            {
                end--;
            }
            for (var idx = 0; idx < end; idx++)
            {
                if (_toks[idx].IsPunct(';'))
                {
                    throw new UnsupportedException("multiple statements");
                }
            }
            if (end == 0)
            {
                return new AccessResult(true);
            }
            if (_toks[0].IsWord("WITH"))
            {
                throw new UnsupportedException("WITH");
            }
            if (!_toks[0].IsWord("SELECT"))
            {
                throw new UnsupportedException("statement other than SELECT");
            }
            return Select(0, end, 0);
        }

        // Check the SELECT spanning [start, end); start is the SELECT keyword.
        private AccessResult Select(int start, int end, int depth)
        {
            if (depth > MaxNesting)
            {
                throw new UnsupportedException("nesting depth");
            }
            var fromAt = FindFrom(start, end);
            int selectEnd;
            int tailAt;
            FromClause clause;
            if (fromAt is null)
            {
                selectEnd = TailStart(start + 1, end);
                tailAt = selectEnd;
                clause = new FromClause();
            }
            else
            {
                selectEnd = fromAt.Value;
                tailAt = TailStart(fromAt.Value + 1, end);
                clause = ParseFrom(fromAt.Value + 1, tailAt);
            }
            var tails = SplitTail(tailAt, end);
            var scope = clause.Scope;

            if (depth == 0 && scope.Refs.Count <= 1 && clause.Derived.Count == 0)
            {
                // At most one table: check its access and refuse anything that reaches a
                // further table. Its columns are checked below as well as by the
                // single-table checks, so a column either check misses is still caught.
                for (var idx = start + 1; idx < end; idx++)
                {
                    if (_toks[idx].IsWord("SELECT", "TABLE"))
                    {
                        throw new UnsupportedException("subquery");
                    }
                }
                if (scope.Refs.Count == 0)
                {
                    return new AccessResult(true);
                }
                var only = scope.Refs[0];
                var onlyAccess = EnforcementEngine.ValidateAccess(only.Table ?? "", _policy);
                if (!onlyAccess.Allowed)
                {
                    return onlyAccess;
                }
                // A supplied object name must name the table the query reads; otherwise
                // the object checked is not the object read.
                if (_objectName is not null && !SameObject(_objectName, only.Path))
                {
                    return new AccessResult(false, ObjectMismatchReason);
                }
            }

            foreach (var r in scope.Refs)
            {
                if (!r.Derived && r.Table is not null)
                {
                    var access = EnforcementEngine.ValidateAccess(r.Table, _policy);
                    if (!access.Allowed)
                    {
                        return access;
                    }
                }
            }
            foreach (var (innerStart, innerEnd) in clause.Derived)
            {
                var inner = Select(innerStart, innerEnd, depth + 1);
                if (!inner.Allowed)
                {
                    return inner;
                }
            }

            CheckSelectList(start + 1, selectEnd, scope);
            foreach (var (a, b) in clause.On)
            {
                Walk(a, b, scope);
            }
            foreach (var (cols, refs) in clause.Using)
            {
                foreach (var col in cols)
                {
                    foreach (var r in refs)
                    {
                        CheckColumn(r, col);
                    }
                }
            }
            if (clause.Natural && (_hidden.Length > 0 || (_allowed is not null && !AllowsEverything())))
            {
                throw new UnsupportedException("NATURAL JOIN");
            }
            var aliases = SelectAliases(start + 1, selectEnd);
            foreach (var (word, a, b) in tails)
            {
                if (a >= b)
                {
                    throw new UnsupportedException($"empty {word} clause");
                }
                if (SkippedTail.Contains(word))
                {
                    CheckSkippedTail(word, a, b);
                }
                else if (word == "ORDER")
                {
                    CheckOrderBy(a, b, scope, aliases);
                }
                else
                {
                    Walk(a, b, scope);
                }
            }
            return new AccessResult(true);
        }

        // Refuse a LIMIT, OFFSET, FETCH or FOR clause holding anything but its own words,
        // numbers and parameters (and, after FOR ... OF, table names).
        private void CheckSkippedTail(string word, int start, int end)
        {
            var names = false;
            for (var idx = start; idx < end; idx++)
            {
                var tok = _toks[idx];
                if (tok.IsWord("SELECT", "TABLE"))
                {
                    throw new UnsupportedException("subquery");
                }
                if (word == "FOR" && tok.IsWord("OF"))
                {
                    names = true;
                    continue;
                }
                if (tok.Kind is TokKind.Number or TokKind.Param
                    || (tok.Kind == TokKind.Punct && tok.Text is "," or "(" or ")"))
                {
                    continue;
                }
                if (tok.Kind == TokKind.Word && SkippedTailWords.Contains(tok.Upper))
                {
                    continue;
                }
                if (names && (tok.IsIdent || tok.IsPunct('.')))
                {
                    continue;
                }
                throw new UnsupportedException($"{word} clause");
            }
        }

        // The SELECT's own FROM keyword, refusing set operations and SELECT INTO.
        private int? FindFrom(int start, int end)
        {
            int? fromAt = null;
            foreach (var idx in TopLevel(start + 1, end))
            {
                var tok = _toks[idx];
                if (tok.Kind != TokKind.Word)
                {
                    continue;
                }
                var word = tok.Upper;
                if (SetOperations.Contains(word))
                {
                    throw new UnsupportedException("set operation");
                }
                if (word == "INTO")
                {
                    throw new UnsupportedException("SELECT INTO");
                }
                if (word == "FROM" && !IsDistinctFrom(idx, start))
                {
                    if (fromAt is not null)
                    {
                        throw new UnsupportedException("FROM clause");
                    }
                    fromAt = idx;
                }
            }
            return fromAt;
        }

        // "a IS [NOT] DISTINCT FROM b" is a comparison, not a FROM clause.
        private bool IsDistinctFrom(int idx, int start) =>
            idx - 2 > start && _toks[idx - 1].IsWord("DISTINCT") && _toks[idx - 2].IsWord("IS", "NOT");

        private bool IsTailMark(int idx)
        {
            var tok = _toks[idx];
            if (tok.Kind != TokKind.Word || !TailClauses.Contains(tok.Upper))
            {
                return false;
            }
            if (tok.Upper == "WITH")
            {
                // TIME WITH TIME ZONE, FETCH ... ROWS WITH TIES, GROUP BY ... WITH ROLLUP.
                if (idx > 0 && _toks[idx - 1].IsWord("TIME", "TIMESTAMP", "ROW", "ROWS"))
                {
                    return false;
                }
                if (idx + 1 < _toks.Count && _toks[idx + 1].IsWord("TIES", "ROLLUP", "CUBE"))
                {
                    return false;
                }
            }
            return true;
        }

        private int TailStart(int start, int end)
        {
            foreach (var idx in TopLevel(start, end))
            {
                if (IsTailMark(idx))
                {
                    return idx;
                }
            }
            return end;
        }

        // The tail clauses as (keyword, content start, content end).
        private List<(string Word, int Start, int End)> SplitTail(int start, int end)
        {
            var marks = TopLevel(start, end).Where(IsTailMark).ToList();
            var tails = new List<(string, int, int)>();
            for (var pos = 0; pos < marks.Count; pos++)
            {
                var idx = marks[pos];
                var word = _toks[idx].Upper;
                if (!CheckedTail.Contains(word) && !SkippedTail.Contains(word))
                {
                    throw new UnsupportedException(word);
                }
                var contentStart = idx + 1;
                if (word is "GROUP" or "ORDER" && contentStart < end && _toks[contentStart].IsWord("BY"))
                {
                    contentStart++;
                }
                var contentEnd = pos + 1 < marks.Count ? marks[pos + 1] : end;
                tails.Add((word, contentStart, contentEnd));
            }
            return tails;
        }

        // -- FROM ----------------------------------------------------------

        private FromClause ParseFrom(int start, int end)
        {
            var clause = new FromClause();
            var i = ParseItem(start, end, clause);
            while (i < end)
            {
                if (_toks[i].IsPunct(','))
                {
                    i = ParseItem(i + 1, end, clause);
                    continue;
                }
                if (_toks[i].IsWord("NATURAL"))
                {
                    clause.Natural = true;
                    i++;
                }
                if (i + 1 < end && _toks[i].IsWord("CROSS", "OUTER") && _toks[i + 1].IsWord("APPLY"))
                {
                    throw new UnsupportedException("APPLY");
                }
                if (i < end && _toks[i].IsWord("INNER", "CROSS"))
                {
                    i++;
                }
                else if (i < end && _toks[i].IsWord("LEFT", "RIGHT", "FULL"))
                {
                    i++;
                    if (i < end && _toks[i].IsWord("OUTER"))
                    {
                        i++;
                    }
                }
                if (!(i < end && _toks[i].IsWord("JOIN", "STRAIGHT_JOIN")))
                {
                    throw new UnsupportedException("FROM clause");
                }
                var left = clause.Scope.Refs.ToList();
                i = ParseItem(i + 1, end, clause);
                var right = clause.Scope.Refs[^1];
                if (i < end && _toks[i].IsWord("ON"))
                {
                    var onEnd = end;
                    foreach (var idx in TopLevel(i + 1, end))
                    {
                        if (_toks[idx].IsPunct(',') || IsJoinWord(idx, end))
                        {
                            onEnd = idx;
                            break;
                        }
                    }
                    clause.On.Add((i + 1, onEnd));
                    i = onEnd;
                }
                else if (i < end && _toks[i].IsWord("USING"))
                {
                    if (!(i + 1 < end && _toks[i + 1].IsPunct('(')))
                    {
                        throw new UnsupportedException("FROM clause");
                    }
                    var close = _match[i + 1];
                    var cols = new List<string>();
                    for (var idx = i + 2; idx < close; idx++)
                    {
                        var tok = _toks[idx];
                        if (tok.IsIdent)
                        {
                            cols.Add(tok.Text);
                        }
                        else if (!tok.IsPunct(','))
                        {
                            throw new UnsupportedException("FROM clause");
                        }
                    }
                    left.Add(right);
                    clause.Using.Add((cols, left));
                    i = close + 1;
                }
            }
            return clause;
        }

        // LEFT(...) and RIGHT(...) in a join condition are functions, not joins.
        private bool IsJoinWord(int idx, int end)
        {
            var tok = _toks[idx];
            if (tok.Kind != TokKind.Word || !JoinWords.Contains(tok.Upper))
            {
                return false;
            }
            return !(idx + 1 < end && _toks[idx + 1].IsPunct('('));
        }

        private int ParseItem(int start, int end, FromClause clause)
        {
            if (start >= end)
            {
                throw new UnsupportedException("FROM clause");
            }
            var tok = _toks[start];
            if (tok.IsWord("LATERAL"))
            {
                throw new UnsupportedException("LATERAL");
            }
            int i;
            Tok? alias;
            if (tok.IsPunct('('))
            {
                var close = _match[start];
                if (!(start + 1 < close && _toks[start + 1].IsWord("SELECT")))
                {
                    throw new UnsupportedException("parenthesized join");
                }
                clause.Derived.Add((start + 1, close));
                (alias, i) = ParseAlias(close + 1, end);
                if (i < end && _toks[i].IsPunct('('))
                {
                    i = _match[i] + 1; // column aliases rename the derived table's outputs
                }
                var table = SingleBaseTable(start + 1, close);
                var derivedNames = alias is null
                    ? new HashSet<string>(StringComparer.Ordinal)
                    : new HashSet<string>(StringComparer.Ordinal) { alias.Fold };
                clause.Scope.Add(new Ref(table, derivedNames, true));
                return i;
            }
            if (!tok.IsIdent
                || (tok.Kind == TokKind.Word && (Keywords.Contains(tok.Upper) || NotAnAlias.Contains(tok.Upper))))
            {
                throw new UnsupportedException("FROM clause");
            }
            var parts = new List<Tok> { tok };
            i = start + 1;
            while (i + 1 < end && _toks[i].IsPunct('.') && _toks[i + 1].IsIdent)
            {
                parts.Add(_toks[i + 1]);
                i += 2;
            }
            if (i < end && _toks[i].IsPunct('('))
            {
                throw new UnsupportedException("table-valued function");
            }
            (alias, i) = ParseAlias(i, end);
            if (i < end && _toks[i].IsPunct('('))
            {
                throw new UnsupportedException("column alias list");
            }
            var leafTok = parts[^1];
            var leaf = leafTok.Text;
            if (leafTok.Kind == TokKind.QIdent && leaf.Contains('.'))
            {
                leaf = leaf[(leaf.LastIndexOf('.') + 1)..];
            }
            var names = new HashSet<string>(StringComparer.Ordinal);
            if (alias is not null)
            {
                names.Add(alias.Fold);
            }
            else
            {
                var folded = parts.Select(p => p.Fold).ToList();
                for (var k = 0; k < folded.Count; k++)
                {
                    names.Add(string.Join(".", folded.Skip(k)));
                }
            }
            var path = parts
                .SelectMany(p => p.Kind == TokKind.QIdent ? p.Text.Split('.') : [p.Text])
                .Select(AsciiLower)
                .ToArray();
            clause.Scope.Add(new Ref(leaf, names, false, path));
            return i;
        }

        private (Tok? Alias, int Next) ParseAlias(int i, int end)
        {
            if (i < end && _toks[i].IsWord("AS"))
            {
                if (i + 1 < end && CanAlias(_toks[i + 1]))
                {
                    return (_toks[i + 1], i + 2);
                }
                throw new UnsupportedException("FROM clause");
            }
            if (i < end && CanAlias(_toks[i]))
            {
                return (_toks[i], i + 1);
            }
            return (null, i);
        }

        private static bool CanAlias(Tok tok) =>
            tok.Kind == TokKind.QIdent
            || (tok.Kind == TokKind.Word && !NotAnAlias.Contains(tok.Upper) && !Keywords.Contains(tok.Upper));

        // The one base table a derived table reads, or null when there is not exactly one.
        private string? SingleBaseTable(int start, int end)
        {
            var fromAt = FindFrom(start, end);
            if (fromAt is null)
            {
                return null;
            }
            var inner = ParseFrom(fromAt.Value + 1, TailStart(fromAt.Value + 1, end));
            return inner.Scope.Refs.Count == 1 && inner.Derived.Count == 0 ? inner.Scope.Refs[0].Table : null;
        }

        // -- field rules ---------------------------------------------------

        private bool AllowsEverything() => _allowed is not null && _allowed.Any(a => a.Trim() == "*");

        // Check a table-qualified column against both field rules.
        private void CheckName(string name)
        {
            if (_hidden.Any(h => EnforcementEngine.FieldNameMatches(h, name)))
            {
                throw new FieldDeniedException();
            }
            if (_allowed is not null && !_allowed.Any(a => EnforcementEngine.AllowedFieldMatches(a, name)))
            {
                throw new FieldDeniedException();
            }
        }

        // Check a column whose table is unknown: only an unqualified entry can allow it.
        private void CheckUnresolved(string col)
        {
            if (_hidden.Any(h => EnforcementEngine.FieldNameMatches(h, col)))
            {
                throw new FieldDeniedException();
            }
            if (_allowed is not null
                && !_allowed.Any(a => !a.Contains('.') && EnforcementEngine.FieldNameMatches(a, col)))
            {
                throw new FieldDeniedException();
            }
        }

        private void CheckColumn(Ref r, string col)
        {
            if (r.Table is null)
            {
                CheckUnresolved(col);
            }
            else
            {
                CheckName($"{r.Table}.{col}");
            }
        }

        private void CheckBare(string col, Scope scope)
        {
            if (scope.Refs.Count == 1)
            {
                CheckColumn(scope.Refs[0], col);
            }
            else
            {
                CheckUnresolved(col);
            }
        }

        // Refuse col if it may name a hidden column of any table in scope.
        private void CheckHidden(string col, Scope scope)
        {
            foreach (var r in scope.Refs)
            {
                var name = r.Table is null ? col : $"{r.Table}.{col}";
                if (_hidden.Any(h => EnforcementEngine.FieldNameMatches(h, name)))
                {
                    throw new FieldDeniedException();
                }
            }
            if (scope.Refs.Count == 0 && _hidden.Any(h => EnforcementEngine.FieldNameMatches(h, col)))
            {
                throw new FieldDeniedException();
            }
        }

        // t.*: hidden fields are stripped after the fetch, but an allow-list must fit. The
        // fetched keys are bare column names, so an entry qualified with another table
        // would admit this table's column of the same name. The star is allowed only when
        // every qualified entry names this table.
        private void CheckStar(Ref r)
        {
            if (_allowed is null || AllowsEverything())
            {
                return;
            }
            var table = r.Table is null ? null : AsciiLower(r.Table);
            foreach (var entry in _allowed)
            {
                var dot = entry.LastIndexOf('.');
                if (dot >= 0 && (table is null || AsciiLower(entry[..dot]) != table))
                {
                    throw new FieldDeniedException();
                }
            }
        }

        // -- expressions ---------------------------------------------------

        // Check every column reference in the expression tokens [start, end).
        private void Walk(int start, int end, Scope scope)
        {
            var ends = new HashSet<int>(); // words that end an operand
            var windows = new HashSet<int>(); // the "(" opening each OVER (...) window
            var brackets = new List<int>();
            var i = start;
            while (i < end)
            {
                var tok = _toks[i];
                if (tok.Kind == TokKind.Punct)
                {
                    if (tok.Text is "(" or "[")
                    {
                        brackets.Add(i);
                    }
                    else if (tok.Text is ")" or "]" && brackets.Count > 0)
                    {
                        brackets.RemoveAt(brackets.Count - 1);
                    }
                    else if (tok.Text == ":" && i + 2 < end && _toks[i + 1].IsPunct(':'))
                    {
                        if (_toks[i + 2].IsIdent)
                        {
                            ends.Add(i + 2);
                            i += 3; // a cast's target type
                            continue;
                        }
                    }
                    else if (tok.Text == ":" && i + 1 < end && _toks[i + 1].IsIdent
                             && !(brackets.Count > 0 && _toks[brackets[^1]].IsPunct('[')))
                    {
                        ends.Add(i + 1);
                        i += 2; // a named bind parameter; inside [...] it is a slice bound
                        continue;
                    }
                    i++;
                    continue;
                }
                if (!tok.IsIdent)
                {
                    i++;
                    continue;
                }
                var parts = new List<Tok> { tok };
                var j = i;
                while (j + 2 < end
                       && _toks[j + 1].IsPunct('.')
                       && (_toks[j + 2].IsIdent || _toks[j + 2].IsPunct('*')))
                {
                    parts.Add(_toks[j + 2]);
                    j += 2;
                    if (parts[^1].IsPunct('*'))
                    {
                        break;
                    }
                }
                var lastPart = parts[^1];
                if (j + 1 < end && _toks[j + 1].IsPunct('(') && !lastPart.IsPunct('*'))
                {
                    if (j == i && tok.IsWord("OVER") && i > start && _toks[i - 1].IsPunct(')'))
                    {
                        windows.Add(i + 1);
                    }
                    i = j + 1; // a function name; its arguments are walked
                    continue;
                }
                if (parts.Count == 1)
                {
                    var inWindow = brackets.Count > 0 && windows.Contains(brackets[^1]);
                    i = Bare(i, start, end, scope, ends, inWindow);
                    continue;
                }
                var qualifier = string.Join(".", parts.Take(parts.Count - 1).Select(p => p.Fold));
                if (!scope.ByName.TryGetValue(qualifier, out var r))
                {
                    throw new UnsupportedException("unresolved qualifier");
                }
                if (lastPart.IsPunct('*'))
                {
                    CheckStar(r);
                }
                else
                {
                    CheckColumn(r, lastPart.Text);
                    ends.Add(j);
                }
                i = j + 1;
            }
        }

        // Whether token k of the walk that began at start ends an operand.
        private bool EndsOperand(int k, int start, HashSet<int> ends)
        {
            if (k < start)
            {
                return false;
            }
            var tok = _toks[k];
            return tok.Kind is TokKind.QIdent or TokKind.String or TokKind.Number or TokKind.Param
                || tok.IsPunct(')')
                || tok.IsPunct(']')
                || ends.Contains(k);
        }

        // Handle a lone identifier at i; return the index to continue from.
        //
        // A word is skipped only where it cannot be a column: a reserved word, a word
        // directly after an operand (an operator, ASC, an alias), the second word of a
        // keyword pair, or a window's frame words. Anywhere else it is checked, so a
        // column named like a keyword (zone, first) is still read as one.
        private int Bare(int i, int start, int end, Scope scope, HashSet<int> ends, bool inWindow)
        {
            var tok = _toks[i];
            var following = i + 1 < end ? _toks[i + 1] : null;
            var prev = i - 1 >= start ? _toks[i - 1] : null;
            var prev2 = i - 2 >= start ? _toks[i - 2] : null;
            if (tok.Kind == TokKind.Word)
            {
                var word = tok.Upper;
                if (word is "SELECT" or "TABLE")
                {
                    throw new UnsupportedException("subquery");
                }
                if (word is "AS" or "COLLATE")
                {
                    // An alias or cast type, or a collation.
                    if (following is not null && following.IsIdent)
                    {
                        ends.Add(i + 1);
                        return i + 2;
                    }
                    return i + 1;
                }
                if (Reserved.Contains(word))
                {
                    if (word is "TRUE" or "FALSE")
                    {
                        CheckHidden(tok.Text, scope);
                    }
                    if (ReservedValues.Contains(word))
                    {
                        ends.Add(i);
                    }
                    return i + 1;
                }
                if (word == "OVER" && prev is not null && prev.IsPunct(')'))
                {
                    if (following is not null && following.IsIdent)
                    {
                        ends.Add(i + 1);
                        return i + 2; // a named window
                    }
                    return i + 1;
                }
                if (EndsOperand(i - 1, start, ends))
                {
                    if (OperandEndKeywords.Contains(word) || word is "ISNULL" or "NOTNULL")
                    {
                        ends.Add(i);
                        return i + 1;
                    }
                    if (AfterOperand.Contains(word) || DateParts.Contains(word))
                    {
                        return i + 1; // an operator or modifier: DIV, ASC, BETWEEN, AT
                    }
                }
                if (prev is { Kind: TokKind.Word })
                {
                    var before = prev.Upper;
                    if (KeywordPairs.TryGetValue(before, out var seconds) && seconds.Contains(word)
                        // WITH TIME is only a keyword pair ahead of ZONE
                        && !(word == "TIME" && !(following is not null && following.IsWord("ZONE"))))
                    {
                        return i + 1;
                    }
                    if (word == "ZONE" && before == "TIME" && prev2 is not null
                        && prev2.IsWord("WITH", "WITHOUT", "AT"))
                    {
                        return i + 1;
                    }
                    if (before == "IS" || (before == "NOT" && prev2 is not null && prev2.IsWord("IS")))
                    {
                        ends.Add(i);
                        return i + 1; // IS [NOT] UNKNOWN, IS JSON, IS DISTINCT FROM
                    }
                    if (before == "NOT" && NegatedOperators.Contains(word) && EndsOperand(i - 2, start, ends))
                    {
                        return i + 1; // a NOT BETWEEN b; a prefix NOT is followed by a value
                    }
                }
                if (inWindow && FrameWord(i, following, prev))
                {
                    return i + 1;
                }
                if (prev is not null && prev.IsPunct('(') && prev2 is not null)
                {
                    if (DateParts.Contains(word) && prev2.IsWord("EXTRACT"))
                    {
                        return i + 1; // EXTRACT(YEAR FROM ...)
                    }
                    if (word is "BOTH" or "LEADING" or "TRAILING" && prev2.IsWord("TRIM"))
                    {
                        return i + 1; // TRIM(LEADING 'x' FROM ...)
                    }
                }
                if (word == "INTERVAL")
                {
                    var k = IntervalLiteralEnd(i, end);
                    if (k is int past)
                    {
                        ends.Add(past - 1);
                        return past;
                    }
                    if (following is not null && following.IsIdent && i + 2 < end
                        && _toks[i + 2].Kind == TokKind.Word && DateParts.Contains(_toks[i + 2].Upper))
                    {
                        return i + 1; // MySQL's INTERVAL n DAY
                    }
                }
                if (word is "DATE" or "TIME" or "TIMESTAMP")
                {
                    if (following is { Kind: TokKind.String })
                    {
                        return i + 1; // a typed literal: DATE '2024-01-01'
                    }
                    if (following is not null && following.IsWord("WITH", "WITHOUT") && i + 3 < end
                        && _toks[i + 2].IsWord("TIME") && _toks[i + 3].IsWord("ZONE"))
                    {
                        return i + 4; // TIMESTAMP WITH TIME ZONE '...'
                    }
                }
                if (word == "ARRAY" && following is not null && following.IsPunct('['))
                {
                    return i + 1; // an array constructor: ARRAY[1, 2]
                }
                if (word == "GROUPING" && following is not null && following.IsWord("SETS"))
                {
                    return i + 1;
                }
            }
            CheckBare(tok.Text, scope);
            if (!(tok.Kind == TokKind.Word && PrefixOperators.Contains(tok.Upper)))
            {
                ends.Add(i);
            }
            return i + 1;
        }

        // Whether the word at i, directly inside OVER (...), is a frame keyword.
        private bool FrameWord(int i, Tok? following, Tok? prev)
        {
            var word = _toks[i].Upper;
            var nxt = following is { Kind: TokKind.Word } ? following.Upper : "";
            var opens = prev is not null && prev.IsPunct('(');
            return word switch
            {
                "PARTITION" => opens && nxt == "BY",
                "ROWS" or "RANGE" or "GROUPS" => opens
                    && (nxt is "BETWEEN" or "UNBOUNDED" or "CURRENT"
                        || following is { Kind: TokKind.Number or TokKind.Param or TokKind.String }),
                "UNBOUNDED" => nxt is "PRECEDING" or "FOLLOWING",
                "CURRENT" => nxt == "ROW",
                "EXCLUDE" => nxt is "CURRENT" or "GROUP" or "TIES" or "NO",
                _ => false,
            };
        }

        // The index past INTERVAL [-]'1' [DAY [TO SECOND]] at i, or null.
        private int? IntervalLiteralEnd(int i, int end)
        {
            var k = i + 1;
            if (k < end && (_toks[k].IsPunct('-') || _toks[k].IsPunct('+')))
            {
                k++;
            }
            if (!(k < end && _toks[k].Kind is TokKind.String or TokKind.Number or TokKind.Param))
            {
                return null;
            }
            k++;
            if (k < end && _toks[k].Kind == TokKind.Word && DateParts.Contains(_toks[k].Upper))
            {
                k++;
                if (k + 1 < end && _toks[k].IsWord("TO")
                    && _toks[k + 1].Kind == TokKind.Word && DateParts.Contains(_toks[k + 1].Upper))
                {
                    k += 2;
                }
            }
            return k;
        }

        // -- select list and ORDER BY -------------------------------------

        private List<(int Start, int End)> Entries(int start, int end)
        {
            var entries = new List<(int, int)>();
            var entryStart = start;
            foreach (var idx in TopLevel(start, end))
            {
                if (_toks[idx].IsPunct(','))
                {
                    entries.Add((entryStart, idx));
                    entryStart = idx + 1;
                }
            }
            entries.Add((entryStart, end));
            return entries.Where(e => e.Item1 < e.Item2).ToList();
        }

        // Step past DISTINCT [ON (...)], TOP n and the like, checking DISTINCT ON.
        private int SkipModifiers(int start, int end, Scope scope)
        {
            var i = start;
            while (i < end)
            {
                var tok = _toks[i];
                if (tok.IsWord("DISTINCT"))
                {
                    i++;
                    if (i + 1 < end && _toks[i].IsWord("ON") && _toks[i + 1].IsPunct('('))
                    {
                        var close = _match[i + 1];
                        Walk(i + 2, close, scope);
                        i = close + 1;
                    }
                    continue;
                }
                if (tok.IsWord("TOP"))
                {
                    i++;
                    if (i < end && _toks[i].IsPunct('('))
                    {
                        i = _match[i] + 1;
                    }
                    else if (i < end && _toks[i].Kind is TokKind.Number or TokKind.Param)
                    {
                        i++;
                    }
                    if (i < end && _toks[i].IsWord("PERCENT"))
                    {
                        i++;
                    }
                    if (i + 1 < end && _toks[i].IsWord("WITH") && _toks[i + 1].IsWord("TIES"))
                    {
                        i += 2;
                    }
                    continue;
                }
                if (tok.Kind == TokKind.Word && SelectModifiers.Contains(tok.Upper))
                {
                    i++;
                    continue;
                }
                break;
            }
            return i;
        }

        // Where an entry's expression ends, and its alias if it has one.
        private (int ExprEnd, Tok? Alias) EntryAlias(int a, int b)
        {
            if (b - a >= 3 && _toks[b - 2].IsWord("AS") && _toks[b - 1].IsIdent)
            {
                return (b - 2, _toks[b - 1]);
            }
            if (b - a >= 2 && CanBeOutputAlias(_toks[b - 1]))
            {
                var prev = _toks[b - 2];
                var prevEndsOperand =
                    prev.Kind is TokKind.QIdent or TokKind.String or TokKind.Number or TokKind.Param
                    || prev.IsPunct(')')
                    || (prev.Kind == TokKind.Word
                        && !PrefixOperators.Contains(prev.Upper)
                        && (!Keywords.Contains(prev.Upper) || OperandEndKeywords.Contains(prev.Upper)));
                if (prevEndsOperand)
                {
                    return (b - 1, _toks[b - 1]);
                }
            }
            return (b, null);
        }

        // Whether tok may be an alias written without AS. A unit or operator word is not:
        // in dob + INTERVAL year HOUR the HOUR is the interval's unit, and taking it for
        // an alias would leave year unread.
        private static bool CanBeOutputAlias(Tok tok) =>
            tok.Kind == TokKind.QIdent
            || (tok.Kind == TokKind.Word
                && !Keywords.Contains(tok.Upper)
                && !AfterOperand.Contains(tok.Upper)
                && !DateParts.Contains(tok.Upper));

        private void CheckSelectList(int start, int end, Scope scope)
        {
            var body = SkipModifiers(start, end, scope);
            foreach (var (a, b) in Entries(body, end))
            {
                if (b - a == 1 && _toks[a].IsPunct('*'))
                {
                    foreach (var r in scope.Refs)
                    {
                        CheckStar(r);
                    }
                    continue;
                }
                var (exprEnd, alias) = EntryAlias(a, b);
                if (alias is not null && exprEnd == b - 1)
                {
                    // An alias without AS cannot be told from an unknown prefix operator
                    // applied to a column (MySQL's BINARY ssn), so it must not name a
                    // hidden column. An allow-list is not applied: the alias is not read.
                    CheckHidden(alias.Text, scope);
                }
                Walk(a, exprEnd, scope);
            }
        }

        private HashSet<string> SelectAliases(int start, int end)
        {
            var aliases = new HashSet<string>(StringComparer.Ordinal);
            foreach (var (a, b) in Entries(start, end))
            {
                var (_, alias) = EntryAlias(a, b);
                if (alias is not null)
                {
                    aliases.Add(alias.Fold);
                }
            }
            return aliases;
        }

        private void CheckOrderBy(int start, int end, Scope scope, HashSet<string> aliases)
        {
            foreach (var (a, b) in Entries(start, end))
            {
                var k = b;
                while (k > a && _toks[k - 1].IsWord("ASC", "DESC", "FIRST", "LAST", "NULLS"))
                {
                    k--;
                }
                if (k - a == 1 && _toks[a].IsIdent && aliases.Contains(_toks[a].Fold))
                {
                    continue; // an output column's alias, which ORDER BY resolves first
                }
                Walk(a, b, scope);
            }
        }
    }
}
