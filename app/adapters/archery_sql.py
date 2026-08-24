"""Small MySQL-aware lexical helpers for Archery safety checks.

This module intentionally does not try to parse SQL. It provides the bounded
lexical and structural operations the provider policy needs before applying
its own statement rules: safe comment removal, token-based equality that never
rewrites literals, and conservative table/identifier extraction.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

_MULTI_CHARACTER_OPERATORS = (
    "<=>",
    "->>",
    "!=",
    "&&",
    ":=",
    "<<",
    "<=",
    "<>",
    ">=",
    ">>",
    "||",
    "->",
)


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str
    value: str


@dataclass(frozen=True, slots=True)
class SQLTableReference:
    """One physical-looking table identifier found in a MySQL statement."""

    schema: str | None
    table: str


def strip_mysql_comments(sql: str) -> str | None:
    """Remove ordinary MySQL comments, rejecting executable or malformed input."""

    scanned = _scan(sql)
    return scanned[0] if scanned is not None else None


def canonical_sql(sql: str) -> str | None:
    """Return a formatting-insensitive key while preserving literal semantics."""

    scanned = _scan(sql)
    if scanned is None:
        return None
    tokens = list(scanned[1])
    while tokens and tokens[-1] == _Token("symbol", ";"):
        tokens.pop()
    if not tokens:
        return None
    return json.dumps(
        [
            _canonical_token(token)
            for token in tokens
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    )


def unquoted_words(sql: str) -> tuple[str, ...] | None:
    """Return case-folded bare words, excluding quoted identifiers and literals."""

    scanned = _scan(sql)
    if scanned is None:
        return None
    return tuple(token.value.casefold() for token in scanned[1] if token.kind == "word")


def is_simple_single_table_select(sql: str) -> bool:
    """Accept the bounded SELECT shape used for Archery metadata resolution.

    This deliberately recognizes less SQL than MySQL supports. Metadata
    resolution needs only a direct projection from one physical table, with
    optional filters, ordering, and a limit. Anything that can add another
    execution source or hide work behind an expression fails closed.
    """

    scanned = _scan(sql)
    if scanned is None:
        return False
    tokens = list(scanned[1])
    while tokens and tokens[-1] == _Token("symbol", ";"):
        tokens.pop()
    if (
        not tokens
        or tokens[0].kind != "word"
        or tokens[0].value.casefold() != "select"
        or any(token.kind == "hint" for token in tokens)
        or any(
            token.kind == "symbol" and token.value in {";", "@", ":=", "{", "}"}
            for token in tokens
        )
    ):
        return False

    depth = 0
    depths: list[int] = []
    for token in tokens:
        depths.append(depth)
        if token == _Token("symbol", "("):
            depth += 1
        elif token == _Token("symbol", ")"):
            depth -= 1
            if depth < 0:
                return False
    if depth != 0:
        return False

    words = tuple(
        token.value.casefold() for token in tokens if token.kind == "word"
    )
    if words.count("select") != 1 or {
        "all",
        "distinct",
        "dumpfile",
        "except",
        "for",
        "group",
        "having",
        "intersect",
        "into",
        "join",
        "lock",
        "outfile",
        "procedure",
        "sql_big_result",
        "sql_buffer_result",
        "sql_calc_found_rows",
        "sql_no_cache",
        "sql_small_result",
        "straight_join",
        "union",
        "with",
    }.intersection(words):
        return False

    # A word/identifier immediately followed by '(' is a function or table
    # function. Parenthesized predicate groups and literal IN lists remain
    # usable, but no built-in or user-defined function crosses this gate.
    for index, token in enumerate(tokens[:-1]):
        if (
            token.kind in {"word", "identifier", "double_quoted"}
            and tokens[index + 1] == _Token("symbol", "(")
            and not (token.kind == "word" and token.value.casefold() == "in")
        ):
            return False

    top_level_from = [
        index
        for index, token in enumerate(tokens)
        if depths[index] == 0
        and token.kind == "word"
        and token.value.casefold() == "from"
    ]
    if len(top_level_from) != 1:
        return False
    from_index = top_level_from[0]

    def is_identifier(index: int) -> bool:
        if index >= len(tokens):
            return False
        token = tokens[index]
        return token.kind in {"identifier", "double_quoted"} or (
            token.kind == "word"
            and bool(token.value)
            and (token.value[0].isalpha() or token.value[0] in {"_", "$"})
        )

    cursor = from_index + 1
    if not is_identifier(cursor):
        return False
    cursor += 1
    if cursor < len(tokens) and tokens[cursor] == _Token("symbol", "."):
        cursor += 1
        if not is_identifier(cursor):
            return False
        cursor += 1

    clause_words = {"limit", "order", "where"}
    if (
        cursor < len(tokens)
        and depths[cursor] == 0
        and tokens[cursor].kind == "word"
        and tokens[cursor].value.casefold() == "as"
    ):
        cursor += 1
        if not is_identifier(cursor):
            return False
        cursor += 1
    elif (
        cursor < len(tokens)
        and depths[cursor] == 0
        and is_identifier(cursor)
        and not (
            tokens[cursor].kind == "word"
            and tokens[cursor].value.casefold() in clause_words
        )
    ):
        cursor += 1

    if cursor < len(tokens) and not (
        depths[cursor] == 0
        and tokens[cursor].kind == "word"
        and tokens[cursor].value.casefold() in clause_words
    ):
        return False

    references = mysql_table_references(sql)
    return references is not None and len(references) == 1


def mysql_table_references(sql: str) -> tuple[SQLTableReference, ...] | None:
    """Extract FROM/JOIN and DML-target references without reading literals.

    This is deliberately a bounded structural extractor rather than a SQL
    parser. It covers the statement families accepted by Archery's EXPLAIN
    policy and returns ``None`` for malformed lexical input.
    """

    scanned = _scan(sql)
    if scanned is None:
        return None
    tokens = scanned[1]
    depths: list[int] = []
    depth = 0
    for token in tokens:
        depths.append(depth)
        if token == _Token("symbol", "("):
            depth += 1
        elif token == _Token("symbol", ")"):
            depth -= 1
            if depth < 0:
                return None
    if depth != 0:
        return None

    references: list[SQLTableReference] = []

    def identifier(index: int) -> str | None:
        if index >= len(tokens):
            return None
        token = tokens[index]
        if token.kind == "identifier":
            return token.value
        if token.kind == "double_quoted":
            quoted = _quoted_token(token.value, 0, '"')
            return quoted[1] if quoted is not None else None
        if token.kind == "word" and token.value and (
            token.value[0].isalpha() or token.value[0] in {"_", "$"}
        ):
            return token.value
        return None

    def table_reference(index: int) -> tuple[SQLTableReference, int] | None:
        first = identifier(index)
        if first is None:
            return None
        if (
            index + 2 < len(tokens)
            and tokens[index + 1] == _Token("symbol", ".")
            and (second := identifier(index + 2)) is not None
        ):
            return SQLTableReference(schema=first, table=second), index + 3
        return SQLTableReference(schema=None, table=first), index + 1

    def parenthesized_table_reference(
        index: int,
    ) -> tuple[SQLTableReference, int] | None:
        """Read the leading table factor from one or more grouping parentheses."""

        cursor = index
        while cursor < len(tokens) and tokens[cursor] == _Token("symbol", "("):
            cursor += 1
        if cursor == index or cursor >= len(tokens):
            return None
        if tokens[cursor].kind == "word" and tokens[cursor].value.casefold() in {
            "select",
            "table",
            "values",
            "with",
        }:
            return None
        return table_reference(cursor)

    def add(reference: SQLTableReference) -> None:
        if reference not in references:
            references.append(reference)

    def add_source(
        parsed: tuple[SQLTableReference, int] | None,
    ) -> tuple[SQLTableReference, int] | None:
        if parsed is None:
            return None
        reference, cursor = parsed
        # LATERAL derived tables and JSON_TABLE/stored table functions are not
        # physical tables whose columns can be fetched through metadata tools.
        if cursor >= len(tokens) or tokens[cursor] != _Token("symbol", "("):
            add(reference)
        return parsed

    clause_boundaries = {
        "for",
        "group",
        "having",
        "into",
        "limit",
        "lock",
        "order",
        "qualify",
        "returning",
        "set",
        "union",
        "values",
        "where",
        "window",
    }
    join_boundaries = {
        "cross",
        "full",
        "inner",
        "join",
        "left",
        "natural",
        "right",
        "straight_join",
    }

    def is_table_query_expression(index: int) -> bool:
        cursor = index - 1
        while cursor >= 0 and tokens[cursor].kind == "hint":
            cursor -= 1
        if cursor < 0 or tokens[cursor] == _Token("symbol", "("):
            return True
        previous = tokens[cursor]
        if previous.kind != "word":
            return False
        previous_keyword = previous.value.casefold()
        if previous_keyword in {"union", "intersect", "except"}:
            return True
        if previous_keyword not in {"all", "distinct"}:
            return False
        cursor -= 1
        while cursor >= 0 and tokens[cursor].kind == "hint":
            cursor -= 1
        return bool(
            cursor >= 0
            and tokens[cursor].kind == "word"
            and tokens[cursor].value.casefold() in {"union", "intersect", "except"}
        )

    for index, token in enumerate(tokens):
        keyword = token.value.casefold() if token.kind == "word" else ""
        if keyword == "table" and is_table_query_expression(index):
            parsed = table_reference(index + 1)
            if parsed is not None:
                add(parsed[0])
            continue
        if keyword not in {"from", "join", "using"}:
            continue
        parsed = add_source(table_reference(index + 1))
        source_list_depths = {depths[index]}
        if parsed is None:
            parsed = add_source(parenthesized_table_reference(index + 1))
            if parsed is not None:
                source_list_depths.add(
                    depths[parsed[1]] if parsed[1] < len(depths) else depths[parsed[1] - 1]
                )
        cursor = index + 1
        if parsed is not None:
            cursor = parsed[1]
        if keyword not in {"from", "using"}:
            continue
        clause_depth = depths[index]
        while cursor < len(tokens):
            current = tokens[cursor]
            current_keyword = (
                current.value.casefold() if current.kind == "word" else ""
            )
            if depths[cursor] == clause_depth and (
                current_keyword in clause_boundaries
                or current_keyword in join_boundaries
            ):
                break
            if (
                depths[cursor] in source_list_depths
                and current == _Token("symbol", ",")
            ):
                parsed = add_source(table_reference(cursor + 1))
                if parsed is None:
                    parsed = add_source(parenthesized_table_reference(cursor + 1))
                if parsed is not None:
                    cursor = parsed[1]
                    continue
            cursor += 1

    terminal_index = next(
        (
            index
            for index, token in enumerate(tokens)
            if depths[index] == 0
            and token.kind == "word"
            and token.value.casefold()
            in {"select", "insert", "update", "delete", "replace"}
        ),
        None,
    )
    if terminal_index is not None:
        terminal = tokens[terminal_index].value.casefold()
        cursor = terminal_index + 1
        modifiers = {
            "delayed",
            "high_priority",
            "ignore",
            "low_priority",
        }
        if terminal in {"insert", "replace", "update"}:
            while (
                cursor < len(tokens)
                and (
                    tokens[cursor].kind == "hint"
                    or (
                        tokens[cursor].kind == "word"
                        and tokens[cursor].value.casefold() in modifiers
                    )
                )
            ):
                cursor += 1
            if (
                terminal in {"insert", "replace"}
                and cursor < len(tokens)
                and tokens[cursor].kind == "word"
                and tokens[cursor].value.casefold() == "into"
            ):
                cursor += 1
            while cursor < len(tokens) and tokens[cursor].kind == "hint":
                cursor += 1
            parsed = table_reference(cursor)
            if parsed is not None:
                add(parsed[0])
                cursor = parsed[1]
            if terminal == "update":
                while cursor < len(tokens):
                    current = tokens[cursor]
                    if (
                        depths[cursor] == 0
                        and current.kind == "word"
                        and current.value.casefold() == "set"
                    ):
                        break
                    if depths[cursor] == 0 and current == _Token("symbol", ","):
                        parsed = table_reference(cursor + 1)
                        if parsed is not None:
                            add(parsed[0])
                            cursor = parsed[1]
                            continue
                    cursor += 1
            elif terminal in {"insert", "replace"}:
                # TABLE is a query source only when it immediately follows the
                # target's optional column list. A later SELECT column named
                # ``table`` must not be interpreted as TABLE source syntax.
                if cursor < len(tokens) and tokens[cursor] == _Token("symbol", "("):
                    column_list_depth = depths[cursor]
                    cursor += 1
                    while cursor < len(tokens):
                        if (
                            tokens[cursor] == _Token("symbol", ")")
                            and depths[cursor] == column_list_depth + 1
                        ):
                            cursor += 1
                            break
                        cursor += 1
                if (
                    cursor < len(tokens)
                    and depths[cursor] == 0
                    and tokens[cursor].kind == "word"
                    and tokens[cursor].value.casefold() == "table"
                ):
                    parsed = table_reference(cursor + 1)
                    if parsed is not None:
                        add(parsed[0])
        elif terminal == "delete":
            modifiers = {"ignore", "low_priority", "quick"}
            while (
                cursor < len(tokens)
                and (
                    tokens[cursor].kind == "hint"
                    or (
                        tokens[cursor].kind == "word"
                        and tokens[cursor].value.casefold() in modifiers
                    )
                )
            ):
                cursor += 1
            # In the first multi-table DELETE form, targets precede FROM. The
            # FROM/JOIN scan already resolves unqualified names and aliases to
            # their physical sources; retain qualified targets here so an
            # explicit cross-schema write target can never disappear.
            if not (
                cursor < len(tokens)
                and tokens[cursor].kind == "word"
                and tokens[cursor].value.casefold() == "from"
            ):
                while cursor < len(tokens):
                    if (
                        depths[cursor] == 0
                        and tokens[cursor].kind == "word"
                        and tokens[cursor].value.casefold() == "from"
                    ):
                        break
                    parsed = table_reference(cursor)
                    if parsed is None:
                        break
                    reference, cursor = parsed
                    if reference.schema is not None:
                        add(reference)
                    if (
                        cursor + 1 < len(tokens)
                        and tokens[cursor] == _Token("symbol", ".")
                        and tokens[cursor + 1] == _Token("symbol", "*")
                    ):
                        cursor += 2
                    if cursor >= len(tokens) or tokens[cursor] != _Token("symbol", ","):
                        break
                    cursor += 1

    return tuple(references)


def mysql_identifier_paths(sql: str) -> tuple[tuple[str, ...], ...] | None:
    """Return dotted identifier paths with original identifier case preserved."""

    scanned = _scan(sql)
    if scanned is None:
        return None
    tokens = scanned[1]

    def identifier(index: int) -> str | None:
        if index >= len(tokens):
            return None
        token = tokens[index]
        if token.kind == "identifier":
            return token.value
        if token.kind == "double_quoted":
            quoted = _quoted_token(token.value, 0, '"')
            return quoted[1] if quoted is not None else None
        if token.kind == "word" and token.value and (
            token.value[0].isalpha() or token.value[0] in {"_", "$"}
        ):
            return token.value
        return None

    paths: list[tuple[str, ...]] = []
    index = 0
    while index < len(tokens):
        first = identifier(index)
        if first is None or (index > 0 and tokens[index - 1] == _Token("symbol", ".")):
            index += 1
            continue
        parts = [first]
        cursor = index
        while cursor + 2 < len(tokens) and tokens[cursor + 1] == _Token("symbol", "."):
            next_identifier = identifier(cursor + 2)
            if next_identifier is not None:
                parts.append(next_identifier)
                cursor += 2
                continue
            if tokens[cursor + 2] == _Token("symbol", "*"):
                parts.append("*")
                cursor += 2
            break
        if len(parts) > 1:
            paths.append(tuple(parts))
            index = cursor + 1
        else:
            index += 1
    return tuple(paths)


def _scan(sql: str) -> tuple[str, tuple[_Token, ...]] | None:
    output: list[str] = []
    tokens: list[_Token] = []
    index = 0
    length = len(sql)

    while index < length:
        character = sql[index]
        if character.isspace():
            output.append(character)
            index += 1
            continue

        # ODBC escape clauses such as ``{OJ ...}`` require a dialect parser to
        # identify their true sources. The safety boundary intentionally has no
        # such parser, so braces outside literals are unsupported.
        if character in {"{", "}"}:
            return None

        if sql.startswith("/*", index):
            if sql.startswith("/*!", index) or sql[index : index + 4].casefold() == "/*m!":
                return None
            end = sql.find("*/", index + 2)
            if end < 0:
                return None
            if sql.startswith("/*+", index):
                hint = sql[index : end + 2]
                output.append(hint)
                tokens.append(_Token("hint", hint))
            else:
                output.append(" ")
            index = end + 2
            continue

        if character == "#" or (
            sql.startswith("--", index)
            and (
                index + 2 == length
                or ord(sql[index + 2]) <= 32
            )
        ):
            newline = sql.find("\n", index)
            if newline < 0:
                break
            output.append("\n")
            index = newline + 1
            continue

        if character in {"'", '"', "`"}:
            quoted = _quoted_token(sql, index, character)
            if quoted is None:
                return None
            raw, value, index = quoted
            output.append(raw)
            token_kind = (
                "identifier"
                if character == "`"
                else "double_quoted"
                if character == '"'
                else "literal"
            )
            tokens.append(_Token(token_kind, value if character == "`" else raw))
            continue

        if character.isalnum() or character in {"_", "$"}:
            end = index + 1
            while end < length and (
                sql[end].isalnum() or sql[end] in {"_", "$"}
            ):
                end += 1
            value = sql[index:end]
            output.append(value)
            tokens.append(_Token("word", value))
            index = end
            continue

        operator = next(
            (
                candidate
                for candidate in _MULTI_CHARACTER_OPERATORS
                if sql.startswith(candidate, index)
            ),
            None,
        )
        value = operator or character
        output.append(value)
        tokens.append(_Token("symbol", value))
        index += len(value)

    return "".join(output), tuple(tokens)


def _canonical_token(token: _Token) -> tuple[str, str]:
    if token.kind == "word":
        # MySQL bare words are compared case-insensitively. String literals and
        # quoted identifiers remain byte-for-byte significant, and optimizer
        # hints retain their complete token, so equality never rewrites data or
        # silently drops a plan-affecting directive.
        return "word", token.value.casefold()
    return token.kind, token.value


def _quoted_token(
    sql: str,
    start: int,
    quote: str,
) -> tuple[str, str, int] | None:
    index = start + 1
    decoded: list[str] = []
    while index < len(sql):
        character = sql[index]
        if character == "\\" and quote != "`":
            if index + 1 >= len(sql):
                return None
            # Whether backslash escapes a quote depends on NO_BACKSLASH_ESCAPES.
            # If the quote boundary changes with sql_mode, target extraction and
            # statement counting are not authoritative enough to permit a call.
            if sql[index + 1] == quote:
                return None
            decoded.extend((character, sql[index + 1]))
            index += 2
            continue
        if character == quote:
            if index + 1 < len(sql) and sql[index + 1] == quote:
                decoded.append(quote)
                index += 2
                continue
            end = index + 1
            return sql[start:end], "".join(decoded), end
        decoded.append(character)
        index += 1
    return None
