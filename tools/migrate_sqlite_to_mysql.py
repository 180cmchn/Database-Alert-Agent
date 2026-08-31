from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import importlib.util
import json
import math
import os
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from dotenv import dotenv_values
from sqlalchemy import LargeBinary, MetaData, Table, cast, func, select, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from app.adapters.persistence import DATABASE_SCHEMA_REVISION

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "data" / "alerts.db"
DEFAULT_TARGET_ENV = "MIGRATION_TARGET_DATABASE_URL"
MIGRATION_LOCK_NAME = "database-alert-agent-sqlite-to-mysql"
MINIMUM_MYSQL_VERSION = (8, 0, 13)

TABLE_ORDER = (
    "alerts",
    "investigation_runs",
    "investigation_progress",
    "evidence_records",
    "validation_results",
    "agent_events",
    "agent_checkpoints",
    "agent_checkpoint_writes",
    "tool_invocations",
    "agent_artifacts",
)
APPLICATION_TABLES = frozenset(TABLE_ORDER)
EXPECTED_TARGET_TABLES = APPLICATION_TABLES | {"alembic_version"}
LARGE_TEXT_COLUMNS = (
    ("agent_checkpoint_writes", "value_base64"),
    ("agent_artifacts", "sanitized_content"),
)
TARGET_ONLY_COLUMN_DEFAULTS: dict[tuple[str, str], Any] = {
    ("alerts", "legacy_runbooks_json"): (),
    ("investigation_runs", "legacy_runbooks_json"): None,
}
DIGEST_BATCH_ROWS = 10


class MigrationError(RuntimeError):
    """A preflight, copy, or verification invariant failed."""


@dataclass(frozen=True)
class TargetSnapshot:
    server_version: str
    max_allowed_packet: int
    character_set: str
    collation: str
    sql_mode: str
    tables: frozenset[str]
    row_counts: dict[str, int]
    revision: str | None


@dataclass(frozen=True)
class TableDigest:
    rows: int
    sha256: str


@dataclass(frozen=True)
class CopyStats:
    digest: TableDigest
    inserted: int
    skipped: int


def _positive_integer(raw: str) -> int:
    value = int(raw)
    if value <= 0:
        raise argparse.ArgumentTypeError("value must be a positive integer")
    return value


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Copy the current Database Alert Agent SQLite data into a dedicated MySQL 8 "
            "database, then verify every application table."
        )
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE,
        help=f"SQLite source file (default: {DEFAULT_SOURCE})",
    )
    parser.add_argument(
        "--target-env",
        default=DEFAULT_TARGET_ENV,
        help=(
            "Name of the process/local .env variable containing the mysql+asyncmy URL; "
            "the URL is never accepted as a command-line value"
        ),
    )
    parser.add_argument(
        "--batch-rows",
        type=_positive_integer,
        default=10,
        help="Maximum rows per target transaction (default: 10)",
    )
    parser.add_argument(
        "--batch-bytes",
        type=_positive_integer,
        default=8 * 1024 * 1024,
        help="Approximate maximum payload bytes per target transaction (default: 8 MiB)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip primary keys already present after a previously interrupted copy",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Do not mutate the target; compare row counts and canonical SHA-256 digests",
    )
    return parser.parse_args(argv)


def _target_url_from_environment(variable_name: str) -> str:
    value = os.environ.get(variable_name, "").strip()
    if not value:
        dotenv_value = dotenv_values(ROOT / ".env").get(variable_name)
        value = dotenv_value.strip() if isinstance(dotenv_value, str) else ""
    if not value:
        raise MigrationError(
            f"{variable_name} is not set in the process environment or local .env; "
            "never provide the target URL as a command-line argument"
        )
    try:
        parsed = make_url(value)
    except (ArgumentError, TypeError, ValueError) as exc:
        raise MigrationError(f"{variable_name} is not a valid SQLAlchemy URL") from exc
    if parsed.drivername != "mysql+asyncmy":
        raise MigrationError(f"{variable_name} must use mysql+asyncmy, got {parsed.drivername!r}")
    if not parsed.host or not parsed.database:
        raise MigrationError(f"{variable_name} must include a host and dedicated database")
    return value


def _redacted_url(value: str) -> str:
    return make_url(value).render_as_string(hide_password=True)


def _source_url(path: Path) -> URL:
    return URL.create("sqlite+aiosqlite", database=str(path.resolve()))


def _require_mysql_driver() -> None:
    if importlib.util.find_spec("asyncmy") is None:
        raise MigrationError(
            'The asyncmy driver is not installed; run python -m pip install -e ".[dev,mysql]"'
        )


def _mysql_version(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if match is None:
        raise MigrationError(f"Cannot parse MySQL server version {value!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _canonical_value(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(UTC).replace(tzinfo=None)
        # The current MySQL schema uses DATETIME(0), whose default assignment
        # behavior rounds fractional seconds. Compare the value MySQL persists.
        if value.microsecond >= 500_000:
            value += timedelta(seconds=1)
        value = value.replace(microsecond=0)
        return {"$datetime": value.isoformat(timespec="seconds")}
    if isinstance(value, date):
        return {"$date": value.isoformat()}
    if isinstance(value, Decimal):
        return {"$decimal": format(value, "f")}
    if isinstance(value, bytes):
        return {"$bytes": base64.b64encode(value).decode("ascii")}
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, float):
        if not math.isfinite(value):
            raise MigrationError("Source data contains a non-finite number that MySQL JSON rejects")
        # MySQL's binary JSON round-trip can move a DOUBLE by one ULP. Twelve
        # significant digits retain substantially better than microsecond
        # precision for these duration values while removing representation noise.
        normalized = 0.0 if value == 0 else value
        return {"$float": format(normalized, ".12g")}
    return value


def _canonical_row_bytes(row: Mapping[str, Any], columns: Sequence[str]) -> bytes:
    payload = [_canonical_value(row[column]) for column in columns]
    try:
        serialized = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise MigrationError("A source row cannot be represented canonically") from exc
    return serialized.encode("utf-8")


def _update_digest(hasher: Any, payload: bytes) -> None:
    hasher.update(len(payload).to_bytes(8, byteorder="big", signed=False))
    hasher.update(payload)


async def _reflect_tables(
    connection: AsyncConnection,
    *,
    expected: frozenset[str] = APPLICATION_TABLES,
) -> dict[str, Table]:
    metadata = MetaData()

    def reflect(sync_connection: Any) -> None:
        metadata.reflect(bind=sync_connection, only=sorted(expected))

    await connection.run_sync(reflect)
    missing = sorted(expected - set(metadata.tables))
    if missing:
        raise MigrationError(f"Database is missing application tables: {', '.join(missing)}")
    return {name: metadata.tables[name] for name in expected}


async def _table_names(connection: AsyncConnection) -> frozenset[str]:
    def inspect_names(sync_connection: Any) -> frozenset[str]:
        from sqlalchemy import inspect

        return frozenset(inspect(sync_connection).get_table_names())

    return await connection.run_sync(inspect_names)


async def _schema_revision(connection: AsyncConnection, tables: frozenset[str]) -> str | None:
    if "alembic_version" not in tables:
        return None
    revision = await connection.scalar(text("SELECT version_num FROM alembic_version"))
    return str(revision) if revision is not None else None


async def _lock_source_snapshot(connection: AsyncConnection) -> None:
    await connection.exec_driver_sql("BEGIN IMMEDIATE")
    await connection.exec_driver_sql("PRAGMA query_only=ON")


async def _inspect_source(path: Path) -> None:
    engine = create_async_engine(_source_url(path), connect_args={"timeout": 30})
    try:
        async with engine.connect() as connection:
            await connection.exec_driver_sql("PRAGMA query_only=ON")
            tables = await _table_names(connection)
            missing = sorted(EXPECTED_TARGET_TABLES - tables)
            if missing:
                raise MigrationError(f"SQLite source is missing tables: {', '.join(missing)}")
            revision = await _schema_revision(connection, tables)
            if revision != DATABASE_SCHEMA_REVISION:
                raise MigrationError(
                    f"SQLite source revision is {revision or 'unversioned'}, expected "
                    f"{DATABASE_SCHEMA_REVISION}; stop services and run alembic upgrade head"
                )
            active_leases = await connection.scalar(
                text(
                    "SELECT COUNT(*) FROM investigation_runs "
                    "WHERE lease_owner IS NOT NULL AND lease_expires_at > CURRENT_TIMESTAMP"
                )
            )
            if int(active_leases or 0):
                raise MigrationError(
                    "SQLite source has an active investigation lease; stop API and Worker "
                    "before migration"
                )
    finally:
        await engine.dispose()


async def _inspect_target(target_url: str) -> TargetSnapshot:
    engine = create_async_engine(target_url, pool_pre_ping=True)
    try:
        async with engine.connect() as connection:
            row = (
                (
                    await connection.execute(
                        text(
                            "SELECT VERSION() AS server_version, "
                            "@@version_comment AS version_comment, "
                            "@@max_allowed_packet AS max_allowed_packet, "
                            "@@character_set_database AS character_set, "
                            "@@collation_database AS collation, "
                            "@@sql_mode AS sql_mode"
                        )
                    )
                )
                .mappings()
                .one()
            )
            server_version = str(row["server_version"])
            version_identity = f"{server_version} {row['version_comment']}".casefold()
            if "mariadb" in version_identity:
                raise MigrationError("MariaDB is not supported; the target must be MySQL 8")
            if _mysql_version(server_version) < MINIMUM_MYSQL_VERSION:
                minimum = ".".join(str(part) for part in MINIMUM_MYSQL_VERSION)
                raise MigrationError(
                    f"MySQL {server_version} is too old; JSON defaults require {minimum}+"
                )
            character_set = str(row["character_set"]).casefold()
            if character_set != "utf8mb4":
                raise MigrationError(
                    f"Target database character set is {character_set!r}; utf8mb4 is required"
                )
            collation = str(row["collation"]).casefold()
            if not collation.endswith("_bin"):
                raise MigrationError(
                    f"Target database collation is {collation!r}; a utf8mb4 binary "
                    "collation is required to preserve SQLite identifier semantics"
                )
            sql_mode = str(row["sql_mode"])
            modes = {mode.strip().upper() for mode in sql_mode.split(",")}
            if not modes & {"STRICT_TRANS_TABLES", "STRICT_ALL_TABLES"}:
                raise MigrationError("Target MySQL must enable a strict SQL mode")
            if "TIME_TRUNCATE_FRACTIONAL" in modes:
                raise MigrationError(
                    "Target MySQL must use its default fractional-second rounding mode"
                )

            tables = await _table_names(connection)
            unexpected = sorted(tables - EXPECTED_TARGET_TABLES)
            if unexpected:
                raise MigrationError(
                    "Target must be a dedicated database; unexpected tables: "
                    + ", ".join(unexpected)
                )
            row_counts: dict[str, int] = {}
            for table_name in sorted(tables & APPLICATION_TABLES):
                count = await connection.scalar(text(f"SELECT COUNT(*) FROM `{table_name}`"))
                row_counts[table_name] = int(count or 0)
            revision = await _schema_revision(connection, tables)
            return TargetSnapshot(
                server_version=server_version,
                max_allowed_packet=int(row["max_allowed_packet"]),
                character_set=character_set,
                collation=collation,
                sql_mode=sql_mode,
                tables=tables,
                row_counts=row_counts,
                revision=revision,
            )
    finally:
        await engine.dispose()


def _upgrade_target_schema(target_url: str) -> None:
    environment = os.environ.copy()
    environment["DATABASE_URL"] = target_url
    environment.setdefault("STREAM_MAIN_AGENT_REASONING", "false")
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT,
        env=environment,
        check=False,
    )
    if result.returncode:
        raise MigrationError(f"Target Alembic upgrade failed with exit code {result.returncode}")


async def _assert_mysql_large_text_columns(connection: AsyncConnection) -> None:
    for table_name, column_name in LARGE_TEXT_COLUMNS:
        data_type = await connection.scalar(
            text(
                "SELECT DATA_TYPE FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table_name "
                "AND COLUMN_NAME = :column_name"
            ),
            {"table_name": table_name, "column_name": column_name},
        )
        if str(data_type).casefold() != "longtext":
            raise MigrationError(
                f"Target column {table_name}.{column_name} must be LONGTEXT, got {data_type!r}"
            )

    collated_columns = (
        await connection.execute(
            text(
                "SELECT TABLE_NAME, COLUMN_NAME, COLLATION_NAME "
                "FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() "
                "AND COLLATION_NAME IS NOT NULL"
            )
        )
    ).mappings()
    non_binary = [
        f"{row['TABLE_NAME']}.{row['COLUMN_NAME']}={row['COLLATION_NAME']}"
        for row in collated_columns
        if not str(row["COLLATION_NAME"]).casefold().endswith("_bin")
    ]
    if non_binary:
        raise MigrationError(
            "Target text columns must use a binary collation: " + ", ".join(non_binary[:10])
        )


async def _maximum_source_row_bytes(
    connection: AsyncConnection,
    tables: Mapping[str, Table],
) -> tuple[str, int]:
    largest_table = ""
    largest_size = 0
    for table_name in TABLE_ORDER:
        table = tables[table_name]
        row_size: Any = 0
        for column in table.columns:
            row_size = row_size + func.coalesce(func.length(cast(column, LargeBinary)), 0)
        value = await connection.scalar(select(func.max(row_size)).select_from(table))
        size = int(value or 0)
        if size > largest_size:
            largest_table = table_name
            largest_size = size
    return largest_table, largest_size


async def _target_primary_keys(
    connection: AsyncConnection,
    table: Table,
) -> set[Any]:
    primary_keys = tuple(table.primary_key.columns)
    if len(primary_keys) != 1:
        raise MigrationError(f"Table {table.name} must have exactly one primary key column")
    result = await connection.execute(select(primary_keys[0]))
    return set(result.scalars())


async def _flush_batch(
    connection: AsyncConnection,
    table: Table,
    batch: list[dict[str, Any]],
) -> int:
    if not batch:
        return 0
    await connection.execute(table.insert(), batch)
    await connection.commit()
    count = len(batch)
    batch.clear()
    return count


async def _copy_table(
    source: AsyncConnection,
    target: AsyncConnection,
    source_table: Table,
    target_table: Table,
    *,
    resume: bool,
    batch_rows: int,
    batch_bytes: int,
    safe_packet_bytes: int,
) -> CopyStats:
    source_columns = tuple(column.name for column in source_table.columns)
    target_columns = tuple(column.name for column in target_table.columns)
    missing_target_columns = sorted(set(source_columns) - set(target_columns))
    if missing_target_columns:
        raise MigrationError(
            f"Target {target_table.name} is missing source columns: "
            + ", ".join(missing_target_columns)
        )
    target_only_columns = tuple(
        column for column in target_columns if column not in source_columns
    )
    unsupported_target_columns = [
        column
        for column in target_only_columns
        if (target_table.name, column) not in TARGET_ONLY_COLUMN_DEFAULTS
    ]
    if unsupported_target_columns:
        raise MigrationError(
            f"Target {target_table.name} has unsupported extra columns: "
            + ", ".join(unsupported_target_columns)
        )

    primary_keys = tuple(source_table.primary_key.columns)
    if len(primary_keys) != 1:
        raise MigrationError(f"Table {source_table.name} must have one primary key")
    primary_key = primary_keys[0].name
    existing_keys = await _target_primary_keys(target, target_table) if resume else set()

    hasher = hashlib.sha256()
    rows = 0
    inserted = 0
    skipped = 0
    pending_bytes = 0
    batch: list[dict[str, Any]] = []
    statement = select(source_table).order_by(*source_table.primary_key.columns)
    result = await source.stream(statement)
    async for row in result.mappings():
        values = {column: row[column] for column in source_columns}
        payload = _canonical_row_bytes(values, source_columns)
        payload_size = len(payload)
        if payload_size > safe_packet_bytes:
            raise MigrationError(
                f"Row {source_table.name}.{values[primary_key]!r} is approximately "
                f"{payload_size} bytes, above the safe max_allowed_packet budget "
                f"{safe_packet_bytes}"
            )
        _update_digest(hasher, payload)
        rows += 1

        if values[primary_key] in existing_keys:
            skipped += 1
            continue
        if batch and (len(batch) >= batch_rows or pending_bytes + payload_size > batch_bytes):
            inserted += await _flush_batch(target, target_table, batch)
            pending_bytes = 0
        insert_values = dict(values)
        for column in target_only_columns:
            default = TARGET_ONLY_COLUMN_DEFAULTS[(target_table.name, column)]
            insert_values[column] = list(default) if isinstance(default, tuple) else default
        batch.append(insert_values)
        pending_bytes += payload_size

    inserted += await _flush_batch(target, target_table, batch)
    return CopyStats(
        digest=TableDigest(rows=rows, sha256=hasher.hexdigest()),
        inserted=inserted,
        skipped=skipped,
    )


async def _digest_table(
    connection: AsyncConnection,
    table: Table,
    *,
    columns: Sequence[str] | None = None,
) -> TableDigest:
    selected_columns = tuple(columns or (column.name for column in table.columns))
    missing_columns = sorted(set(selected_columns) - set(table.c.keys()))
    if missing_columns:
        raise MigrationError(
            f"Table {table.name} is missing digest columns: " + ", ".join(missing_columns)
        )
    primary_keys = tuple(table.primary_key.columns)
    if len(primary_keys) != 1:
        raise MigrationError(f"Table {table.name} must have one primary key")
    primary_key = primary_keys[0]
    query_columns = [table.c[column] for column in selected_columns]
    if primary_key.name not in selected_columns:
        query_columns.append(primary_key)

    hasher = hashlib.sha256()
    rows = 0
    last_primary_key: Any | None = None
    while True:
        statement = select(*query_columns).order_by(primary_key).limit(DIGEST_BATCH_ROWS)
        if last_primary_key is not None:
            statement = statement.where(primary_key > last_primary_key)
        result = await connection.execute(statement)
        batch = result.mappings().all()
        if not batch:
            break
        for row in batch:
            _update_digest(hasher, _canonical_row_bytes(row, selected_columns))
            rows += 1
        last_primary_key = batch[-1][primary_key.name]

    return TableDigest(rows=rows, sha256=hasher.hexdigest())


def _value_difference(left: Any, right: Any, path: str = "$") -> str:
    if _canonical_value(left) == _canonical_value(right):
        return f"{path}: canonical values match"
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        if set(left) != set(right):
            return f"{path}: object key sets differ ({len(left)} != {len(right)})"
        for key in sorted(left, key=str):
            if _canonical_value(left[key]) != _canonical_value(right[key]):
                return _value_difference(left[key], right[key], f"{path}.{key}")
    if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
        if len(left) != len(right):
            return f"{path}: array lengths differ ({len(left)} != {len(right)})"
        for index, (left_item, right_item) in enumerate(zip(left, right, strict=True)):
            if _canonical_value(left_item) != _canonical_value(right_item):
                return _value_difference(left_item, right_item, f"{path}[{index}]")
    if isinstance(left, float) and isinstance(right, float):
        return f"{path}: floats differ ({left:.17g} != {right:.17g})"
    if type(left) is not type(right):
        return f"{path}: types differ ({type(left).__name__} != {type(right).__name__})"
    if isinstance(left, (int, bool)) or left is None:
        return f"{path}: scalar values differ ({left!r} != {right!r})"
    left_payload = json.dumps(
        _canonical_value(left), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    right_payload = json.dumps(
        _canonical_value(right), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return (
        f"{path}: values differ "
        f"({len(left_payload)} bytes/{hashlib.sha256(left_payload).hexdigest()[:12]} != "
        f"{len(right_payload)} bytes/{hashlib.sha256(right_payload).hexdigest()[:12]})"
    )


async def _first_table_difference(
    source: AsyncConnection,
    target: AsyncConnection,
    source_table: Table,
    target_table: Table,
) -> str:
    primary_keys = tuple(source_table.primary_key.columns)
    if len(primary_keys) != 1:
        return "diagnostic requires one primary key"
    primary_key = primary_keys[0]
    columns = tuple(column.name for column in source_table.columns)
    last_primary_key: Any | None = None
    while True:
        statement = select(source_table).order_by(primary_key).limit(DIGEST_BATCH_ROWS)
        if last_primary_key is not None:
            statement = statement.where(primary_key > last_primary_key)
        source_rows = (await source.execute(statement)).mappings().all()
        if not source_rows:
            return "no per-row difference found; row ordering differs"
        keys = [row[primary_key.name] for row in source_rows]
        target_rows = (
            await target.execute(
                select(target_table).where(target_table.c[primary_key.name].in_(keys))
            )
        ).mappings()
        targets_by_key = {row[primary_key.name]: row for row in target_rows}
        for source_row in source_rows:
            key = source_row[primary_key.name]
            target_row = targets_by_key.get(key)
            if target_row is None:
                return f"primary key {key!r} is missing from target"
            for column in columns:
                if _canonical_row_bytes(source_row, (column,)) != _canonical_row_bytes(
                    target_row, (column,)
                ):
                    return (
                        f"primary key {key!r}, column {column}: "
                        + _value_difference(source_row[column], target_row[column])
                    )
        last_primary_key = source_rows[-1][primary_key.name]


async def _run_copy(
    source_path: Path,
    target_url: str,
    target_snapshot: TargetSnapshot,
    *,
    resume: bool,
    verify_only: bool,
    batch_rows: int,
    batch_bytes: int,
) -> None:
    source_engine: AsyncEngine = create_async_engine(
        _source_url(source_path), connect_args={"timeout": 30}
    )
    target_engine: AsyncEngine = create_async_engine(target_url, pool_pre_ping=True)
    source_connection: AsyncConnection | None = None
    target_connection: AsyncConnection | None = None
    lock_acquired = False
    try:
        source_connection = await source_engine.connect()
        await _lock_source_snapshot(source_connection)

        target_connection = await target_engine.connect()
        acquired = await target_connection.scalar(
            text("SELECT GET_LOCK(:lock_name, 0)"),
            {"lock_name": MIGRATION_LOCK_NAME},
        )
        await target_connection.commit()
        if int(acquired or 0) != 1:
            raise MigrationError("Another database migration holds the target advisory lock")
        lock_acquired = True

        source_tables = await _reflect_tables(source_connection)
        target_tables = await _reflect_tables(target_connection)
        source_revision = await _schema_revision(
            source_connection, await _table_names(source_connection)
        )
        target_revision = await _schema_revision(
            target_connection, await _table_names(target_connection)
        )
        if source_revision != DATABASE_SCHEMA_REVISION:
            raise MigrationError(f"Source revision changed to {source_revision!r} during preflight")
        if target_revision != DATABASE_SCHEMA_REVISION:
            raise MigrationError(f"Target revision is {target_revision!r}, expected current head")
        await _assert_mysql_large_text_columns(target_connection)

        largest_table, largest_row = await _maximum_source_row_bytes(
            source_connection, source_tables
        )
        safe_packet_bytes = target_snapshot.max_allowed_packet * 3 // 4
        if largest_row > safe_packet_bytes:
            raise MigrationError(
                f"Largest source row is about {largest_row} bytes in {largest_table}, but "
                f"the safe target packet budget is {safe_packet_bytes}; increase "
                "max_allowed_packet before retrying"
            )
        effective_batch_bytes = min(batch_bytes, safe_packet_bytes)
        print(
            f"Preflight: largest source row={largest_row} bytes ({largest_table}), "
            f"batch budget={effective_batch_bytes} bytes"
        )

        source_digests: dict[str, TableDigest] = {}
        for table_name in TABLE_ORDER:
            if verify_only:
                digest = await _digest_table(source_connection, source_tables[table_name])
                source_digests[table_name] = digest
                print(f"Source {table_name}: {digest.rows} rows")
                continue
            stats = await _copy_table(
                source_connection,
                target_connection,
                source_tables[table_name],
                target_tables[table_name],
                resume=resume,
                batch_rows=batch_rows,
                batch_bytes=effective_batch_bytes,
                safe_packet_bytes=safe_packet_bytes,
            )
            source_digests[table_name] = stats.digest
            print(
                f"Copied {table_name}: source={stats.digest.rows}, "
                f"inserted={stats.inserted}, skipped={stats.skipped}"
            )

        mismatches: list[str] = []
        mismatch_tables: list[str] = []
        for table_name in TABLE_ORDER:
            source_columns = tuple(
                column.name for column in source_tables[table_name].columns
            )
            target_digest = await _digest_table(
                target_connection,
                target_tables[table_name],
                columns=source_columns,
            )
            source_digest = source_digests[table_name]
            if target_digest != source_digest:
                mismatch_tables.append(table_name)
                mismatches.append(
                    f"{table_name}: source={source_digest.rows}/{source_digest.sha256}, "
                    f"target={target_digest.rows}/{target_digest.sha256}"
                )
            else:
                print(
                    f"Verified {table_name}: {target_digest.rows} rows, "
                    f"sha256={target_digest.sha256}"
                )
        if mismatches:
            for table_name in mismatch_tables:
                detail = await _first_table_difference(
                    source_connection,
                    target_connection,
                    source_tables[table_name],
                    target_tables[table_name],
                )
                print(f"First difference in {table_name}: {detail}")
            raise MigrationError("Verification failed:\n" + "\n".join(mismatches))
    finally:
        if target_connection is not None:
            if lock_acquired:
                try:
                    await target_connection.execute(
                        text("SELECT RELEASE_LOCK(:lock_name)"),
                        {"lock_name": MIGRATION_LOCK_NAME},
                    )
                    await target_connection.commit()
                except SQLAlchemyError:
                    await target_connection.rollback()
            await target_connection.close()
        if source_connection is not None:
            await source_connection.rollback()
            await source_connection.close()
        await target_engine.dispose()
        await source_engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    if sys.platform == "win32":
        # asyncmy's buffered protocol can retain an exported receive buffer while
        # Proactor schedules the next overlapping read, failing on larger results.
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    args = _parse_args(argv)
    try:
        _require_mysql_driver()
        target_url = _target_url_from_environment(args.target_env)
        source_path = args.source.expanduser().resolve()
        if not source_path.is_file():
            raise MigrationError(f"SQLite source does not exist: {source_path}")
        asyncio.run(_inspect_source(source_path))

        initial_target = asyncio.run(_inspect_target(target_url))
        populated = {name: count for name, count in initial_target.row_counts.items() if count}
        if args.verify_only:
            if initial_target.revision != DATABASE_SCHEMA_REVISION:
                raise MigrationError(
                    f"Verify-only target revision is {initial_target.revision!r}, expected "
                    f"{DATABASE_SCHEMA_REVISION}"
                )
        else:
            if populated and not args.resume:
                details = ", ".join(f"{name}={count}" for name, count in populated.items())
                raise MigrationError(
                    "Target already contains application data; use a dedicated empty database "
                    f"or --resume after an interrupted migration ({details})"
                )
            _upgrade_target_schema(target_url)

        target_snapshot = asyncio.run(_inspect_target(target_url))
        if target_snapshot.revision != DATABASE_SCHEMA_REVISION:
            raise MigrationError(
                f"Target revision is {target_snapshot.revision!r}, expected "
                f"{DATABASE_SCHEMA_REVISION}"
            )
        print(
            f"Source: {source_path}\n"
            f"Target: {_redacted_url(target_url)}\n"
            f"MySQL: {target_snapshot.server_version}, "
            f"charset={target_snapshot.character_set}, "
            f"collation={target_snapshot.collation}, "
            f"max_allowed_packet={target_snapshot.max_allowed_packet}"
        )
        asyncio.run(
            _run_copy(
                source_path,
                target_url,
                target_snapshot,
                resume=args.resume,
                verify_only=args.verify_only,
                batch_rows=args.batch_rows,
                batch_bytes=args.batch_bytes,
            )
        )
    except (MigrationError, OSError, SQLAlchemyError) as exc:
        print(f"Migration failed: {exc}", file=sys.stderr)
        return 1

    action = "Verification" if args.verify_only else "Migration"
    print(f"{action} completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
