from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime
from pathlib import Path


class SQLiteDeliveryStore:
    """Persist only successful delivery keys; no message content or credentials."""

    def __init__(self, path: Path) -> None:
        self._path = path

    async def initialize(self) -> None:
        await asyncio.to_thread(self._initialize_sync)

    async def get_success(self, event_key: str) -> str | None:
        return await asyncio.to_thread(self._get_success_sync, event_key)

    async def save_success(self, event_key: str, delivery_id: str) -> None:
        await asyncio.to_thread(self._save_success_sync, event_key, delivery_id)

    async def ping(self) -> None:
        await asyncio.to_thread(self._ping_sync)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=5)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize_sync(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS successful_deliveries (
                    event_key TEXT PRIMARY KEY,
                    delivery_id TEXT NOT NULL,
                    delivered_at TEXT NOT NULL
                )
                """
            )

    def _get_success_sync(self, event_key: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT delivery_id FROM successful_deliveries WHERE event_key = ?",
                (event_key,),
            ).fetchone()
        return str(row[0]) if row else None

    def _save_success_sync(self, event_key: str, delivery_id: str) -> None:
        delivered_at = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO successful_deliveries (event_key, delivery_id, delivered_at)
                VALUES (?, ?, ?)
                ON CONFLICT(event_key) DO UPDATE SET
                    delivery_id = excluded.delivery_id,
                    delivered_at = excluded.delivered_at
                """,
                (event_key, delivery_id, delivered_at),
            )

    def _ping_sync(self) -> None:
        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()
