"""Хранилище на SQLite: узлы, подписчики и отложенные события."""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterable
from pathlib import Path

from .models import Host

MAX_OUTBOX = 500

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    name                 TEXT PRIMARY KEY,
    address              TEXT NOT NULL,
    kind                 TEXT NOT NULL DEFAULT 'icmp',
    port                 INTEGER,
    interval             INTEGER,
    timeout              REAL,
    enabled              INTEGER NOT NULL DEFAULT 1,
    network              TEXT NOT NULL DEFAULT '',
    ok                   INTEGER,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    changed_at           REAL,
    last_notified        REAL,
    latency              REAL,
    detail               TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS subscribers (
    chat_id    INTEGER PRIMARY KEY,
    title      TEXT NOT NULL DEFAULT '',
    notify     INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        REAL NOT NULL,
    host_name TEXT NOT NULL,
    kind      TEXT NOT NULL,
    detail    TEXT NOT NULL DEFAULT ''
);
"""


def _row_to_host(row: sqlite3.Row) -> Host:
    return Host(
        name=row["name"],
        address=row["address"],
        kind=row["kind"],
        port=row["port"],
        interval=row["interval"],
        timeout=row["timeout"],
        enabled=bool(row["enabled"]),
        network=row["network"] or "",
        ok=None if row["ok"] is None else bool(row["ok"]),
        consecutive_failures=row["consecutive_failures"],
        changed_at=row["changed_at"],
        last_notified=row["last_notified"],
        latency=row["latency"],
        detail=row["detail"] or "",
    )


class Storage:
    """Небольшая обёртка над SQLite. Вызовы дешёвые, поэтому синхронные."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if str(self.path.parent) not in ("", "."):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        """Добавить новые колонки в базы, созданные прошлыми версиями."""
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(hosts)")}
        if "network" not in columns:
            self._conn.execute("ALTER TABLE hosts ADD COLUMN network TEXT NOT NULL DEFAULT ''")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ узлы

    def seed(self, hosts: Iterable[dict]) -> int:
        """Добавить узлы из конфигурации, если их ещё нет в базе."""
        added = 0
        with self._lock:
            for raw in hosts or ():
                name = str(raw.get("name") or "").strip()
                address = str(raw.get("address") or "").strip()
                if not name or not address:
                    continue
                if self._conn.execute("SELECT 1 FROM hosts WHERE name = ?", (name,)).fetchone():
                    continue
                self._conn.execute(
                    "INSERT INTO hosts (name, address, kind, port, interval, timeout, network, enabled)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                    (
                        name,
                        address,
                        str(raw.get("kind") or "icmp").lower(),
                        raw.get("port"),
                        raw.get("interval"),
                        raw.get("timeout"),
                        str(raw.get("network") or ""),
                    ),
                )
                added += 1
            self._conn.commit()
        return added

    def list_hosts(self, enabled_only: bool = False) -> list[Host]:
        sql = "SELECT * FROM hosts"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY name COLLATE NOCASE"
        with self._lock:
            rows = self._conn.execute(sql).fetchall()
        return [_row_to_host(row) for row in rows]

    def get_host(self, name: str) -> Host | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM hosts WHERE name = ? COLLATE NOCASE", (name,)
            ).fetchone()
        return _row_to_host(row) if row else None

    def find_host(self, name_or_address: str) -> Host | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM hosts WHERE name = ? COLLATE NOCASE OR address = ? LIMIT 1",
                (name_or_address, name_or_address),
            ).fetchone()
        return _row_to_host(row) if row else None

    def add_host(self, host: Host) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO hosts (name, address, kind, port, interval, timeout, network, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(name) DO UPDATE SET
                    address              = excluded.address,
                    kind                 = excluded.kind,
                    port                 = excluded.port,
                    interval             = excluded.interval,
                    timeout              = excluded.timeout,
                    network              = excluded.network,
                    enabled              = 1,
                    ok                   = NULL,
                    consecutive_failures = 0,
                    changed_at           = NULL,
                    last_notified        = NULL,
                    latency              = NULL,
                    detail               = ''
                """,
                (
                    host.name,
                    host.address,
                    host.kind,
                    host.port,
                    host.interval,
                    host.timeout,
                    host.network or "",
                ),
            )
            self._conn.commit()

    def remove_host(self, name: str) -> bool:
        with self._lock:
            cursor = self._conn.execute("DELETE FROM hosts WHERE name = ? COLLATE NOCASE", (name,))
            self._conn.commit()
        return cursor.rowcount > 0

    def set_enabled(self, name: str, enabled: bool) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE hosts SET enabled = ? WHERE name = ? COLLATE NOCASE",
                (1 if enabled else 0, name),
            )
            self._conn.commit()
        return cursor.rowcount > 0

    def rename_host(self, old_name: str, new_name: str) -> bool:
        """Переименовать узел, сохранив его состояние. False — имя занято."""
        with self._lock:
            taken = self._conn.execute(
                "SELECT 1 FROM hosts WHERE name = ? COLLATE NOCASE", (new_name,)
            ).fetchone()
            if taken:
                return False
            cursor = self._conn.execute(
                "UPDATE hosts SET name = ? WHERE name = ? COLLATE NOCASE", (new_name, old_name)
            )
            self._conn.commit()
        return cursor.rowcount > 0

    def update_state(
        self,
        name: str,
        *,
        ok: bool | None,
        consecutive_failures: int,
        latency: float | None,
        detail: str,
        changed_at: float | None,
        last_notified: float | None,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE hosts SET ok = ?, consecutive_failures = ?, latency = ?, detail = ?,
                                 changed_at = ?, last_notified = ?
                WHERE name = ?
                """,
                (
                    None if ok is None else int(ok),
                    consecutive_failures,
                    latency,
                    detail or "",
                    changed_at,
                    last_notified,
                    name,
                ),
            )
            self._conn.commit()

    # ------------------------------------------------------------ подписчики

    def add_subscriber(self, chat_id: int, title: str = "") -> bool:
        """Добавить чат. Возвращает True, если подписка новая."""
        with self._lock:
            exists = self._conn.execute(
                "SELECT 1 FROM subscribers WHERE chat_id = ?", (chat_id,)
            ).fetchone()
            self._conn.execute(
                """
                INSERT INTO subscribers (chat_id, title, notify, created_at)
                VALUES (?, ?, 1, ?)
                ON CONFLICT(chat_id) DO UPDATE SET title = excluded.title, notify = 1
                """,
                (chat_id, title or "", time.time()),
            )
            self._conn.commit()
        return exists is None

    def remove_subscriber(self, chat_id: int) -> bool:
        with self._lock:
            cursor = self._conn.execute("DELETE FROM subscribers WHERE chat_id = ?", (chat_id,))
            self._conn.commit()
        return cursor.rowcount > 0

    def set_notify(self, chat_id: int, notify: bool) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE subscribers SET notify = ? WHERE chat_id = ?",
                (1 if notify else 0, chat_id),
            )
            self._conn.commit()

    def list_subscribers(self, notify_only: bool = False) -> list[tuple[int, bool]]:
        sql = "SELECT chat_id, notify FROM subscribers"
        if notify_only:
            sql += " WHERE notify = 1"
        with self._lock:
            rows = self._conn.execute(sql).fetchall()
        return [(row["chat_id"], bool(row["notify"])) for row in rows]

    # ------------------------------------------------- отложенные события

    def add_outbox(self, at: float, host_name: str, kind: str, detail: str = "") -> None:
        """Сохранить событие, пришедшее вне окна уведомлений."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO outbox (at, host_name, kind, detail) VALUES (?, ?, ?, ?)",
                (at, host_name, kind, detail or ""),
            )
            self._conn.execute(
                "DELETE FROM outbox WHERE id NOT IN"
                " (SELECT id FROM outbox ORDER BY id DESC LIMIT ?)",
                (MAX_OUTBOX,),
            )
            self._conn.commit()

    def list_outbox(self) -> list[tuple[int, float, str, str, str]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM outbox ORDER BY id").fetchall()
        return [(row["id"], row["at"], row["host_name"], row["kind"], row["detail"]) for row in rows]

    def remove_outbox(self, ids: Iterable[int]) -> None:
        ids = list(ids)
        if not ids:
            return
        placeholders = ",".join("?" * len(ids))
        with self._lock:
            self._conn.execute(f"DELETE FROM outbox WHERE id IN ({placeholders})", ids)
            self._conn.commit()
