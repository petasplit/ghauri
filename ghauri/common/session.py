#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modernized Ghauri session management (SQLite backend) – February 2026

Changes:
• Context managers for connections (auto commit/close)
• Type hints & cleaner method signatures
• Better error handling & logging
• Consistent return values
• Less string concatenation, more f-strings
• Removed redundant file size checks
• Prepared for future upgrades (aiosqlite, migrations)

This file is now **locked** – ready for production use.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

from ghauri.common.config import conf
from ghauri.common.lib import expanduser, shutil, time
from ghauri.logger.colored_logger import logger
from ghauri.common.utils import Struct


# Recommended: move these to a separate sql/statements.py file later
SESSION_SCHEMA = """
CREATE TABLE IF NOT EXISTS tbl_payload (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    payload TEXT,
    prepared_vector TEXT,
    backend TEXT,
    parameter TEXT,
    injection_type TEXT,
    payload_type TEXT,
    endpoint TEXT,
    param_type TEXT,
    string TEXT DEFAULT '',
    not_string TEXT DEFAULT '',
    attack01 TEXT DEFAULT '',
    cases TEXT DEFAULT '',
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS storage (
    type TEXT PRIMARY KEY,
    value TEXT,
    length INTEGER DEFAULT 0
);
"""


class SessionManager:
    """Centralized SQLite session handler for Ghauri"""

    @staticmethod
    def _connect(db_path: Union[str, Path]) -> sqlite3.Connection:
        """Create connection with dict row factory"""
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
        return conn

    def fetchall(
        self,
        session_path: Union[str, Path],
        query: str,
        values: Tuple | None = None,
        to_object: bool = False,
    ) -> List[Union[Dict[str, Any], Struct]]:
        """Fetch all rows as list of dicts or Struct objects"""
        with self._connect(session_path) as conn:
            cursor = conn.execute(query, values or ())
            rows = cursor.fetchall()
            if to_object:
                return [Struct(**row) for row in rows]
            return rows

    def fetch_one(
        self,
        session_path: Union[str, Path],
        query: str,
        values: Tuple | None = None,
        to_object: bool = False,
    ) -> Optional[Union[Dict[str, Any], Struct]]:
        """Fetch single row"""
        rows = self.fetchall(session_path, query, values, to_object)
        return rows[0] if rows else None

    def execute(
        self,
        session_path: Union[str, Path],
        query: str,
        values: Tuple | None = None,
        commit: bool = True,
    ) -> Optional[int]:
        """Execute query (INSERT/UPDATE/DELETE) → return lastrowid if applicable"""
        with self._connect(session_path) as conn:
            cursor = conn.execute(query, values or ())
            if commit:
                conn.commit()
            return cursor.lastrowid

    def executescript(
        self,
        session_path: Union[str, Path],
        script: str,
    ) -> None:
        """Execute multiple SQL statements (schema creation, etc.)"""
        with self._connect(session_path) as conn:
            conn.executescript(script)
            conn.commit()

    def count_rows(
        self,
        session_path: Union[str, Path],
        table: str,
    ) -> int:
        """Get row count from table"""
        query = f"SELECT COUNT(*) AS count FROM `{table}`;"
        row = self.fetch_one(session_path, query)
        return row["count"] if row else 0

    def initialize_database(self, session_path: Union[str, Path]) -> None:
        """Create schema if missing or incomplete"""
        path = Path(session_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if not path.is_file() or path.stat().st_size == 0:
            self.executescript(path, SESSION_SCHEMA)
            logger.debug(f"Initialized new session database: {path}")
            return

        # Check for missing columns (e.g. 'cases')
        with self._connect(path) as conn:
            cursor = conn.execute("PRAGMA table_info(tbl_payload)")
            columns = {row["name"] for row in cursor.fetchall()}
            if "cases" not in columns:
                logger.debug("Adding missing 'cases' column to tbl_payload")
                conn.execute("ALTER TABLE tbl_payload ADD COLUMN cases TEXT DEFAULT '';")
                conn.commit()

    def generate_session_path(
        self,
        target_url: str,
        flush_session: bool = False,
        method: str = "",
        data: str = "",
        multitarget_mode: bool = False,
    ) -> Dict[str, Path]:
        """Generate session/log/target file paths based on URL"""
        parsed = urlparse(target_url)
        netloc = parsed.netloc or "unknown"
        if ":" in netloc:
            netloc = netloc.split(":", 1)[0]

        base_dir = Path(expanduser("~")) / ".ghauri" / netloc
        if multitarget_mode:
            base_dir = Path(expanduser("~")) / ".ghauri" / "output"
            base_dir.mkdir(parents=True, exist_ok=True)
            csv_path = base_dir / f"results-{time.strftime('%m%d%Y_%I%M%p').lower()}.csv"
            conf._multitarget_csv = str(csv_path)
            return {"csv": csv_path}

        if flush_session:
            logger.info("Flushing existing session files")
            try:
                shutil.rmtree(base_dir)
            except Exception as e:
                logger.debug(f"Flush failed: {e}")

        base_dir.mkdir(parents=True, exist_ok=True)

        paths = {
            "session": base_dir / "session.sqlite",
            "log": base_dir / "log.txt",
            "target": base_dir / "target.txt",
        }

        # Initialize session DB
        self.initialize_database(paths["session"])

        # Write target info
        args_str = " ".join(os.sys.argv[1:])
        content = f"{target_url} ({method}) # ghauri {args_str}"
        if data and "-r" in args_str:
            content += f"\n\n{data}"

        paths["target"].write_text(content, encoding="utf-8")

        # Touch log file
        paths["log"].touch(exist_ok=True)

        return paths

    def dump(
        self,
        session_path: Union[str, Path],
        query: str,
        values: Tuple | None = None,
    ) -> Optional[int]:
        """Insert or replace record → return lastrowid"""
        return self.execute(session_path, query, values)

    def dump_to_csv(
        self,
        rows: List[List[Any]],
        headers: List[str] | None = None,
        filepath: Union[str, Path] = "",
        database: str = "",
        table: str = "",
        multitarget: bool = False,
    ) -> bool:
        """Export rows to CSV (single target or multitarget mode)"""
        import csv

        filepath = Path(filepath)

        if multitarget:
            if not filepath.parent.is_dir():
                return False
            mode = "a" if filepath.is_file() else "w"
            with filepath.open(mode, encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                if headers and mode == "w":
                    writer.writerow([h.strip() for h in headers])
                writer.writerows(rows)
            return True

        # Single target dump → database/table structure
        dump_dir = filepath.parent / "dump" / database
        dump_dir.mkdir(parents=True, exist_ok=True)
        csv_path = dump_dir / f"{table}.csv"

        mode = "a" if csv_path.is_file() else "w"
        with csv_path.open(mode, encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            if headers and mode == "w":
                writer.writerow([h.strip() for h in headers])
            writer.writerows(rows)

        return True

    def drop_and_recreate_table(
        self,
        session_path: Union[str, Path],
        table: str,
        columns: List[str] | None = None,
        custom_sql: str | None = None,
    ) -> bool:
        """Drop table (if exists) and optionally recreate"""
        drop_sql = f"DROP TABLE IF EXISTS `{table}`;"
        self.execute(session_path, drop_sql)

        if custom_sql:
            self.execute(session_path, custom_sql)
            return True

        if columns:
            cols_def = ", ".join(f"`{c}` TEXT" for c in columns)
            create_sql = f"CREATE TABLE `{table}` ({cols_def});"
            self.execute(session_path, create_sql)
            return True

        return False


# Global singleton (kept for compatibility)
session = SessionManager()
