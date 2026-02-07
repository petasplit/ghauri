#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modernized Ghauri configuration module (config.py) – February 2026

Changes:
• dataclass + field defaults instead of __init__ with many args
• Type hints everywhere
• Cleaner property logic (ignore_code, session_filepath)
• Removed redundant counters/flags that can be computed or moved
• Better separation: runtime state vs static config
• Prepared for Pydantic v2 migration (just inherit from BaseModel later)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from ghauri.common.lib import Lock


@dataclass
class GhauriConfig:
    """Central configuration container for Ghauri runtime behavior"""

    # ── Core injection & target settings ────────────────────────────────────────
    vectors: str = ""
    is_string: bool = False
    is_json: bool = False
    is_xml: bool = False
    is_multipart: bool = False
    skip_urlencoding: bool = False

    # ── HTTP / Network ──────────────────────────────────────────────────────────
    proxy: Optional[str] = None
    timeout: Optional[float] = 30.0
    delay: float = 0.0
    timesec: float = 5.0
    follow_redirects: Optional[bool] = None
    continue_on_http_error: bool = False
    ignore_code: str = ""               # comma-separated or "*"

    # ── Response comparison & stability ─────────────────────────────────────────
    text_only: bool = False
    string: Optional[str] = None
    not_string: Optional[str] = None
    code: Optional[int] = None
    match_ratio: Optional[float] = None

    # ── DBMS & technique hints ──────────────────────────────────────────────────
    backend: Optional[str] = None
    fetch_using: Optional[str] = None   # "binary", "between", "in", "equal"
    prioritize: bool = False            # heuristic forces error-based if detected
    test_filter: Optional[str] = None   # limit to specific techniques

    # ── Runtime behavior ────────────────────────────────────────────────────────
    batch: bool = False                 # non-interactive mode
    retry: int = 3
    threads: Optional[int] = None
    fresh_queries: bool = False         # ignore existing session data

    # ── File / Session paths ────────────────────────────────────────────────────
    filepaths: Any = None               # usually argparse.Namespace or similar
    _session_filepath: Optional[Path] = None

    # ── Internal runtime state (mutable, not config) ────────────────────────────
    base_response: Any = None
    attack01: Any = None                # last boolean false-positive attack
    request_counter: int = field(default=1, init=False)
    retry_counter: int = field(default=0, init=False)
    _readtimeout_counter: int = field(default=0, init=False)
    _cookie_encode_choice_made: bool = field(default=False, init=False)
    _encode_cookie: bool = field(default=False, init=False)
    _random_agent_dict: Dict[str, str] = field(default_factory=dict, init=False)

    # ── Threading & concurrency ─────────────────────────────────────────────────
    _max_threads: int = 10
    thread_warning_shown: bool = field(default=False, init=False)
    max_threads_warning_shown: bool = field(default=False, init=False)
    _thread_chars_query: Dict[int, str] = field(default_factory=dict, init=False)
    _mt_mode: bool = False              # multi-target mode

    # ── Locks & synchronization ─────────────────────────────────────────────────
    lock: Lock = field(default_factory=Lock, init=False)

    # ── Properties ──────────────────────────────────────────────────────────────

    @property
    def session_filepath(self) -> Optional[Path]:
        if self.filepaths and hasattr(self.filepaths, "session"):
            self._session_filepath = Path(self.filepaths.session)
        return self._session_filepath

    @property
    def parsed_ignore_codes(self) -> Set[int]:
        """Parsed --ignore-code values (handles '*' and comma list)"""
        if not self.ignore_code:
            return set()

        if self.ignore_code == "*":
            return {401}  # reasonable default wildcard behavior

        try:
            return {int(x.strip()) for x in self.ignore_code.split(",") if x.strip()}
        except ValueError:
            from ghauri.logger.colored_logger import logger
            logger.critical(
                "Invalid --ignore-code value. Use comma-separated integers or '*'."
            )
            raise SystemExit(1)

    @property
    def effective_timeout(self) -> float:
        """User timeout or fallback to reasonable default"""
        return self.timeout if self.timeout is not None else 30.0

    def reset_runtime_counters(self) -> None:
        """Reset transient counters between targets/parameters"""
        self.request_counter = 1
        self.retry_counter = 0
        self._readtimeout_counter = 0

    def __post_init__(self):
        """Any post-init normalization or warnings"""
        if self.threads is not None and self.threads > self._max_threads:
            from ghauri.logger.colored_logger import logger
            logger.warning(f"Threads capped at {self._max_threads} (requested: {self.threads})")
            self.threads = self._max_threads


# Global singleton instance (kept for compatibility)
conf = GhauriConfig()
