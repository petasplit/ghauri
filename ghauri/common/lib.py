#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modernized Ghauri common imports & constants (lib.py) – February 2026

Purpose:
• Single place for all third-party & stdlib imports
• Global constants, regex patterns, SQL statements
• Backward compatibility shims (if needed)

Changes:
• Removed unused/deprecated imports
• Grouped constants logically
• Compiled regex where performance matters
• Cleaner formatting & comments
"""

from __future__ import annotations

import base64
import binascii
import collections
import csv
import gzip
import html
import io
import itertools
import json
import logging
import os
import re
import shutil
import socket
import sqlite3
import stat
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor as futures
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import (
    parse_qs,
    quote,
    quote_plus,
    unquote,
    urlencode,
    urljoin,
    urlparse,
)

import chardet
import requests
import urllib3
from colorama import Back, Fore, Style, init

# ─── Third-party extras (minimal set) ───────────────────────────────────────────────

# ua_generator (if still used for random UA)
try:
    import ua_generator
except ImportError:
    ua_generator = None

# ─── Global constants ───────────────────────────────────────────────────────────────

GIT_REPOSITORY = "https://github.com/r0oth3x49/ghauri.git"
LATEST_VERSION_API = "https://api.github.com/repos/r0oth3x49/ghauri/releases/latest"

INJECTABLE_HEADERS_DEFAULT = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "User-Agent",
    "Referer",
    "Accept-Language",
    "X-Real-IP",
    "Client-IP",
]

AVOID_PARAMS = {
    "__ASYNCPOST",
    "__LASTFOCUS",
    "__EVENTTARGET",
    "__EVENTARGUMENT",
    "__VIEWSTATE",
    "__VIEWSTATEGENERATOR",
    "__VIEWSTATEENCRYPTED",
    "__EVENTVALIDATION",
    "__RequestVerificationToken",
    "_dc",
    "SAMLResponse",
    "RelayState",
    "__SCROLLPOSITIONY",
    "__SCROLLPOSITIONX",
}

DBMS_DICT = {
    "mssql": "Microsoft SQL Server",
    "microsoft sql server": "Microsoft SQL Server",
    "postgresql": "PostgreSQL",
    "mysql": "MySQL",
    "oracle": "Oracle",
}

# ─── SQL statements ─────────────────────────────────────────────────────────────────

SESSION_SCHEMA = """
DROP TABLE IF EXISTS tbl_payload;
DROP TABLE IF EXISTS storage;

CREATE TABLE tbl_payload (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    attempts INTEGER NOT NULL,
    payload TEXT NOT NULL,
    vector TEXT NOT NULL,
    backend TEXT NOT NULL,
    parameter TEXT NOT NULL,
    injection_type TEXT NOT NULL,
    payload_type TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    param_type TEXT,
    string TEXT DEFAULT '',
    not_string TEXT DEFAULT '',
    attack01 TEXT DEFAULT '',
    cases TEXT DEFAULT '' NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE storage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT,
    length INTEGER DEFAULT 0,
    type TEXT NOT NULL UNIQUE
);

CREATE INDEX idx_storage_type ON storage(type);
"""

PAYLOAD_STATEMENT = """
INSERT OR REPLACE INTO tbl_payload (
    title, attempts, payload, vector, backend, parameter,
    injection_type, payload_type, endpoint, param_type,
    string, not_string, attack01, cases
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

STORAGE_INSERT = "INSERT OR REPLACE INTO storage (value, length, type) VALUES (?, ?, ?);"
STORAGE_UPDATE = "UPDATE storage SET value = ?, length = ? WHERE type = ?;"

# ─── SQL error detection patterns (compiled for speed) ──────────────────────────────

SQL_ERROR_PATTERNS: Dict[str, List[re.Pattern]] = {
    "MySQL": [
        re.compile(r"(?i)SQL syntax.*?MySQL", re.I),
        re.compile(r"(?i)Warning.*?\Wmysqli?_", re.I),
        re.compile(r"(?i)You have an error in your SQL syntax", re.I),
        re.compile(r"(?i)check the manual that .*?MySQL.*?server version", re.I),
        re.compile(r"(?i)SQLSTATE\[\d+\]: Syntax error or access violation", re.I),
    ],
    "PostgreSQL": [
        re.compile(r"(?i)PostgreSQL.*ERROR", re.I),
        re.compile(r"(?i)ERROR:\s+syntax error at or near", re.I),
        re.compile(r"(?i)PSQLException", re.I),
        re.compile(r"(?i)org\.postgresql\.util\.PSQLException", re.I),
    ],
    "Microsoft SQL Server": [
        re.compile(r"(?i)Microsoft SQL.*Driver", re.I),
        re.compile(r"(?i)Msg \d+, Level \d+, State \d+", re.I),
        re.compile(r"(?i)Unclosed quotation mark after the character string", re.I),
        re.compile(r"(?i)SQL Server[^<>\"]+Driver", re.I),
        re.compile(r"(?i)System\.Data\.SqlClient\.SqlException", re.I),
    ],
    "Oracle": [
        re.compile(r"\bORA-[0-9]{4}", re.I),
        re.compile(r"(?i)Oracle error", re.I),
        re.compile(r"(?i)Warning.*oci_", re.I),
    ],
    "Microsoft Access": [
        re.compile(r"(?i)Microsoft Access Driver", re.I),
        re.compile(r"(?i)Syntax error.*query expression", re.I),
    ],
    # Add others if needed (SQLite, DB2, Sybase, Informix, etc.)
}

# ─── HTTP status code descriptions (partial – can be extended) ──────────────────────

HTTP_STATUS_REASONS = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}

# ─── Utility functions (minimal – most moved to utils.py) ───────────────────────────

def compile_sql_errors() -> None:
    """Pre-compile regex patterns on import for performance"""
    for dbms, patterns in SQL_ERROR_PATTERNS.items():
        SQL_ERROR_PATTERNS[dbms] = [re.compile(p, re.I) for p in patterns]
