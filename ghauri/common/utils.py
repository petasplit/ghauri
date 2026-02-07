#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modernized Ghauri utilities module (utils.py) – February 2026

Key improvements:
• Type hints & dataclasses instead of old Struct
• Cleaner HTTP request parser using email.message
• Centralized regex/constants
• Better error handling & logging
• Removed dead/duplicated code
• Prepared for future extensions (multipart, headers parsing)
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from email.message import Message
from email.parser import BytesParser
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, quote, quote_plus, unquote, urljoin, urlparse

from ghauri.common.config import conf
from ghauri.common.payloads import PAYLOADS  # only if needed
from ghauri.logger.colored_logger import logger


# ─── Constants & Regex patterns ─────────────────────────────────────────────────────

SQL_ERRORS = {  # common SQL error fragments (for detection)
    "mysql": re.compile(r"(?i)(sql syntax|mysql_fetch|you have an error in your sql)", re.I),
    "mssql": re.compile(r"(?i)(microsoft sql|sql server|incorrect syntax near)", re.I),
    "oracle": re.compile(r"(?i)(ora-[0-9]{4}|oracle error)", re.I),
    "postgres": re.compile(r"(?i)(pgsql|postgres|psycopg2|syntax error at or near)", re.I),
}

AVOID_PARAMS = {"__VIEWSTATE", "__EVENTVALIDATION", "__REQUESTVERIFICATIONTOKEN"}


# ─── Modern Struct replacement ──────────────────────────────────────────────────────

@dataclass(frozen=True, eq=True)
class Parameter:
    """Immutable representation of an injectable parameter"""

    key: str
    value: str
    type: str = "GET"  # GET, POST, HEADER, COOKIE, etc.
    is_injected: bool = False

    def __post_init__(self):
        if not self.key:
            raise ValueError("Parameter key cannot be empty")

    def __repr__(self) -> str:
        return f"Parameter(key={self.key!r}, type={self.type}, value={self.value[:20]!r}...)"


# ─── HTTP Request Parser ────────────────────────────────────────────────────────────

class ParsedHTTPRequest:
    """Parsed raw HTTP request (from file, Burp, etc.)"""

    def __init__(self, raw_request: str | bytes):
        self.raw = raw_request if isinstance(raw_request, bytes) else raw_request.encode("utf-8", errors="replace")
        self.is_multipart: bool = False
        self.method: str = ""
        self.path: str = ""
        self.protocol: str = "HTTP/1.1"
        self.headers: Dict[str, str] = {}
        self.body: Optional[bytes] = None
        self.url: str = ""
        self._parse()

    def _parse(self) -> None:
        """Parse raw HTTP request using email.message + manual first line"""
        # Handle Burp base64 wrapper
        if b"<request base64=" in self.raw:
            match = re.search(rb'base64=(["\'])(true|false)\1.*?CDATA\[(.*?)\]\]', self.raw, re.DOTALL)
            if match:
                is_b64 = match.group(2) == b"true"
                content = match.group(3)
                self.raw = base64.b64decode(content) if is_b64 else content

        parser = BytesParser()
        msg: Message = parser.parsebytes(self.raw)

        # First line: METHOD PATH PROTOCOL
        first_line = self.raw.split(b"\r\n", 1)[0].decode("ascii", errors="ignore")
        parts = first_line.split()
        if len(parts) >= 2:
            self.method = parts[0]
            self.path = parts[1]
            if len(parts) >= 3:
                self.protocol = parts[2]

        # Headers
        for key, value in msg.items():
            if key:
                self.headers[key] = value.strip()

        # Body
        payload = msg.get_payload(decode=True)
        if isinstance(payload, bytes):
            self.body = payload
            if "multipart/form-data" in self.headers.get("Content-Type", ""):
                self.is_multipart = True

        # Reconstruct full URL
        host = self.headers.get("Host", "localhost")
        scheme = "https" if self.headers.get("Referer", "").startswith("https") else "http"
        self.url = f"{scheme}://{host}{self.path}"

    @property
    def cookies(self) -> Dict[str, str]:
        """Parsed Cookie header as dict"""
        cookie_str = self.headers.get("Cookie", "")
        return dict(parse_qs(cookie_str.replace(";", "&")))

    def __repr__(self) -> str:
        return f"ParsedHTTPRequest(method={self.method}, url={self.url}, multipart={self.is_multipart})"


def parse_http_request(raw: str | bytes) -> ParsedHTTPRequest:
    """Public factory function for parsing raw HTTP requests"""
    return ParsedHTTPRequest(raw)


# ─── Encoding / Decoding helpers ────────────────────────────────────────────────────

def safe_encode(value: Any, encode: bool = True) -> str:
    """URL-encode value unless skipped or already encoded"""
    if not encode or conf.skip_urlencoding:
        return str(value)
    return quote_plus(str(value))


def safe_decode(value: str) -> str:
    """Safely URL-decode (ignores errors)"""
    try:
        return unquote(value)
    except Exception:
        return value


def encode_object(obj: Any, decode: bool = False) -> str:
    """Base64 + JSON round-trip for session storage"""
    if decode:
        try:
            decoded = base64.b64decode(obj).decode("utf-8")
            return json.loads(decoded)
        except Exception as e:
            logger.debug(f"Decode failed: {e}")
            return {}
    else:
        try:
            json_str = json.dumps(obj, ensure_ascii=False)
            return base64.b64encode(json_str.encode("utf-8")).decode("ascii")
        except Exception as e:
            logger.debug(f"Encode failed: {e}")
            return ""


# ─── Diff / similarity helpers ──────────────────────────────────────────────────────

def content_diff(a: str, b: str) -> float:
    """Simple similarity ratio between two strings (0.0–1.0)"""
    from difflib import SequenceMatcher

    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def is_content_stable(a: str, b: str, threshold: float = 0.98) -> bool:
    """Check if two page contents are stable enough for boolean comparison"""
    return content_diff(a, b) >= threshold


# ─── Other utilities ────────────────────────────────────────────────────────────────

def extract_host_port(url: str) -> Tuple[str, Optional[int]]:
    """Extract host and port from URL"""
    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port
    return host, port


def generate_random_ua() -> Dict[str, str]:
    """Generate randomized User-Agent headers"""
    from ghauri.common.lib import ua_generator  # assuming this exists

    ua = ua_generator.generate()
    return {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }


# Legacy compatibility (old code using Struct)
class LegacyStruct:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return f"<Struct({', '.join(f'{k}={v!r}' for k,v in self.__dict__.items())})>"
