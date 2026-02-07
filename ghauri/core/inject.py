#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ghauri injection core – finalized & modernized version (February 2026)

Features / upgrades:
• httpx instead of requests (HTTP/2, better timeouts, connection pooling ready)
• Loop-based retry (no recursion)
• Tamper application point before payload encoding/preparation
• Randomized UA + jitter for evasion
• Structured exception handling
• Multipart / GET / POST / Header / Cookie injection types preserved
• Backward compatibility layer for old request.perform calls

This file is now considered **locked** – no structural changes needed anymore.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any

import httpx

from ghauri.common.config import conf
from ghauri.logger.colored_logger import logger
from ghauri.common.utils import prepare_attack_request, urldecode


# ─── Tamper integration (aligned with extract.py) ──────────────────────────────────

class TamperStage:
    INJECTION = "injection"


@dataclass
class TamperResult:
    payload: str
    applied: list[str] = None

    def __post_init__(self):
        self.applied = self.applied or []


def apply_tampers(
    expression: str,
    stage: str = TamperStage.INJECTION,
    context: dict | None = None,
) -> TamperResult:
    """
    Hook for tamper chain – implement in ghauri/tampers/engine.py
    Currently identity transform.
    """
    # Placeholder example:
    # encoded = quote(expression)
    # return TamperResult(encoded, applied=["urlencode"])
    return TamperResult(payload=expression)


# ─── Retry & backoff constants ─────────────────────────────────────────────────────

MAX_RETRIES: Final = 5
BASE_BACKOFF: Final = 0.9      # seconds
JITTER_MIN_MAX: Final = (0.0, 0.7)


def _is_retryable(exc: Exception) -> bool:
    retryable_types = (
        httpx.TimeoutException,
        httpx.ConnectError,
        httpx.ConnectTimeout,
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.PoolTimeout,
        httpx.NetworkError,
        ConnectionResetError,
        ConnectionAbortedError,
        ConnectionRefusedError,
    )
    return isinstance(exc, retryable_types)


# ─── Randomized headers (evasion helper) ───────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Edg/120.0.2210.91",
]


def _randomized_headers(original: dict | None = None) -> dict:
    headers = dict(original or {})
    headers.setdefault("User-Agent", random.choice(USER_AGENTS))
    # Optional: add Accept, Accept-Language randomization if needed
    return headers


# ─── Core injection function ───────────────────────────────────────────────────────

def inject_expression(
    url: str,
    data: Any = None,
    proxy: str | None = None,
    delay: float = 0.0,
    timesec: float = 5.0,
    timeout: float = 30.0,
    headers: dict | None = None,
    parameter: Any = None,
    expression: str | None = None,
    is_multipart: bool = False,
    injection_type: str | None = None,
    connection_test: bool = False,
) -> httpx.Response | None:
    """
    Main entry point for sending tampered / injected requests.
    Returns httpx.Response on success or raises on persistent failure.
    """

    # Override timeout if user specified higher value
    effective_timeout = max(timeout, conf.timeout if hasattr(conf, 'timeout') else 0)

    # ── 1. Apply tampers ────────────────────────────────────────────────────────
    if expression:
        tamper_res = apply_tampers(expression)
        expression = tamper_res.payload
        if tamper_res.applied:
            logger.debug(f"Tampers applied: {', '.join(tamper_res.applied)}")
        logger.payload(urldecode(expression))

    # ── 2. Prepare target components ────────────────────────────────────────────
    attack_url = url
    attack_data = data
    attack_headers = _randomized_headers(headers)

    orig_param_value = parameter.value.replace("*", "") if parameter else ""

    if not connection_test and expression:
        match injection_type:
            case "HEADER":
                attack_headers = prepare_attack_request(
                    headers, expression, param=parameter, injection_type=injection_type
                )
            case "COOKIE":
                if not getattr(conf, '_is_cookie_choice_taken', False) and not conf.skip_urlencoding:
                    choice = logger.read_input(
                        "URL-encode cookie values? [Y/n] ",
                        batch=conf.batch,
                        user_input="Y"
                    )
                    conf._encode_cookie = choice.lower() != "n"
                    conf._is_cookie_choice_taken = True
                attack_headers = prepare_attack_request(
                    headers, expression, param=parameter,
                    encode=getattr(conf, '_encode_cookie', False),
                    injection_type=injection_type
                )
            case "GET":
                attack_url = prepare_attack_request(
                    url, expression, param=parameter,
                    encode=not conf.skip_urlencoding,
                    injection_type=injection_type
                )
            case "POST":
                attack_data = prepare_attack_request(
                    data, expression, param=parameter,
                    encode=not conf.skip_urlencoding,
                    injection_type=injection_type
                )

    # ── 3. Build httpx client ───────────────────────────────────────────────────
    proxies = {"all://": proxy} if proxy else None

    client = httpx.Client(
        proxies=proxies,
        timeout=httpx.Timeout(effective_timeout, connect=effective_timeout / 2),
        follow_redirects=True,
        http2=True,                     # enable where server supports it
    )

    # ── 4. Execute with retry + backoff ─────────────────────────────────────────
    attempt = 0
    while attempt < MAX_RETRIES:
        attempt += 1

        if delay > 0:
            time.sleep(delay + random.uniform(*JITTER_MIN_MAX))

        try:
            if injection_type == "GET" or attack_data is None:
                resp = client.get(attack_url, headers=attack_headers)
            else:
                if is_multipart or getattr(conf, 'is_multipart', False):
                    # Expect prepare_attack_request returned {'data': ..., 'files': ...}
                    if isinstance(attack_data, dict):
                        resp = client.post(
                            attack_url,
                            data=attack_data.get('data'),
                            files=attack_data.get('files'),
                            headers=attack_headers,
                        )
                    else:
                        resp = client.post(attack_url, data=attack_data, headers=attack_headers)
                else:
                    resp = client.post(attack_url, data=attack_data, headers=attack_headers)

            status = resp.status_code

            if status == 401:
                ignore_codes = getattr(conf, 'ignore_code', set())
                if status in ignore_codes:
                    logger.debug(f"Ignoring {status} per --ignore-code")
                else:
                    logger.critical(
                        "401 Unauthorized → provide auth or use --ignore-code=401"
                    )
                    raise SystemExit(1)

            return resp

        except httpx.TimeoutException as exc:
            logger.warning(f"Timeout ({exc.__class__.__name__}) – attempt {attempt}/{MAX_RETRIES}")
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            logger.warning(f"Connection issue – attempt {attempt}/{MAX_RETRIES}")
        except Exception as exc:
            logger.critical(f"Unexpected injection error: {type(exc).__name__}")
            if attempt == MAX_RETRIES:
                raise

        # Exponential backoff + jitter
        backoff = BASE_BACKOFF * (2.1 ** (attempt - 1))
        time.sleep(backoff + random.uniform(*JITTER_MIN_MAX))

    logger.critical(f"Failed after {MAX_RETRIES} attempts → target unreachable / blocked?")
    raise RuntimeError("Injection retry limit exceeded")


# Backward compatibility shim (old code calls request.perform)
class LegacyRequest:
    @staticmethod
    def perform(**kwargs):
        return inject_expression(**kwargs)


request = LegacyRequest() 
