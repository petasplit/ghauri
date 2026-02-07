#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modernized Ghauri HTTP request handler (request.py) – February 2026 final

Upgrades:
• httpx.Client with connection pooling (default) & HTTP/2
• Single reusable client instance (performance critical for blind/time-based)
• Specific exceptions instead of broad except
• Removed urllib fallback & requests conditional
• Jitter in timing + better timeout granularity
• Backward compatible return type (namedtuple)
• Ready for async transition (commented)

This module is now **locked**.
"""

from __future__ import annotations

import random
import time
from collections import namedtuple
from typing import Any, Optional

import httpx

from ghauri.common.config import conf
from ghauri.logger.colored_logger import logger
from ghauri.common.utils import (
    unescape_html,
    prepare_request,
    parse_http_response,
    prepare_response,
)

# ─── Module-level httpx Client (connection pooling) ────────────────────────────────

# Reusable client – created once, reused forever (pooling benefit)
# Limits can be tuned via conf if needed
_http_client = httpx.Client(
    http2=True,
    follow_redirects=True,
    timeout=httpx.Timeout(30.0, connect=10.0, read=30.0, write=10.0, pool=30.0),
    limits=httpx.Limits(
        max_connections=100,
        max_keepalive_connections=20,
        keepalive_expiry=60.0,
    ),
)


def get_http_client() -> httpx.Client:
    """Get shared client instance (pooling + HTTP/2)"""
    return _http_client


# For future async version (when we migrate extract/inject to async)
# _async_client = None
# async def get_async_client():
#     global _async_client
#     if _async_client is None:
#         _async_client = httpx.AsyncClient(http2=True, ...)
#     return _async_client


# ─── Response structure (backward compatibility) ───────────────────────────────────

HTTPResponse = namedtuple(
    "HTTPResponse",
    [
        "ok",
        "url",
        "data",
        "text",
        "path",
        "method",
        "reason",
        "headers",
        "error_msg",
        "redirected",
        "request_url",
        "status_code",
        "response_time",
        "content_length",
        "filtered_text",
    ],
)


class HTTPRequestHandler:
    """
    Modern httpx-based request performer – used by inject_expression
    """

    def perform(
        self,
        url: str,
        data: str = "",
        proxy: str = "",
        headers: str = "",
        timeout: float = 30.0,
        verify: bool = False,
        use_requests: bool = False,  # ignored – we use httpx
        connection_test: bool = False,
        follow_redirects: bool = True,
        is_multipart: bool = False,
    ) -> HTTPResponse:

        # ── Prepare request components ──────────────────────────────────────────
        if connection_test:
            url = url.replace("*", "")
            data = data.replace("*", "") if data else ""
            # headers cleanup if needed

        req = prepare_request(
            url=url,
            data=data,
            custom_headers=headers,
            use_requests=False,  # legacy – ignored
        )

        raw_request = req.raw
        endpoint = req.endpoint
        custom_headers = req.headers

        if conf._random_agent_dict:
            custom_headers.update(conf._random_agent_dict)
        if conf.is_json:
            custom_headers["Content-Type"] = "application/json"

        request_url = req.request.get("url", url)

        logger.traffic_out(f"HTTP request [#{conf.request_counter}]:\n{raw_request}")

        # ── Proxy setup ─────────────────────────────────────────────────────────
        proxies = {"all://": proxy} if proxy else None

        # ── Execute request ─────────────────────────────────────────────────────
        client = get_http_client()
        start_time = time.perf_counter()

        try:
            if not data:
                method = "GET"
                resp = client.get(
                    request_url,
                    headers=custom_headers,
                    proxies=proxies,
                    timeout=timeout,
                )
            else:
                method = "POST"
                if is_multipart or conf.is_multipart:
                    # Expect dict with 'data' and/or 'files'
                    post_kwargs = {}
                    if isinstance(data, dict):
                        post_kwargs["data"] = data.get("data")
                        post_kwargs["files"] = data.get("files")
                    else:
                        post_kwargs["data"] = data
                    resp = client.post(
                        request_url,
                        headers=custom_headers,
                        proxies=proxies,
                        timeout=timeout,
                        **post_kwargs,
                    )
                else:
                    resp = client.post(
                        request_url,
                        data=data,
                        headers=custom_headers,
                        proxies=proxies,
                        timeout=timeout,
                    )

            resp.raise_for_status()

        except httpx.TimeoutException as exc:
            logger.debug(f"Timeout during request: {exc}")
            conf._readtimout_counter = getattr(conf, '_readtimout_counter', 0) + 1
            parsed = self._error_to_response(exc, url, is_timeout=True)
        except httpx.HTTPStatusError as exc:
            parsed = parse_http_response(exc.response) if exc.response else self._error_to_response(exc)
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            logger.critical(f"Connection failed: {type(exc).__name__}")
            raise
        except Exception as exc:
            logger.critical(f"Unexpected request error: {type(exc).__name__}")
            raise
        else:
            parsed = parse_http_response(resp)

        end_time = time.perf_counter()
        response_time = end_time - start_time + random.uniform(0.0, 0.08)  # light jitter

        redirected = parsed.status_code in {301, 302, 303, 307, 308}

        http_response = HTTPResponse(
            ok=parsed.ok,
            url=parsed.url,
            data=data,
            text=parsed.text,
            path=endpoint,
            method=method,
            reason=parsed.reason,
            headers=parsed.headers,
            error_msg=parsed.error,
            redirected=redirected,
            request_url=request_url,
            status_code=parsed.status_code,
            response_time=response_time,
            content_length=parsed.content_length,
            filtered_text=parsed.filtered_text,
        )

        raw_response = prepare_response(http_response)
        logger.traffic_in(f"HTTP response {raw_response}\n")

        conf.request_counter += 1

        return http_response

    def _error_to_response(
        self,
        exc: Exception,
        url: str,
        is_timeout: bool = False,
    ) -> Any:
        """Minimal fallback response object for errors"""
        class ErrorResponse:
            def __init__(self):
                self.ok = False
                self.url = url
                self.status_code = 0
                self.reason = str(exc)
                self.text = ""
                self.headers = {}
                self.content_length = 0
                self.filtered_text = ""
                self.error = str(exc) if not is_timeout else "Read timeout"

        return ErrorResponse()


request = HTTPRequestHandler() 
