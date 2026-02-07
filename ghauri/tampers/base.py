# ghauri/tampers/base.py
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class TamperStage(Enum):
    DETECTION = "detection"     # during initial tests / heuristic
    INJECTION = "injection"     # during payload sending (extract, confirm)
    EXTRACTION = "extraction"   # during data exfiltration (length, chars)


@dataclass
class TamperResult:
    payload: str
    applied: list[str] = None
    confidence: float = 1.0     # 0.0–1.0 heuristic usefulness

    def __post_init__(self):
        self.applied = self.applied or []


class BaseTamper:
    """Base class every tamper script must inherit from"""

    name: str = "base_tamper"
    description: str = "Base tamper – do not use directly"
    stage: TamperStage = TamperStage.INJECTION
    priority: int = 50          # lower = executed earlier
    applies_to: set[str] = {"boolean", "time", "error"}  # technique types

    def tamper(self, payload: str, context: dict[str, Any]) -> Optional[TamperResult]:
        """
        Main tamper method.
        Return None → skip this tamper
        Return TamperResult → use modified payload
        """
        raise NotImplementedError("Every tamper must implement .tamper()")
