# ghauri/tampers/charencode.py
from .base import BaseTamper, TamperResult, TamperStage


class CharEncode(BaseTamper):
    name = "charencode"
    description = "URL-encodes every character in payload"
    stage = TamperStage.INJECTION
    priority = 10
    applies_to = {"boolean", "time", "error"}

    def tamper(self, payload: str, context: dict) -> TamperResult | None:
        if not payload.strip():
            return None
        encoded = "".join(f"%{ord(c):02X}" for c in payload)
        return TamperResult(encoded, applied=[self.name], confidence=0.88)
