# ghauri/tampers/space2comment.py
import re
from .base import BaseTamper, TamperResult, TamperStage


class Space2Comment(BaseTamper):
    name = "space2comment"
    description = "Replaces spaces with /**/ (classic WAF bypass)"
    stage = TamperStage.INJECTION
    priority = 15
    applies_to = {"boolean", "time", "error"}

    def tamper(self, payload: str, context: dict) -> TamperResult | None:
        # Replace spaces not inside quotes
        def repl(m: re.Match) -> str:
            return "/**/" if m.group(0).strip() else m.group(0)

        modified = re.sub(r"\s+", repl, payload)
        if modified == payload:
            return None
        return TamperResult(modified, applied=[self.name], confidence=0.92)
