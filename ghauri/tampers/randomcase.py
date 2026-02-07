# ghauri/tampers/randomcase.py
import random
import re
from .base import BaseTamper, TamperResult, TamperStage


class RandomCase(BaseTamper):
    name = "randomcase"
    description = "Randomize case of SQL keywords"
    stage = TamperStage.INJECTION
    priority = 20
    applies_to = {"boolean", "time", "error"}

    KEYWORDS = {
        "SELECT", "UNION", "ALL", "FROM", "WHERE", "AND", "OR",
        "SLEEP", "BENCHMARK", "WAITFOR", "DELAY", "IF", "CASE"
    }

    def tamper(self, payload: str, context: dict) -> TamperResult | None:
        def randomize(word: str) -> str:
            return "".join(random.choice([c.upper(), c.lower()]) for c in word)

        def repl(m: re.Match) -> str:
            w = m.group(0)
            if w.upper() in self.KEYWORDS:
                return randomize(w)
            return w

        modified = re.sub(r"\b[a-zA-Z]+\b", repl, payload, flags=re.IGNORECASE)
        if modified == payload:
            return None
        return TamperResult(modified, applied=[self.name], confidence=0.75)
