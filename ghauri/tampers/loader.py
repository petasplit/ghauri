# ghauri/tampers/loader.py
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import List, Type

from .base import BaseTamper, TamperStage, TamperResult


def load_all_tampers() -> list[Type[BaseTamper]]:
    """Dynamically discover and load all tamper classes from tampers/ directory"""
    tampers_dir = Path(__file__).parent
    loaded: list[Type[BaseTamper]] = []

    for pyfile in tampers_dir.glob("*.py"):
        if pyfile.name in {"__init__.py", "base.py", "loader.py"}:
            continue

        module_name = f"ghauri.tampers.{pyfile.stem}"
        spec = importlib.util.spec_from_file_location(module_name, pyfile)
        if not spec or not spec.loader:
            continue

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseTamper)
                and attr is not BaseTamper
            ):
                loaded.append(attr)

    # Sort by priority (lower first)
    loaded.sort(key=lambda t: t.priority)
    return loaded


# Cache loaded tampers (loaded once per process)
_ALL_TAMPERS: list[Type[BaseTamper]] | None = None


def get_tamper_chain(
    stage: TamperStage,
    technique_type: str | None = None,  # "boolean", "time", "error", etc.
    user_selected: list[str] | None = None,
) -> list[BaseTamper]:
    """Build ordered list of tampers to apply"""
    global _ALL_TAMPERS
    if _ALL_TAMPERS is None:
        _ALL_TAMPERS = load_all_tampers()

    chain = []

    # User-selected tampers have highest priority
    if user_selected:
        name_to_cls = {t.name: t for t in _ALL_TAMPERS}
        for name in user_selected:
            if name.lower() == "all":
                chain.extend(t() for t in _ALL_TAMPERS if t.stage == stage)
                break
            if name in name_to_cls and name_to_cls[name].stage == stage:
                chain.append(name_to_cls[name]())

    # Auto-selected fallback
    else:
        for tamper_cls in _ALL_TAMPERS:
            if tamper_cls.stage != stage:
                continue
            if technique_type and technique_type not in tamper_cls.applies_to:
                continue
            chain.append(tamper_cls())

    return chain


def apply_tamper_chain(
    payload: str,
    stage: TamperStage,
    technique_type: str | None = None,
    user_selected: list[str] | None = None,
    context: dict[str, Any] | None = None,
) -> TamperResult:
    """Apply the full chain and return final payload + metadata"""
    chain = get_tamper_chain(stage, technique_type, user_selected)
    ctx = context or {}

    current = payload
    applied: list[str] = []
    total_confidence = 1.0

    for tamper in chain:
        result = tamper().tamper(current, ctx)
        if result is None:
            continue
        current = result.payload
        applied.extend(result.applied)
        total_confidence *= result.confidence

    return TamperResult(
        payload=current,
        applied=applied,
        confidence=total_confidence,
    )
