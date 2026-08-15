from __future__ import annotations

from .adapters import adapt
from .canonical import CompilerResult


def adapt_legacy(result: CompilerResult):
    return adapt(result, "legacy", "legacy")
