from __future__ import annotations

from .adapters import adapt
from .canonical import CompilerResult


def adapt_modern(result: CompilerResult):
    return adapt(result, "modern", "modern")
