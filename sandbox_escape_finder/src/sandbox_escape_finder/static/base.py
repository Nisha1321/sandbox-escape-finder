
from __future__ import annotations

import ast
from dataclasses import dataclass, asdict


@dataclass
class Finding:

    technique: str
    lineno: int
    col_offset: int
    end_lineno: int | None
    end_col_offset: int | None
    confidence: float
    snippet_hint: str  # short human-readable description of what matched

    def to_dict(self) -> dict:

        return asdict(self)


class Detector:

    technique: str = "base"  # subclasses must override this

    def matches(self, node: ast.AST) -> Finding | None:

        raise NotImplementedError
