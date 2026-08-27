"""Shared building blocks for all technique detectors.

Every detector in this package answers the same question — "does this AST
node look like an attempt at MY specific technique?" — and reports back in
the same shape. That shared shape lives here so StaticAnalyzer can treat
every detector identically, without knowing anything about the individual
techniques.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, asdict


@dataclass
class Finding:
    """One suspected escape-technique match found in source code.

    This mirrors exactly what the task spec asks for: technique name, the
    matched AST node's source location, and a confidence score.
    """
    technique: str
    lineno: int
    col_offset: int
    end_lineno: int | None
    end_col_offset: int | None
    confidence: float
    snippet_hint: str  # short human-readable description of what matched

    def to_dict(self) -> dict:
        """Convert to a plain dict, since the public API promises
        `findings: list[dict]`, not a list of our internal dataclass."""
        return asdict(self)


class Detector:
    """Base class for a single escape-technique detector.

    Design note: each technique gets its OWN small subclass instead of one
    giant function with a chain of if/elif checks. That means each
    technique's detection logic can be unit-tested in isolation (hand it a
    snippet, check what it reports) without touching any other technique's
    logic, and adding a 6th technique later means adding one new class
    here, not editing a monolith that already handles five others.
    """

    technique: str = "base"  # subclasses must override this

    def matches(self, node: ast.AST) -> Finding | None:
        """Given a single AST node, return a Finding if this node matches
        this detector's technique, else None.

        This is called once per node during a single ast.walk() pass over
        the whole tree — see StaticAnalyzer.scan() for that loop. Each
        detector only inspects the node it's handed; it doesn't do its own
        tree-walking, so all detectors share one walk instead of each
        re-walking the same tree.
        """
        raise NotImplementedError
