"""StaticAnalyzer: the public-facing class that orchestrates all detectors.

scan(source_code) parses the source into an AST, then does ONE
ast.walk(tree) pass, calling every enabled detector's .matches(node) on
every node (the "single shared walk" design decision from our
SubclassesTraversalDetector discussion). Every non-None Finding gets
converted to a dict via .to_dict() and collected into the returned
list[dict].
"""
from __future__ import annotations

import ast

from .base import Detector
from .detectors import (
    SubclassesTraversalDetector,
    DunderGlobalsDetector,
    BuiltinsRestorationDetector,
    FrameIntrospectionDetector,
    FormatStringDetector,
)
from ..config import validate_config

_ALL_DETECTORS = {
    "subclasses_traversal": SubclassesTraversalDetector,
    "globals_closure_access": DunderGlobalsDetector,
    "builtins_restoration": BuiltinsRestorationDetector,
    "frame_introspection": FrameIntrospectionDetector,
    "format_string_attribute_access": FormatStringDetector,
}


class StaticAnalyzer:
    def __init__(self, config: dict | None = None):
        self.config = validate_config(config or {})
        enabled = self.config["enabled_techniques"]
        self.detectors: list[Detector] = [
            _ALL_DETECTORS[name]() for name in enabled if name in _ALL_DETECTORS
        ]

    def scan(self, source_code: str) -> list[dict]:
        tree = ast.parse(source_code)
        findings = []
        threshold = self.config["confidence_threshold"]
        for node in ast.walk(tree):
            for detector in self.detectors:
                finding = detector.matches(node)
                if finding is not None and finding.confidence >= threshold:
                    findings.append(finding.to_dict())
        return findings
