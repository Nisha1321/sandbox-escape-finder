"""Unit tests for the 5 static detectors -- each with a known positive
and a known negative snippet, per the task's explicit acceptance
criterion ("at least 5 technique classes are implemented with real
positive/negative test cases").
"""
import sys
sys.path.insert(0, "src")

import ast
import pytest

from sandbox_escape_finder.static.detectors import (
    SubclassesTraversalDetector,
    DunderGlobalsDetector,
    BuiltinsRestorationDetector,
    FrameIntrospectionDetector,
    FormatStringDetector,
)


def _findings_for(detector, code: str):
    tree = ast.parse(code)
    return [f for node in ast.walk(tree) for f in [detector.matches(node)] if f]


class TestSubclassesTraversalDetector:
    def test_positive(self):
        findings = _findings_for(
            SubclassesTraversalDetector(),
            "().__class__.__bases__[0].__subclasses__()",
        )
        assert len(findings) == 1
        assert findings[0].technique == "subclasses_traversal"

    def test_negative(self):
        findings = _findings_for(SubclassesTraversalDetector(), "x = [1, 2, 3]")
        assert findings == []


class TestDunderGlobalsDetector:
    def test_positive_globals(self):
        findings = _findings_for(DunderGlobalsDetector(), "(lambda: None).__globals__")
        assert len(findings) == 1

    def test_positive_closure(self):
        findings = _findings_for(
            DunderGlobalsDetector(), "(lambda x=1: (lambda: x))().__closure__"
        )
        assert len(findings) == 1

    def test_negative(self):
        findings = _findings_for(DunderGlobalsDetector(), "x.value")
        assert findings == []


class TestBuiltinsRestorationDetector:
    def test_positive(self):
        findings = _findings_for(BuiltinsRestorationDetector(), "reload(__builtins__)")
        assert len(findings) == 1

    def test_negative_unrelated_reload(self):
        # Reloading some OTHER module is completely normal and must NOT
        # be flagged -- only reloading __builtins__ specifically is the
        # dangerous, restoration-style pattern.
        findings = _findings_for(
            BuiltinsRestorationDetector(), "importlib.reload(my_module)"
        )
        assert findings == []


class TestFrameIntrospectionDetector:
    def test_positive(self):
        findings = _findings_for(
            FrameIntrospectionDetector(), "(x for x in []).gi_frame.f_back"
        )
        assert len(findings) == 2  # gi_frame AND f_back each match

    def test_negative(self):
        findings = _findings_for(FrameIntrospectionDetector(), "obj.value")
        assert findings == []


class TestFormatStringDetector:
    def test_positive(self):
        findings = _findings_for(
            FormatStringDetector(),
            '"{0.__class__}".format(object())',
        )
        assert len(findings) == 1

    def test_negative_benign_format(self):
        findings = _findings_for(FormatStringDetector(), '"Hello {0}".format(name)')
        assert findings == []
