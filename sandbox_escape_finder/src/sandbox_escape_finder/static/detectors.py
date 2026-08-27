
from __future__ import annotations

import ast

from .base import Detector, Finding


class SubclassesTraversalDetector(Detector):

    technique = "subclasses_traversal"

    def matches(self, node: ast.AST) -> Finding | None:
        # In Python's ast module, `x.__subclasses__` parses as an
        # ast.Attribute node: node.value is the expression before the dot
        # (here, `x`), and node.attr is the attribute name as a plain
        # string (here, "__subclasses__").
        if not isinstance(node, ast.Attribute):
            return None
        if node.attr != "__subclasses__":
            return None

        return Finding(
            technique=self.technique,
            lineno=node.lineno,
            col_offset=node.col_offset,
            end_lineno=getattr(node, "end_lineno", None),
            end_col_offset=getattr(node, "end_col_offset", None),
            confidence=0.9,
            snippet_hint="attribute access to '__subclasses__'",
        )


class DunderGlobalsDetector(Detector):


    technique = "globals_closure_access"
    _DANGEROUS_NAMES = {"__globals__", "__closure__"}

    def matches(self, node: ast.AST) -> Finding | None:
        if not isinstance(node, ast.Attribute):
            return None
        if node.attr not in self._DANGEROUS_NAMES:
            return None

        return Finding(
            technique=self.technique,
            lineno=node.lineno,
            col_offset=node.col_offset,
            end_lineno=getattr(node, "end_lineno", None),
            end_col_offset=getattr(node, "end_col_offset", None),
            confidence=0.85,
            snippet_hint=f"attribute access to '{node.attr}'",
        )


class BuiltinsRestorationDetector(Detector):


    technique = "builtins_restoration"

    def matches(self, node: ast.AST) -> Finding | None:
        if not isinstance(node, ast.Call):
            return None

        # The function being called might be a bare name (`reload(...)`,
        # if it was imported directly) or an attribute on a module
        # (`importlib.reload(...)`). Handle both shapes.
        func = node.func
        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            func_name = func.attr
        else:
            return None

        if func_name != "reload":
            return None

        # Now check: is __builtins__ one of the arguments?
        targets_builtins = any(
            isinstance(arg, ast.Name) and arg.id == "__builtins__"
            for arg in node.args
        )
        if not targets_builtins:
            return None

        return Finding(
            technique=self.technique,
            lineno=node.lineno,
            col_offset=node.col_offset,
            end_lineno=getattr(node, "end_lineno", None),
            end_col_offset=getattr(node, "end_col_offset", None),
            confidence=0.9,
            snippet_hint="reload(__builtins__) call",
        )


class FrameIntrospectionDetector(Detector):


    technique = "frame_introspection"
    _FRAME_ATTRS = {"gi_frame", "f_back", "cr_frame", "f_globals", "f_locals"}

    def matches(self, node: ast.AST) -> Finding | None:
        if not isinstance(node, ast.Attribute):
            return None
        if node.attr not in self._FRAME_ATTRS:
            return None

        return Finding(
            technique=self.technique,
            lineno=node.lineno,
            col_offset=node.col_offset,
            end_lineno=getattr(node, "end_lineno", None),
            end_col_offset=getattr(node, "end_col_offset", None),
            confidence=0.75,
            snippet_hint=f"frame-introspection attribute access to '{node.attr}'",
        )


class FormatStringDetector(Detector):


    technique = "format_string_attribute_access"

    def matches(self, node: ast.AST) -> Finding | None:
        if not isinstance(node, ast.Call):
            return None
        func = node.func
        if not isinstance(func, ast.Attribute):
            return None
        if func.attr not in {"format", "format_map"}:
            return None

        target = func.value
        if not (isinstance(target, ast.Constant) and isinstance(target.value, str)):
            return None

        template_text = target.value
        if "__" not in template_text:
            return None

        return Finding(
            technique=self.technique,
            lineno=node.lineno,
            col_offset=node.col_offset,
            end_lineno=getattr(node, "end_lineno", None),
            end_col_offset=getattr(node, "end_col_offset", None),
            confidence=0.8,
            snippet_hint=f".{func.attr}() call on a template containing '__'",
        )
