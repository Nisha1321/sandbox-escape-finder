"""One concrete Detector subclass per escape technique.

Starting with __subclasses__ traversal -- the classic
().__class__.__bases__[0].__subclasses__() family of attacks.
"""
from __future__ import annotations

import ast

from .base import Detector, Finding


class SubclassesTraversalDetector(Detector):
    """Flags any attribute access named '__subclasses__'.

    Why match at the attribute-access level, not the call level:
    the dangerous part is REACHING the list of every loaded class at all --
    `x.__subclasses__` (no call) already exposes the bound method object,
    which is itself informative even before it's called. Matching on the
    Attribute node, rather than only on Call(func=Attribute(...)), catches
    both `obj.__subclasses__()` (called) and `obj.__subclasses__` (just
    referenced, maybe stored in a variable for later) in one check.

    Confidence rationale: '__subclasses__' has essentially no legitimate
    use in typical application code (it's a CPython introspection API for
    tooling/debuggers). Its mere presence as an attribute name is a strong
    signal on its own, independent of surrounding context, so this
    detector assigns a high fixed confidence rather than trying to reason
    about context.
    """

    technique = "subclasses_traversal"

    def matches(self, node: ast.AST) -> Finding | None:
        # In Python's ast module, `x.__subclasses__` parses as an
        # ast.Attribute node: node.value is the expression before the dot
        # (here, `x`), and node.attr is the attribute name as a plain
        # string (here, "__subclasses__"). We only care about the name.
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
    """Flags attribute access to '__globals__' or '__closure__'.

    Same shape as SubclassesTraversalDetector -- both are single dunder
    attribute names that expose dangerous internal state (a function's
    entire enclosing-scope namespace) the moment they're merely read, not
    only when something is done with the result afterward.

    Confidence: slightly below __subclasses__ (0.85 vs 0.9) because
    __closure__ specifically shows up a little more often in legitimate
    advanced/functional-programming code (e.g. decorator libraries
    inspecting closures) than __subclasses__ ever does in ordinary code --
    still rare, but not *quite* as unambiguous.
    """

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
    """Flags calls to reload(__builtins__) or importlib.reload(__builtins__).

    This one matches a CALL shape, not a bare attribute access -- we need
    to see BOTH that a function named 'reload' is being called AND that
    one of its arguments is literally the name '__builtins__'. Matching
    on 'reload' alone would false-positive on totally unrelated code that
    reloads some other module for ordinary development reasons (e.g.
    `importlib.reload(my_module)` during a Jupyter session is completely
    normal); it's specifically reloading __builtins__ that's the
    dangerous, restoration-style pattern.
    """

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
    """Flags attribute access to frame/generator-introspection attributes:
    gi_frame, f_back, cr_frame, f_globals, f_locals.

    These do NOT start with an underscore (unlike __subclasses__ /
    __globals__), which is exactly why this is a real, historically
    successful technique (CVE-2023-37271): RestrictedPython's default
    underscore-based guard simply doesn't apply to these names at all.

    Confidence: 0.75, lower than the dunder-prefixed detectors above,
    because these names are individually less exclusively-dangerous --
    f_locals/f_globals in particular can appear in legitimate debugging
    or introspection tooling more often than a dunder chain would.
    """

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
    """Flags .format() / .format_map() calls on a STRING LITERAL whose
    text contains a dunder attribute reference (e.g. '__class__').

    Design and known limitation: we only inspect string LITERALS written
    directly in the source (ast.Constant with a str value), because
    that's what static analysis can see. A format string assembled at
    runtime (e.g. via string concatenation, or built from user input)
    would NOT be caught here -- this mirrors the exact same category of
    limitation as the chr()-obfuscation evasion we discussed earlier
    (pyjailbreaker): static text-pattern matching can always be evaded by
    NOT writing the dangerous text directly in the source. Worth stating
    explicitly in the README as a documented limitation, not silently
    pretending this detector is complete.
    """

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
