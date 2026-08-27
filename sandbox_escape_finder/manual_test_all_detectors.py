import sys
sys.path.insert(0, "src")

from sandbox_escape_finder.static.analyzer import StaticAnalyzer

analyzer = StaticAnalyzer()

# Each entry: (label, code, expected_technique_or_None)
cases = [
    ("subclasses positive",
     "().__class__.__bases__[0].__subclasses__()",
     "subclasses_traversal"),

    ("globals positive",
     "some_function.__globals__",
     "globals_closure_access"),

    ("closure positive",
     "some_function.__closure__",
     "globals_closure_access"),

    ("builtins restoration positive",
     "reload(__builtins__)",
     "builtins_restoration"),

    ("importlib.reload builtins positive",
     "importlib.reload(__builtins__)",
     "builtins_restoration"),

    ("reload of unrelated module (should NOT match -- not __builtins__)",
     "importlib.reload(some_other_module)",
     None),

    ("frame introspection positive (f_back)",
     "some_generator.gi_frame.f_back",
     "frame_introspection"),

    ("format string attack positive",
     '"{0.__class__.__init__.__globals__}".format(x)',
     "format_string_attribute_access"),

    ("format_map attack positive",
     '"{0.__class__}".format_map(ns)',
     "format_string_attribute_access"),

    ("benign format call (should NOT match -- no dunder in template)",
     '"Hello {0}".format(name)',
     None),

    ("totally benign code (should NOT match anything)",
     "x = 1 + 2\nprint(x)\ny = [i for i in range(10)]",
     None),
]

failures = 0
for label, code, expected in cases:
    findings = analyzer.scan(code)
    techniques_found = [f["technique"] for f in findings]

    if expected is None:
        ok = len(findings) == 0
    else:
        ok = expected in techniques_found

    status = "PASS" if ok else "FAIL"
    if not ok:
        failures += 1
    print(f"[{status}] {label}: findings={techniques_found}")

print(f"\n{len(cases) - failures}/{len(cases)} cases passed.")
if failures:
    raise SystemExit(f"{failures} case(s) FAILED")
print("All detector tests passed.")
