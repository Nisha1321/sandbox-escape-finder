import ast
import sys
sys.path.insert(0, "src")

from sandbox_escape_finder.static.detectors import SubclassesTraversalDetector

detector = SubclassesTraversalDetector()

# Positive example: the classic subclasses-traversal chain from earlier.
positive_snippet = "().__class__.__bases__[0].__subclasses__()"

# Negative example: totally unrelated, harmless code.
negative_snippet = "x = 1 + 2\nprint(x)\ny = [i for i in range(10)]"

def run(label, source):
    print(f"\n--- {label} ---")
    print(f"source: {source!r}")
    tree = ast.parse(source)
    findings = []
    for node in ast.walk(tree):
        finding = detector.matches(node)
        if finding is not None:
            findings.append(finding)
    if findings:
        for f in findings:
            print(f"  FOUND: technique={f.technique} line={f.lineno} "
                  f"col={f.col_offset} confidence={f.confidence}")
    else:
        print("  no findings")
    return findings

pos_findings = run("positive (should find 1)", positive_snippet)
neg_findings = run("negative (should find 0)", negative_snippet)

assert len(pos_findings) == 1, f"expected 1 finding, got {len(pos_findings)}"
assert len(neg_findings) == 0, f"expected 0 findings, got {len(neg_findings)}"
print("\nAll assertions passed.")
