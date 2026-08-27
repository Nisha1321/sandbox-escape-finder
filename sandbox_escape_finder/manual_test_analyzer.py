import sys
sys.path.insert(0, "src")

from sandbox_escape_finder.static.analyzer import StaticAnalyzer

analyzer = StaticAnalyzer()

positive = "().__class__.__bases__[0].__subclasses__()"
negative = "x = 1 + 2\nprint(x)\ny = [i for i in range(10)]"

print("--- positive ---")
findings = analyzer.scan(positive)
for f in findings:
    print(f)
assert len(findings) == 1
assert findings[0]["technique"] == "subclasses_traversal"

print("\n--- negative ---")
findings = analyzer.scan(negative)
print(findings)
assert len(findings) == 0

print("\nAnalyzer orchestration test passed.")
