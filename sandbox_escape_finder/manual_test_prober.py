import sys
sys.path.insert(0, "src")

from sandbox_escape_finder.static.analyzer import StaticAnalyzer
from sandbox_escape_finder.dynamic.prober import DynamicProber
from sandbox_escape_finder.dynamic.sandbox import sandbox_exec
from sandbox_escape_finder.oracle.canary import oracle

analyzer = StaticAnalyzer()
prober = DynamicProber(
    sandbox_exec=sandbox_exec,
    oracle=oracle,
    config={"timeout_seconds": 5.0},
    static_scan=analyzer.scan,
)

corpus = [
    {"code": "1 + 2", "technique": "none (benign control)"},
    {"code": "().__class__.__bases__[0].__subclasses__()", "technique": "subclasses_traversal"},
    {"code": "reload(__builtins__)", "technique": "builtins_restoration"},
    {"code": '"{0.__class__.__init__.__globals__}".format(object())', "technique": "format_string_attribute_access"},
]

report = prober.run(corpus)

print(f"{'technique':<38} {'static_flagged':<15} {'executed':<10} {'escaped':<9} {'stage':<12} time")
for row in report:
    print(f"{row['technique']:<38} {str(row['static_flagged']):<15} "
          f"{str(row['executed']):<10} {str(row['escaped']):<9} "
          f"{str(row['stage']):<12} {row['timing_seconds']}")

# Structural assertions
assert len(report) == 4
assert report[0]["static_flagged"] is False, "benign code should not be statically flagged"
assert report[0]["executed"] is True, "benign code should execute successfully"
assert report[1]["static_flagged"] is True, "subclasses payload SHOULD be statically flagged"
print("\nStructural assertions passed.")
