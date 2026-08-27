import sys
sys.path.insert(0, "src")

from sandbox_escape_finder.static.analyzer import StaticAnalyzer
from sandbox_escape_finder.dynamic.prober import DynamicProber, summarize_fp_fn
from sandbox_escape_finder.dynamic.sandbox import sandbox_exec
from sandbox_escape_finder.oracle.canary import oracle
from sandbox_escape_finder.corpus.payloads import PAYLOAD_CORPUS

analyzer = StaticAnalyzer()
prober = DynamicProber(
    sandbox_exec=sandbox_exec,
    oracle=oracle,
    config={"timeout_seconds": 5.0},
    static_scan=analyzer.scan,
)

report = prober.run(PAYLOAD_CORPUS)

print(f"{'technique':<45} {'flagged':<8} {'exec':<6} {'escaped':<8} {'stage':<12} time")
for row in report:
    print(f"{row['technique']:<45} {str(row['static_flagged']):<8} "
          f"{str(row['executed']):<6} {str(row['escaped']):<8} "
          f"{str(row['stage']):<12} {row['timing_seconds']}")

summary = summarize_fp_fn(report)
print(f"\n=== FP/FN Summary ===")
print(f"Total payloads: {summary['total']}")
print(f"True positives (flagged AND escaped):  {summary['true_positive_count']}")
print(f"True negatives (not flagged, safe):     {summary['true_negative_count']}")
print(f"False positives (flagged, but safe):    {summary['false_positive_count']}")
print(f"False negatives (escaped, not flagged): {summary['false_negative_count']}")

if summary["false_negatives"]:
    print("\n!! FALSE NEGATIVES (these actually escaped and we MISSED them) !!")
    for row in summary["false_negatives"]:
        print(f"  {row['technique']}: {row['code']!r}")
