"""End-to-end test: the full seeded corpus against the REAL, unmodified
RestrictedPython sandbox -- per the acceptance criteria ("the dynamic
prober runs the full corpus against RestrictedPython safely... the
report distinguishes statically-flagged vs. actually-escaping payloads").
"""
import sys
sys.path.insert(0, "src")

from sandbox_escape_finder.static.analyzer import StaticAnalyzer
from sandbox_escape_finder.dynamic.prober import DynamicProber, summarize_fp_fn
from sandbox_escape_finder.dynamic.sandbox import sandbox_exec
from sandbox_escape_finder.oracle.canary import oracle
from sandbox_escape_finder.corpus.payloads import PAYLOAD_CORPUS


def test_full_corpus_end_to_end():
    analyzer = StaticAnalyzer()
    prober = DynamicProber(
        sandbox_exec=sandbox_exec,
        oracle=oracle,
        config={"timeout_seconds": 5.0, "seed": 42},
        static_scan=analyzer.scan,
    )

    report = prober.run(PAYLOAD_CORPUS)

    # Every payload produced a report row.
    assert len(report) == len(PAYLOAD_CORPUS)

    # Every row has the exact shape the spec requires.
    for row in report:
        assert "static_flagged" in row
        assert "executed" in row
        assert "escaped" in row
        assert "timing_seconds" in row

    # Attack payloads should be statically flagged; benign ones should not.
    for row in report:
        if row["technique"].startswith("none"):
            assert row["static_flagged"] is False
            assert row["executed"] is True
        else:
            assert row["static_flagged"] is True

    # No payload in our current corpus should crash our OWN tooling.
    assert all(row["stage"] != "prober_error" for row in report)
    assert all(row["stage"] != "harness_crash" for row in report)


def test_fp_fn_summary_matches_report():
    analyzer = StaticAnalyzer()
    prober = DynamicProber(
        sandbox_exec=sandbox_exec,
        oracle=oracle,
        config={"timeout_seconds": 5.0, "seed": 42},
        static_scan=analyzer.scan,
    )
    report = prober.run(PAYLOAD_CORPUS)
    summary = summarize_fp_fn(report)

    assert summary["total"] == len(report)
    counted = (
        summary["true_positive_count"] + summary["true_negative_count"]
        + summary["false_positive_count"] + summary["false_negative_count"]
    )
    assert counted == len(report), "every row must fall into exactly one category"


def test_reproducible_via_seed():
    """Same seed + same corpus must produce the same marker values and
    therefore the same escaped/not-escaped verdicts every run (Req 6)."""
    analyzer = StaticAnalyzer()

    def make_prober():
        return DynamicProber(
            sandbox_exec=sandbox_exec,
            oracle=oracle,
            config={"timeout_seconds": 5.0, "seed": 123},
            static_scan=analyzer.scan,
        )

    report_a = make_prober().run(PAYLOAD_CORPUS)
    report_b = make_prober().run(PAYLOAD_CORPUS)

    escaped_a = [row["escaped"] for row in report_a]
    escaped_b = [row["escaped"] for row in report_b]
    assert escaped_a == escaped_b, "same seed must produce the same escape verdicts"
