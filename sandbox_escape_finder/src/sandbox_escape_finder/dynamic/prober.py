
from __future__ import annotations

import os
import random
import time
from typing import Callable, Iterable, Optional

from ..oracle.canary import new_canary_path, capture_pre_state, capture_post_state
from ..config import validate_config


class DynamicProber:
    def __init__(
        self,
        sandbox_exec: Callable[..., dict],
        oracle: Callable[[dict, dict, dict], bool],
        config: dict | None = None,
        static_scan: Optional[Callable[[str], list[dict]]] = None,
    ):
        self.sandbox_exec = sandbox_exec
        self.oracle = oracle
        self.config = validate_config(config or {})
        self.static_scan = static_scan

    def run(self, payload_corpus: Iterable[dict]) -> list[dict]:
        timeout = self.config["timeout_seconds"]
        # Seeded, not secrets.token_hex(): the same seed + same corpus
        # must produce the same report every time (Req 6, reproducible
        # via seed). This is safe here because our payloads are fixed,
        # non-adaptive strings from a static corpus -- nothing in a
        # payload could ever "predict" or react to the marker value
        # during its own execution, so a seeded (rather than
        # cryptographically unpredictable) marker doesn't weaken the
        # oracle's reliability for this use case.
        rng = random.Random(self.config["seed"])
        report = []

        for payload_entry in payload_corpus:
            code = payload_entry["code"]
            technique = payload_entry.get("technique", "unknown")

            try:
                # -- static verdict, only if a scanner was wired up --
                static_flagged = False
                if self.static_scan is not None:
                    static_findings = self.static_scan(code)
                    static_flagged = len(static_findings) > 0

                # -- fresh tripwire + secret marker, unique to THIS payload --
                canary_path = new_canary_path()
                marker_value = f"{rng.getrandbits(64):016x}"

                pre_state = capture_pre_state(canary_path, marker_value)

                start = time.perf_counter()
                exec_result = self.sandbox_exec(code, marker_value, timeout)
                elapsed_seconds = time.perf_counter() - start

                post_state = capture_post_state(canary_path)
                escaped = self.oracle(pre_state, exec_result, post_state)

                if os.path.exists(canary_path):
                    os.remove(canary_path)

                report.append({
                    "code": code,
                    "technique": technique,
                    "static_flagged": static_flagged,
                    "executed": exec_result.get("success", False),
                    "escaped": escaped,
                    "stage": exec_result.get("stage"),
                    "timing_seconds": round(elapsed_seconds, 4),
                })

            except Exception as e:
                # A bug in OUR harness/prober for one payload should never
                # kill the whole corpus run -- report it distinctly and
                # keep going.
                report.append({
                    "code": code,
                    "technique": technique,
                    "static_flagged": None,
                    "executed": False,
                    "escaped": False,
                    "stage": "prober_error",
                    "error": f"{type(e).__name__}: {e}",
                    "timing_seconds": None,
                })

        return report


def summarize_fp_fn(report: list[dict]) -> dict:

    false_positives = [
        row for row in report
        if row.get("static_flagged") is True and row.get("escaped") is False
    ]
    false_negatives = [
        row for row in report
        if row.get("static_flagged") is False and row.get("escaped") is True
    ]
    true_positives = [
        row for row in report
        if row.get("static_flagged") is True and row.get("escaped") is True
    ]
    true_negatives = [
        row for row in report
        if row.get("static_flagged") is False and row.get("escaped") is False
    ]

    return {
        "total": len(report),
        "false_positive_count": len(false_positives),
        "false_negative_count": len(false_negatives),
        "true_positive_count": len(true_positives),
        "true_negative_count": len(true_negatives),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }
