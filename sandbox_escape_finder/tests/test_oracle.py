
import sys
sys.path.insert(0, "src")

from sandbox_escape_finder.oracle.canary import (
    new_canary_path, capture_pre_state, capture_post_state, oracle
)
import os


def broken_sandbox_exec(code: str, marker_value: str, timeout: float = 5.0) -> dict:

    return {
        "success": True,
        "result_repr": f"leaked: {marker_value}",
        "marker_leaked": True,
        "forbidden_modules_touched": [],
    }


def perfectly_safe_sandbox_exec(code: str, marker_value: str, timeout: float = 5.0) -> dict:

    return {
        "success": True,
        "result_repr": "42",
        "marker_leaked": False,
        "forbidden_modules_touched": [],
    }


def test_oracle_catches_broken_sandbox():
    canary_path = new_canary_path()
    marker_value = "secret-marker-abc123"
    pre_state = capture_pre_state(canary_path, marker_value)

    exec_result = broken_sandbox_exec("irrelevant code", marker_value)

    post_state = capture_post_state(canary_path)
    escaped = oracle(pre_state, exec_result, post_state)
    os.remove(canary_path)

    assert escaped is True, "oracle MUST catch a sandbox that leaks the marker"


def test_oracle_stays_quiet_for_safe_sandbox():
    canary_path = new_canary_path()
    marker_value = "secret-marker-xyz789"
    pre_state = capture_pre_state(canary_path, marker_value)

    exec_result = perfectly_safe_sandbox_exec("irrelevant code", marker_value)

    post_state = capture_post_state(canary_path)
    escaped = oracle(pre_state, exec_result, post_state)
    os.remove(canary_path)

    assert escaped is False, "oracle must NOT false-alarm on a genuinely safe run"


def test_oracle_catches_canary_file_tampering():

    canary_path = new_canary_path()
    marker_value = "unrelated-marker"
    pre_state = capture_pre_state(canary_path, marker_value)

    # Simulate an escape that writes to the canary file, bypassing
    # whatever the (broken) sandbox chooses to self-report.
    with open(canary_path, "w") as f:
        f.write("TAMPERED")
    exec_result = {"success": True, "result_repr": None,
                    "marker_leaked": False, "forbidden_modules_touched": []}

    post_state = capture_post_state(canary_path)
    escaped = oracle(pre_state, exec_result, post_state)
    os.remove(canary_path)

    assert escaped is True, "oracle MUST catch canary file tampering even with no self-reported leak"
