import sys
sys.path.insert(0, "src")

from sandbox_escape_finder.oracle.canary import (
    new_canary_path, capture_pre_state, capture_post_state, oracle, read_canary
)
import os

def test_no_escape():
    path = new_canary_path()
    pre = capture_pre_state(path, marker_value="secret123")
    # simulate a payload that did nothing at all
    exec_result = {"return_value": 4, "marker_leaked": False, "forbidden_modules_touched": []}
    post = capture_post_state(path)
    result = oracle(pre, exec_result, post)
    os.remove(path)
    assert result is False, "expected no escape detected"
    print("test_no_escape: PASS")

def test_canary_file_modified():
    path = new_canary_path()
    pre = capture_pre_state(path, marker_value="secret123")
    # simulate the payload's subprocess writing to the canary file directly
    # (this is what a REAL escape would do -- we're faking it here to
    # test the oracle logic in isolation, before the real sandbox exists)
    with open(path, "w") as f:
        f.write("PWNED")
    exec_result = {"return_value": None, "marker_leaked": False, "forbidden_modules_touched": []}
    post = capture_post_state(path)
    result = oracle(pre, exec_result, post)
    os.remove(path)
    assert result is True, "expected escape detected via canary file"
    print("test_canary_file_modified: PASS")

def test_marker_leaked():
    path = new_canary_path()
    pre = capture_pre_state(path, marker_value="secret123")
    # simulate sandbox.py reporting that the marker value showed up in
    # the payload's own return value / output
    exec_result = {"return_value": "secret123", "marker_leaked": True, "forbidden_modules_touched": []}
    post = capture_post_state(path)
    result = oracle(pre, exec_result, post)
    os.remove(path)
    assert result is True, "expected escape detected via marker leak"
    print("test_marker_leaked: PASS")

def test_forbidden_module_touched():
    path = new_canary_path()
    pre = capture_pre_state(path, marker_value="secret123")
    exec_result = {"return_value": None, "marker_leaked": False, "forbidden_modules_touched": ["os"]}
    post = capture_post_state(path)
    result = oracle(pre, exec_result, post)
    os.remove(path)
    assert result is True, "expected escape detected via forbidden module"
    print("test_forbidden_module_touched: PASS")

test_no_escape()
test_canary_file_modified()
test_marker_leaked()
test_forbidden_module_touched()
print("\nAll oracle tests passed.")
