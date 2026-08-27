
from __future__ import annotations

import os
import tempfile
import uuid


def new_canary_path() -> str:

    canary_dir = tempfile.gettempdir()
    filename = f"sandbox_canary_{uuid.uuid4().hex}.txt"
    path = os.path.join(canary_dir, filename)
    with open(path, "w") as f:
        f.write("untouched")
    return path


def read_canary(path: str) -> str | None:

    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return f.read()


def capture_pre_state(canary_path: str, marker_value: str) -> dict:

    return {
        "canary_contents": read_canary(canary_path),
        "marker_value": marker_value,
    }


def capture_post_state(canary_path: str) -> dict:

    return {
        "canary_contents": read_canary(canary_path),
    }


def oracle(pre_state: dict, exec_result: dict, post_state: dict) -> bool:
    # Signal 1: canary file — checked here, in the parent, because the
    # file is genuinely shared between parent and child.
    canary_tripped = pre_state["canary_contents"] != post_state["canary_contents"]

    # Signal 2 & 3: these were only observable INSIDE the child process,
    # so sandbox.py must have already computed them and put them in
    # exec_result before the child exited. We just read what it reported.
    marker_leaked = exec_result.get("marker_leaked", False)
    forbidden_modules_touched = bool(exec_result.get("forbidden_modules_touched"))

    return canary_tripped or marker_leaked or forbidden_modules_touched
