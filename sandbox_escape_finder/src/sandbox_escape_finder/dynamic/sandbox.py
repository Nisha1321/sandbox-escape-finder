
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

_HARNESS_PATH = Path(__file__).parent / "_harness.py"


def sandbox_exec(code: str, marker_value: str, timeout: float = 5.0) -> dict:
    # Write the payload to a real temp file rather than passing it as a
    # command-line string: payload code can contain quotes, newlines, and
    # special shell characters that would be unsafe or simply broken to
    # pass directly as a CLI argument.
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False
    ) as f:
        f.write(code)
        payload_path = f.name

    # The child gets a COPY of our environment plus one extra variable.
    # Setting it here, in the parent, and reading it in _harness.py is
    # the only way to hand the marker value to the child -- we can't just
    # pass a Python object across a process boundary directly.
    child_env = dict(os.environ)
    child_env["SEF_MARKER_VALUE"] = marker_value

    try:
        proc = subprocess.run(
            [sys.executable, str(_HARNESS_PATH), payload_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=child_env,
        )
    except subprocess.TimeoutExpired:
        # A malicious or buggy payload could infinite-loop. This is
        # exactly what the timeout is for: the child gets killed, and we
        # report a clean "timeout" result instead of hanging forever.
        os.remove(payload_path)
        return {
            "success": False,
            "error": "execution timed out",
            "stage": "timeout",
            "marker_leaked": False,
            "forbidden_modules_touched": [],
        }
    finally:
        if os.path.exists(payload_path):
            os.remove(payload_path)

    if not proc.stdout.strip():
        # The child crashed before it managed to print its JSON result
        # line at all (e.g. an uncaught error in the harness itself,
        # not in the payload). stderr has the real Python traceback.
        return {
            "success": False,
            "error": (proc.stderr or "")[-500:],
            "stage": "harness_crash",
            "marker_leaked": False,
            "forbidden_modules_touched": [],
        }

    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {
            "success": False,
            "error": "could not parse harness output: " + proc.stdout[-500:],
            "stage": "parse_error",
            "marker_leaked": False,
            "forbidden_modules_touched": [],
        }
