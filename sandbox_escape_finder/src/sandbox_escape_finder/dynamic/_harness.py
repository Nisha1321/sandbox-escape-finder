
from __future__ import annotations

import json
import os
import sys

from RestrictedPython import compile_restricted, safe_globals
from RestrictedPython.Guards import safe_builtins, safer_getattr
from RestrictedPython.PrintCollector import PrintCollector
from RestrictedPython.Eval import default_guarded_getiter

# Modules the sandbox is specifically supposed to prevent reaching.
# This is checked by diffing sys.modules before/after -- see below.
FORBIDDEN_MODULES = {"os", "subprocess", "sys", "importlib", "socket", "shutil"}


def build_restricted_globals() -> dict:

    g = dict(safe_globals)  # {'__builtins__': safe_builtins}
    g["_getattr_"] = safer_getattr
    g["_print_"] = PrintCollector
    g["_getiter_"] = default_guarded_getiter
    return g


def run() -> dict:
    payload_path = sys.argv[1]
    with open(payload_path, "r") as f:
        payload_code = f.read()

    marker_value = os.environ.get("SEF_MARKER_VALUE", "")

    # Snapshot BEFORE running anything -- this is only meaningful because
    # we're checking it inside the same process that's about to run the
    # payload.
    modules_before = set(sys.modules.keys())

    # Wrap the payload so we can retrieve its value afterward. exec()
    # itself never returns a value (unlike eval()), so we turn the
    # payload into an assignment and read `result` back out of the
    # globals dict once execution finishes.
    wrapped_source = f"result = (\n{payload_code}\n)"

    restricted_globals = build_restricted_globals()
    output = {
        "success": False,
        "result_repr": None,
        "error": None,
        "stage": None,  # "compile" | "exec" | "success"
    }

    try:
        byte_code = compile_restricted(wrapped_source, "<payload>", "exec")
    except SyntaxError as e:
        # The AST/compile-time layer rejected it outright -- this payload
        # never even got a chance to run.
        output["error"] = str(e)
        output["stage"] = "compile"
        modules_after = set(sys.modules.keys())
        output["forbidden_modules_touched"] = sorted(
            (modules_after - modules_before) & FORBIDDEN_MODULES
        )
        output["marker_leaked"] = marker_value in str(e) if marker_value else False
        print(json.dumps(output))
        return output

    try:
        exec(byte_code, restricted_globals)
        output["success"] = True
        output["stage"] = "success"
        output["result_repr"] = repr(restricted_globals.get("result"))
    except Exception as e:
        # The RUNTIME guard layer rejected it (e.g. safer_getattr raised
        # on an underscore-prefixed attribute name).
        output["error"] = f"{type(e).__name__}: {e}"
        output["stage"] = "exec"

    # Snapshot AFTER -- still inside this same child process.
    modules_after = set(sys.modules.keys())
    newly_touched = modules_after - modules_before
    output["forbidden_modules_touched"] = sorted(newly_touched & FORBIDDEN_MODULES)

    # Did the secret marker value show up anywhere in what we captured?
    haystack = str(output.get("result_repr", "")) + str(output.get("error", ""))
    output["marker_leaked"] = bool(marker_value) and marker_value in haystack

    print(json.dumps(output))
    return output


if __name__ == "__main__":
    run()
