import sys
sys.path.insert(0, "src")

from sandbox_escape_finder.dynamic.sandbox import sandbox_exec

def show(label, code, marker="TESTMARKER123"):
    print(f"\n--- {label} ---")
    print(f"code: {code!r}")
    result = sandbox_exec(code, marker_value=marker, timeout=5.0)
    for k, v in result.items():
        print(f"  {k}: {v}")
    return result

# Test 1: totally benign payload -- should succeed normally
r1 = show("benign payload", "1 + 2")
assert r1["success"] is True, "benign payload should succeed"
assert r1["result_repr"] == "3"

# Test 2: the classic subclasses-traversal escape attempt
r2 = show("subclasses traversal attack", "().__class__.__bases__[0].__subclasses__()")

# Test 3: raw import statement -- should be rejected at COMPILE time
r3 = show("raw import os", "import os\nos.system('echo pwned')")
assert r3["stage"] == "compile", f"expected compile-time rejection, got {r3['stage']}"

print("\nAll structural assertions passed.")
