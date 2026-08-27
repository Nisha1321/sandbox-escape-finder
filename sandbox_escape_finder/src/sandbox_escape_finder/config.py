
from __future__ import annotations

DEFAULT_CONFIG = {
    # Static side: which of the 5 detectors run. Default: all of them.
    "enabled_techniques": [
        "subclasses_traversal",
        "globals_closure_access",
        "builtins_restoration",
        "frame_introspection",
        "format_string_attribute_access",
    ],
    # Static side: findings below this confidence are dropped from
    # results. Default 0.0 means "show everything" -- our lowest
    # detector confidence is 0.75, so nothing is filtered by default.
    "confidence_threshold": 0.0,
    # Dynamic side: how long sandbox_exec waits before killing a
    # payload's subprocess.
    "timeout_seconds": 5.0,
    # Dynamic side: seeds marker-value generation so a run with the same
    # seed and same corpus produces the same report every time.
    "seed": 42,
}


def validate_config(config: dict) -> dict:

    unknown_keys = set(config.keys()) - set(DEFAULT_CONFIG.keys())
    if unknown_keys:
        raise ValueError(f"Unknown config key(s): {sorted(unknown_keys)}")
    merged = dict(DEFAULT_CONFIG)
    merged.update(config)
    return merged
