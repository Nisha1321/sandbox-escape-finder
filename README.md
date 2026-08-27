# sandbox_escape_finder

A static analyzer and dynamic prober for evaluating [RestrictedPython](https://github.com/zopefoundation/RestrictedPython)'s
robustness against known Python sandbox-escape techniques.

## Install

```bash
pip install -e .
```

## Usage

```python
from sandbox_escape_finder import StaticAnalyzer, DynamicProber
from sandbox_escape_finder.dynamic.sandbox import sandbox_exec
from sandbox_escape_finder.oracle.canary import oracle
from sandbox_escape_finder.corpus.payloads import PAYLOAD_CORPUS

config = {"timeout_seconds": 5.0, "seed": 42}

analyzer = StaticAnalyzer(config)
findings = analyzer.scan(source_code)

prober = DynamicProber(sandbox_exec, oracle, config, static_scan=analyzer.scan)
report = prober.run(PAYLOAD_CORPUS)
```

See `examples/quickstart.py` for a runnable version of the above.

## Detected techniques

Five escape-technique classes are detected via AST pattern matching (`static/detectors.py`),
each as an independent `Detector` subclass sharing a single tree walk (`static/analyzer.py`).

| Technique | Pattern | Is RestrictedPython's default guard sufficient? |
|---|---|---|
| `subclasses_traversal` | `.__subclasses__` attribute access | **Yes**, against the default guard. `compile_restricted` rejects any attribute *or bare variable name* starting with `_` at compile time -- verified empirically, this payload never reaches runtime. |
| `globals_closure_access` | `.__globals__` / `.__closure__` access | **Yes**, same compile-time underscore rejection applies. |
| `builtins_restoration` | `reload(__builtins__)` calls | **Yes**. `__builtins__` as a bare identifier is rejected at compile time for the same underscore-name reason -- confirmed empirically (error: `"__builtins__" is an invalid variable name because it starts with "_"`). |
| `frame_introspection` | `.gi_frame` / `.f_back` / etc. | **Historically no** (CVE-2023-37271) -- these names do NOT start with an underscore, so the default guard's rule doesn't apply to them at all. Patched in RestrictedPython 5.3/6.1; current version (8.5) blocks it, but via the same compile-time route now applied more broadly. |
| `format_string_attribute_access` | `.format()`/`.format_map()` on a string literal containing `__` | **Historically no** (CVE-2023-41039) -- `.format()` was blocked by name, but `.format_map()` and `string.Formatter` were not. Against current RestrictedPython, this is blocked, but at **runtime**, not compile time -- the dangerous pattern is hidden inside a string literal, invisible to the compile-time AST checks. |

**Known limitation:** the `FormatStringDetector` only inspects string literals written directly in
source. A format string assembled at runtime (concatenation, user input) would not be caught 
the same category of limitation as `chr()`-based character obfuscation, which defeats any
detector relying on literal text matching.

## Oracle design

Three independent signals, combined with OR (any one firing counts as an escape):

1. **Canary file diff** : a fresh, uniquely-named tripwire file is created before each payload
   runs, in a location outside the sandbox's intended reach. Checked from the *parent* process,
   since a real file on disk is genuinely shared between parent and child.
2. **Marker leak** : a secret value is generated per-payload (seeded by `config["seed"]` for
   reproducibility) and handed to the child process via an environment variable. The child
   checks whether that value appears anywhere in its own captured output before it exits, since
   only the child can see its own execution result.
3. **Forbidden module usage** : the child snapshots `sys.modules` before and after running the
   payload and reports any newly touched module from a denylist (`os`, `subprocess`, etc.).

Signals 2 and 3 must be self-reported by the child process, not checked from the parent
afterward `sys.modules` and environment variables are per-process state that doesn't
propagate back across a subprocess boundary.

## Results

Full 12-payload corpus (10 attributed attack payloads + 2 benign controls) run against
RestrictedPython 8.5 with default guards. Per-payload breakdown:

| # | Technique | Static-flagged | Dynamic-escape | Stage |
|---|---|:---:|:---:|---|
| 1 | `subclasses_traversal` | Yes | No | compile |
| 2 | `subclasses_traversal` (variant) | Yes | No | compile |
| 3 | `globals_closure_access` | Yes | No | compile |
| 4 | `globals_closure_access` (closure variant) | Yes | No | compile |
| 5 | `builtins_restoration` | Yes | No | compile |
| 6 | `frame_introspection` | Yes | No | compile |
| 7 | `frame_introspection` (variant) | Yes | No | compile |
| 8 | `format_string_attribute_access` | Yes | No | exec |
| 9 | `format_string_attribute_access` (format_map variant) | Yes | No | exec |
| 10 | `subclasses_traversal` + `globals_closure_access` (combined chain) | Yes | No | compile |
| 11 | none (benign control) | No | No | success |
| 12 | none (benign control, variant) | No | No | success |

Aggregate summary:

| Category | Count |
|---|---|
| True positives (flagged AND escaped) | 0 |
| True negatives (not flagged, safe) | 2 |
| False positives (flagged, but blocked) | 10 |
| False negatives (escaped, missed) | 0 |

**Interpretation:** every attack payload in the corpus was correctly identified as suspicious by
the static analyzer, and every single one was successfully blocked by RestrictedPython's current
default guard configuration, 8 rejected at compile time, 2 rejected at runtime. Zero false
negatives means the static analyzer never missed a payload that actually succeeded (because
nothing succeeded); the 10 false positives are, in this context, a *good* result  they
represent genuinely dangerous patterns that the static analyzer correctly flagged as suspicious,
even though the sandbox itself held.

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

17 tests: 11 detector unit tests (positive + negative cases per technique), 3 oracle-correctness
tests (including an intentionally-broken toy sandbox that always leaks, and a genuinely safe toy
sandbox that never does, proving the oracle mechanism itself is correct, independent of whether
RestrictedPython is secure), and 3 end-to-end tests against the real sandbox (including a
reproducibility test confirming identical seeds produce identical results).
