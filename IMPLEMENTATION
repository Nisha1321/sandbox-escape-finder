# Implementation Notes - SandboxEscapeFinder (Task 6)

This document explains how I approached this task: how I read and understood the requirements, the background research I did before writing any code, the design choices I considered and why I picked the ones I did, the problems I ran into and how I fixed them, and what the final results mean.

## 1. Starting point

Before writing anything I read the repository's general README (the shared instructions for all seven tasks) and the task-specific file in full. Two things stuck with me and shaped everything after:

- **"You must fully understand every line of code you submit."** I couldn't just accept AI-generated code and move on. Every design decision needed a reason I could actually say out loud, not just code that ran.
- **The definition of done was specific and checkable.** Real execution against the actual sandbox, a public API matching what was asked for, a clean `pip install`, a runnable README example, real tests, config-driven behavior, and being able to explain every choice.

I also noticed the difficulty rating didn't match between two places: the task's own file said 3/5, but the repository's README index said 5/5.

### 1.1 Why I picked this task

There were seven tasks in the repository. I picked this one for two reasons:

- **Hardware.** A few of the other tasks need a real GPU to run a 7B-parameter model locally, either for gradient-based attacks or for serving a model through vLLM. My laptop has an integrated Intel graphics chip and a 4GB GTX 1650, nowhere near enough for that. This task needed no GPU at all, just static code analysis and subprocess-based testing, so I could build and run all of it on my own machine.
- **It's close to what I already know.** I have backend experience with a production messaging platform on Spring Boot, Kafka, and Kubernetes, and I'd already built an in-browser code execution feature for an interview-prep app, wiring the Monaco editor to the Judge0 execution API. That meant I'd already had to think about running code I don't trust safely. This task is the same problem from the research side instead of the product side: how do you know your safety boundary actually held. It let me use skills I already had, program analysis, process isolation, test design, rather than starting from an ML research background I don't have.

## 2. Background research

### 2.1 Reading RestrictedPython's own docs

I read RestrictedPython's documentation closely, looking for what it says it protects against and what it doesn't, since the task asked for that directly. The most important thing I found: RestrictedPython works in two separate layers, not one.

| Layer | When it runs | What it does |
|---|---|---|
| Compile-time | Before any code executes | `compile_restricted` walks the parsed code and rejects any syntax it doesn't recognize as safe, before bytecode is even produced. |
| Runtime | While the code executes | The compiled code calls placeholder functions like `_getattr_` whenever it does something that needs guarding. RestrictedPython does not supply real versions of these itself, the embedding app has to wire them up. |

There's a default guard provided as a convenience (`safer_getattr`) that blocks attribute names starting with an underscore and blocks calling `.format()` by name, but using it is a choice, not something automatic. This distinction mattered a lot later, especially when explaining whether the default guard was actually enough against each technique.

### 2.2 The escape technique catalogs

I read both catalogs the task pointed to:

- **Moshe Kaplan's writeup** covers the classic family: walking up to `__subclasses__` to list every class loaded in the program, reading a function's `__globals__` or `__closure__` to get at hidden state, and restoring deleted builtins with `reload(__builtins__)`.
- **pyjailbreaker** is more advanced. It gave me a full working combined attack, the `os._wrap_close` chain, which strings `__subclasses__` traversal and `__globals__` access together to reach a real shell. It also showed me character-code obfuscation (spelling out dangerous words using `chr()` calls instead of literal text) as a real way to dodge any detector that only looks for literal strings.

I also went looking for RestrictedPython's own official security advisories and found two real CVEs, which gave me the remaining two techniques the task asked for by name rather than folklore from a blog post:

| CVE | Technique | What it does | Why it worked |
|---|---|---|---|
| CVE-2023-37271 | Generator/frame introspection | `.gi_frame.f_back` climbs back up the real call stack past the sandbox boundary | These attribute names don't start with an underscore, so the default guard's rule never applied to them |
| CVE-2023-41039 | Format-string attribute access | `.format()`/`.format_map()` reading a template string can walk a dunder chain hidden inside it | The default guard blocks `.format()` by name specifically, but not its near-identical sibling `.format_map()`, or `string.Formatter` |

Both are patched in current RestrictedPython versions.

I found two more things along the way that I decided **not** to build detectors for, and wrote down why rather than pretending I never saw them:

- **`try/except*` type confusion (CVE-2025-22153)** - a real CPython interpreter bug rather than a code pattern, so there's nothing for a static analyzer to actually look for.
- **`AttributeError.obj` information leak** - real, but narrower than a full escape.

## 3. Understanding the requirements

Before designing anything I went through the task line by line and matched it against what my public API needed to return. One requirement shaped the whole architecture: the report returned by `DynamicProber.run()` has to include a static analyzer verdict on every row. That meant the dynamic side needed some way to reach the static side's results, even though I wanted to keep the two independent and swappable.

## 4. Design choices I considered

I didn't go with the first idea for either half of the system. I laid out real alternatives, checked them against the requirements and acceptance criteria, and picked with reasons.

### 4.1 Static analyzer

| Option | Approach | Verdict |
|---|---|---|
| Regex on raw text | Search source text for substrings | Ruled out immediately. Task asks for AST-based analysis, and regex can't report a real AST node or survive obfuscation like `getattr(x, '__subclasses__')`. |
| One big function, `isinstance` chain | Single loop with a long if/elif chain | Works, but turns into an unmaintainable block as techniques get added, and hard to test one technique in isolation. |
| **One Detector class per technique** (chosen) | Small classes sharing a single tree walk | Satisfies AST-based requirement, each detector is independently testable, adding a 6th technique means adding one class, not editing a shared function. |
| Dataflow/taint tracking | Follow a variable across assignments | More powerful (catches a technique split across lines), but real static-analysis research territory. Risk of getting it subtly wrong on a 3/5 task. Documented as a known limitation instead. |

### 4.2 Dynamic prober isolation

| Option | Approach | Verdict |
|---|---|---|
| In-process `exec()` | Run payloads in my own process | Ruled out immediately. Task is explicit that a genuine escape must not touch the host machine. |
| **`subprocess.run()`, fresh process per payload** (chosen) | One OS process per payload, with a timeout | This is the exact mechanism the task itself describes. Needs nothing beyond the standard library, no dependency the grader might not have. |
| `multiprocessing.Process` | Similar isolation via multiprocessing | Isolation strength depends on the start method. On Linux, the default (`fork`) shares more of the parent's state than I wanted. |
| Docker per payload | Full container isolation | Strongest isolation, but adds a hard dependency the grader would need installed just to run the quickstart. Slower too. |

I checked all six combinations of the static and dynamic choices against every line of the requirements before committing. The combination I picked was the only one with no conditional or risky cells anywhere in that comparison.

## 5. Build order

Since `DynamicProber` takes `sandbox_exec` and `oracle` as constructor arguments, I built things in dependency order rather than the order they appear in the API:

1. The oracle, since it doesn't depend on anything else.
2. The actual RestrictedPython wrapper and the subprocess harness that runs inside an isolated child process.
3. The five static detectors, then the analyzer that runs them together.
4. The prober itself, which ties the oracle and sandbox execution together, with an optional `static_scan` function passed in so it could produce the required per-row static verdict without importing `StaticAnalyzer` directly.
5. The payload corpus, config, the test suite, and the README.

## 6. Problems I ran into and how I fixed them

A few real bugs came up while building this. I want to be upfront about them rather than only show a clean result.

| Problem | What happened | How I caught it | Fix |
|---|---|---|---|
| Missing `_getattr_` wiring | RestrictedPython's compiled code calls `_getattr_(x, 'attr')` instead of `x.attr` directly. Without it, the call fails with a plain `NameError` that looks like a rejection but isn't the guard actually doing its job. | Read the docs closely on how `compile_restricted` transforms attribute access. | Explicitly wired up the real `safer_getattr` function so I was testing genuine guard behavior. |
| Payload referencing an undefined name | My first `__globals__` payload was `harmless_function.__globals__`, but nothing in the sandbox defines that name. It would fail with `NameError` for the wrong reason, a broken test, not a security block. | Reread the payload critically before running it. | Rewrote it as a self-contained lambda that doesn't depend on anything external. |
| Missing `_getiter_` guard | A benign control payload (a list comprehension) came back as "blocked," which shouldn't happen for harmless code. | Investigated instead of assuming the result was real. The actual error was `NameError: name '_getiter_' is not defined`. | RestrictedPython guards iteration the same way it guards attribute access, through a separate hook. Added `default_guarded_getiter` from `RestrictedPython.Eval`, then reran everything to confirm nothing else changed. |
| Reproducibility vs. randomness | Marker values were generated with `secrets.token_hex()`, cryptographically random on purpose, which conflicted with the requirement that the same seed produce the same report every time. | Read the requirements again and noticed the conflict directly. | Switched to a `random.Random` instance seeded from config's seed value. Safe here because the payloads are fixed, non-adaptive strings, nothing in a payload can react to or predict the marker while running. |

One more thing worth noting, not a bug but a real surprise: I assumed from the docs that underscore-name blocking was purely a runtime thing, handled by `_getattr_`. Running real payloads against the real library showed otherwise. `compile_restricted` rejects both underscore-prefixed attribute names *and* plain underscore-prefixed variable names at compile time, before anything runs. That's stronger than what the docs' prose implied, and I only caught it by actually running the code instead of trusting my first read of the documentation.

## 7. Final results

Full corpus run: 10 attributed attack payloads across all five techniques, plus 2 benign controls, against RestrictedPython 8.5 with its default guard.

| Category | Count |
|---|---|
| True positives (flagged and escaped) | 0 |
| True negatives (not flagged, safe) | 2 |
| False positives (flagged, but blocked) | 10 |
| False negatives (escaped, missed) | 0 |

Every attack payload was correctly flagged as suspicious by my static analyzer, and every one was actually blocked by the sandbox: 8 rejected at compile time, 2 at runtime. I don't think this is a weak result. Zero false negatives means my analyzer never missed something that actually got through, since nothing did. The 10 false positives are, in this context, a good sign: they're genuinely dangerous patterns that got flagged correctly, even though the sandbox itself held up against all of them.

The full per-payload table, technique writeups, and oracle design are in the README.
