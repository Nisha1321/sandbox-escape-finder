
from sandbox_escape_finder import StaticAnalyzer, DynamicProber
from sandbox_escape_finder.dynamic.sandbox import sandbox_exec
from sandbox_escape_finder.oracle.canary import oracle
from sandbox_escape_finder.corpus.payloads import PAYLOAD_CORPUS

config = {"timeout_seconds": 5.0, "seed": 42}

analyzer = StaticAnalyzer(config)
prober = DynamicProber(sandbox_exec, oracle, config, static_scan=analyzer.scan)

print("=== Static findings (per payload) ===")
for payload in PAYLOAD_CORPUS:
    findings = analyzer.scan(payload["code"])
    print(f"{payload['technique']}: {len(findings)} finding(s)")

print("\n=== Dynamic report ===")
report = prober.run(PAYLOAD_CORPUS)
for row in report:
    print(f"{row['technique']:<45} flagged={row['static_flagged']} "
          f"escaped={row['escaped']} stage={row['stage']}")
