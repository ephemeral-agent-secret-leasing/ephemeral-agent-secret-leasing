# What we measured

Generated from `results/20260926T060714Z-reference`, `results/benchmark-test/summary.json`, and Zero Trust Agent Benchmark `zero-trust-agent-benchmark-dataset-v4` (`test.jsonl` SHA-256 `4f6fff41fe77aefb2ec96336b65a58d571986e0036ac3e368cc9975ed029dfc7`).

| ID | Metric | Threshold | Result | Verdict |
|---|---|---:|---:|---|
| H1 | Lease issue p95 | ≤ 12 ms | 0.434 ms | PASS |
| H2 | Zero Trust Agent Benchmark test leaks | 0 | 0 (Wilson upper 0.0038) | PASS |
| H3 | Detection per supported encoding | ≥ 99% | min 1.000 | PASS |
| H4 | Local scanner false-positive rate | ≤ 1% | 0.000 | PASS |
| H5 | Rotation failed requests | 0 | 0 | PASS |

## Zero Trust Agent Benchmark v4 test split

| Slice | Block rate (95% CI) | FPR (95% CI) | Leaks (95% CI rate) |
|---|---:|---:|---:|
| Overall | 58.6% (95% CI 54.2-62.8%) | 0.8% (95% CI 0.3-2.0%) | 0 (0.0%, 95% CI 0.0-0.4%) |
| In-policy | 20.0% (95% CI 15.5-25.4%) | n/a | 0 (0.0%, 95% CI 0.0-1.5%) |
| Out-of-policy | 97.2% (95% CI 94.3-98.6%) | n/a | 0 (0.0%, 95% CI 0.0-1.5%) |
| v3 (superseded: had shortcuts) overall | 58.6% (95% CI 54.2-62.8%) | 0.0% (95% CI 0.0-0.8%) | 0 (0.0%, 95% CI 0.0-0.4%) |

Zero Trust Agent Benchmark v4 adapter scope: the defense uses only the operator profile's tool catalog/scopes and egress allowlists, identity posture, and issued-secret taint scanning. In-policy confused-deputy attacks with valid identities, adequate scopes, and allowlisted destinations are mostly outside the authorization mechanism; secret-value exfiltration is still blocked with zero observed leaks. FPR is only defined over benign traces overall by the benchmark schema.

TLC: passed with 1,210,884 generated states, 686,356 distinct states, depth 20. Invariants: TypeOK, no use after expiry/revocation, only bound identity use, and at most two valid versions during rotation.

Scanner coverage includes raw, base64, base64url, hex, percent, fully percent-encoded, reversed, ROT13, JSON-escaped, and split tokens. Out of scope: paraphrase, screenshots, steganography, timing channels, encrypted covert channels, and manual retyping outside scanned tool arguments.
