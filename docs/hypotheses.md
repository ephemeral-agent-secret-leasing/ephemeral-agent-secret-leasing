# What we measured

Generated from `results/20260926T060714Z-reference`, `results/benchmark-dev/summary.json`, and `results/benchmark-test/summary.json`. The Zero Trust Agent Benchmark v4.1 test split SHA-256 digest is `d065bab9bed145490579cd7add6a574c6e23c21c0ea4525dc1c14b0fc15acd2b`.

## Secret-related claims

| Claim | Metric | Threshold | Result | Outcome |
|---|---|---:|---:|---|
| Lease issue latency | Lease issue 95th percentile | ≤ 12 milliseconds | 0.434 milliseconds | Met |
| Secret leak prevention with issued secrets | Benchmark test leaks | 0 | 0 (Wilson upper 0.0038) | Met |
| Secret leak prevention without issued secrets | Benchmark test leaks | 0 | 0 (Wilson upper 0.0038) | Met |
| Supported encoding detection | Detection per supported encoding | ≥ 99% | minimum 1.000 | Met |
| Local false-positive rate | Local scanner false-positive rate | ≤ 1% | 0.000 | Met |
| Rotation safety | Rotation failed requests | 0 | 0 | Met |

The defense now enforces opaque lease references, sender-constrained use by tool and destination, user-originated grants for secret acquisition, explicit grants for privileged user-originated tool use, and independent raw/encoded secret-literal detection. These are in scope for a secret-leasing broker.

## Out-of-scope classes

Tool hijacking and confused-deputy requests that carry no secret, use a valid identity, have adequate scope, and target an allowed destination are not fully solved by a secret-leasing broker. They need separate workflow-intent, planner, or human-approval controls. The benchmark results below report those misses honestly.

## Zero Trust Agent Benchmark v4.1 test split

Official evaluator: `zero_trust_agent_benchmark.evaluate.evaluate(defense, traces, provide_issued_secrets=True)`.

| Slice | Block rate (95% confidence interval) | False-positive rate (95% confidence interval) | Leaks (95% confidence interval rate) |
|---|---:|---:|---:|
| Overall | 92.8% (90.2-94.8%) | 1.8% (0.9-3.4%) | 0 (0.0%, 0.0-0.4%) |
| In-policy attacks | 88.0% (83.4-91.5%) | not applicable | 0 (0.0%, 0.0-1.5%) |
| Out-of-policy attacks | 97.6% (94.9-98.9%) | not applicable | 0 (0.0%, 0.0-1.5%) |

Official evaluator with `provide_issued_secrets=False` produced the same aggregate rates: 92.8% block rate, 1.8% false-positive rate, and 0 leaks. The independent detector covers raw common secret literals plus base64, base64url, hex, URL percent encoding, ROT13, reverse, and split-token forms without using benchmark labels.

## Ablation table

To preserve test-set discipline, only the already published version 1 and the final design are test-scored here; individual controls were selected on the dev split.

| Version | Block rate | False-positive rate | Leak rate | Decision p95 latency |
|---|---:|---:|---:|---:|
| Version 1 | 58.6% (54.2-62.8%) | 0.8% (0.3-2.0%) | 0.0% (0.0-0.4%) | 0.167 ms |
| Final: sender-constrained lease references, requester authority checks, privilege grants, parser hardening, and independent encoded-secret detection | 92.8% (90.2-94.8%) | 1.8% (0.9-3.4%) | 0.0% (0.0-0.4%) | 0.155 ms |

## Regression and integrity evidence

- `tests/test_defense_http.py::test_no_label_fields_affect_benchmark_decisions` randomizes label, family, template identifier, description, split, metadata, trace identifier, and per-step malicious flags, then asserts byte-identical normalized decisions.
- `tests/test_benchmark_literals.py::test_defense_adapter_does_not_embed_benchmark_generator_literals` verifies the adapter does not embed benchmark generator literals, the benchmark domain, trace identifiers, template identifiers, or malicious flags.
- Benchmark artifacts keep `manifest.sha256`, per-trial logs, `env.json`, and the pinned test split digest.

The Temporal Logic of Actions Plus (TLA+) model checker passed with 1,210,884 generated states, 686,356 distinct states, depth 19. Invariants: TypeOK, no use after expiry/revocation, only bound identity use, and at most two valid versions during rotation.

Scanner coverage includes raw, base64, base64url, hex, percent, fully percent-encoded, reversed, ROT13, JSON-escaped, and split tokens. Out of scope: paraphrase, screenshots, steganography, timing channels, encrypted covert channels, and manual retyping outside scanned tool arguments.
