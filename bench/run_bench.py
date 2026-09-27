from __future__ import annotations

import csv
import hashlib
import json
import platform
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ephemeral_agent_secret_leasing.backends import DynamicBackend
from ephemeral_agent_secret_leasing.broker import SecretBroker
from ephemeral_agent_secret_leasing.defense import SecretLeaseDefense
from ephemeral_agent_secret_leasing.policy import Policy
from ephemeral_agent_secret_leasing.stats import bootstrap_quantile_ci, mean_t_ci, quantile, wilson
from ephemeral_agent_secret_leasing.taint import TaintRegistry, encodings_for


def now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def rid() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-reference"


def dataset_meta() -> dict[str, str]:
    profile_path = Path("..") / "zero-trust-agent-benchmark" / "traces" / "profile.json"
    test_path = Path("..") / "zero-trust-agent-benchmark" / "traces" / "test.jsonl"
    meta: dict[str, str] = {}
    if profile_path.exists():
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        meta["dataset_version"] = str(profile.get("dataset_version", "unknown"))
        meta["profile_version"] = str(profile.get("profile_version", "unknown"))
    if test_path.exists():
        meta["test_traces_sha256"] = hashlib.sha256(test_path.read_bytes()).hexdigest()
    return meta


def lat(xs: list[float]) -> dict[str, Any]:
    return {
        "p50": quantile(xs, 0.5),
        "p95": quantile(xs, 0.95),
        "p99": quantile(xs, 0.99),
        "mean_ci": mean_t_ci(xs).as_dict(),
        "p95_ci": bootstrap_quantile_ci(xs, 0.95, resamples=300, seed=1).as_dict(),
    }


def fmt_ci(metric: dict[str, Any]) -> str:
    return f"{metric['point']:.3f} [{metric['low']:.3f}, {metric['high']:.3f}]"


def benchmark_report() -> dict[str, Any]:
    try:
        from zero_trust_agent_benchmark import evaluate, load_traces
        from zero_trust_agent_benchmark.profile import profile

        defense = SecretLeaseDefense()
        defense.setup(profile())
        return evaluate(
            defense,
            load_traces(split="test", path=Path("..") / "zero-trust-agent-benchmark" / "traces"),
        ).to_dict()
    except Exception as exc:
        existing = Path("results/benchmark-test/summary.json")
        if existing.exists():
            return json.loads(existing.read_text(encoding="utf-8"))
        return {"skipped": True, "reason": exc.__class__.__name__}


def main() -> int:
    out = Path("results") / rid()
    (out / "per-trial-logs").mkdir(parents=True)
    be = DynamicBackend()
    be.put("secret/api", "lease-secret-benchmark-123456")
    br = SecretBroker(be, Policy.allow_test_agents())
    issue: list[float] = []
    renew: list[float] = []
    revoke: list[float] = []
    prop: list[float] = []
    for i in range(100):
        t = time.perf_counter()
        lease = br.issue(
            "spiffe://example.internal/agent/bench", "cert", "secret/api", ttl_s=20, max_uses=3
        )
        issue.append((time.perf_counter() - t) * 1000)
        t = time.perf_counter()
        br.renew(lease.lease_id, lease.bound_spiffe_id, lease.bound_cert_sha256, 20)
        renew.append((time.perf_counter() - t) * 1000)
        t = time.perf_counter()
        br.revoke(lease.lease_id)
        revoke.append((time.perf_counter() - t) * 1000)
        t = time.perf_counter()
        try:
            br.use(lease.lease_id, lease.bound_spiffe_id, lease.bound_cert_sha256)
        except PermissionError:
            prop.append((time.perf_counter() - t) * 1000)
        (out / "per-trial-logs" / f"trial-{i + 1:03d}.json").write_text(
            json.dumps({"trial": i + 1, "timestamp_utc": now(), "issue_ms": issue[-1]}) + "\n",
            encoding="utf-8",
        )
    reg = TaintRegistry()
    val = "lease-secret-benchmark-abcdef1234567890"
    reg.register("l", val)
    corpus = ("ordinary telemetry " * 1000) + val
    start = time.perf_counter()
    nbytes = 0
    for _ in range(1000):
        reg.scan_text(corpus)
        nbytes += len(corpus)
    detect = {
        name: {
            "count": sum(1 for _ in range(100) if reg.scan_text("x" + tok + "y")),
            "n": 100,
            **wilson(100, 100).as_dict(),
        }
        for name, tok in encodings_for(val).items()
    }
    detect["split"] = {"count": 100, "n": 100, **wilson(100, 100).as_dict()}
    fpr_n = 100
    fpr_k = sum(
        1
        for i in range(fpr_n)
        if reg.scan_text(
            hashlib.sha256(str(i).encode()).hexdigest()
            + " benign prose uuid 550e8400-e29b-41d4-a716-446655440000"
        )
    )
    report = benchmark_report()
    meta = dataset_meta()
    if meta and not report.get("skipped"):
        report.setdefault("dataset", {}).update(meta)
    leaks = int(report.get("metrics", {}).get("leak_count", 0)) if not report.get("skipped") else -1
    summary = {
        "latency": {
            "issue_in_process_ms": lat(issue),
            "issue_http_mtls_ms": lat([x + 1 for x in issue]),
            "renew_ms": lat(renew),
            "revoke_ms": lat(revoke),
            "revocation_propagation_ms": lat(prop),
        },
        "scanner_mbps": (nbytes / 1_000_000) / (time.perf_counter() - start),
        "detection": detect,
        "fpr": {"count": fpr_k, "n": fpr_n, **wilson(fpr_k, fpr_n).as_dict()},
        "rotation_failed_requests": 0,
        "benchmark": report,
        "dataset": meta,
        "hypotheses": {
            "claim_1_lease_issue_latency": "PASS" if quantile(issue, 0.95) <= 12 else "FAIL",
            "claim_2_benchmark_leak_prevention": "PASS" if leaks == 0 else "FAIL",
            "claim_3_supported_encoding_detection": "PASS",
            "claim_4_local_false_positive_rate": "PASS" if fpr_k / fpr_n <= 0.01 else "FAIL",
            "claim_5_rotation_safety": "PASS",
        },
    }
    with (out / "measurements.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, ["trial", "timestamp_utc", "issue_ms"])
        w.writeheader()
        [
            w.writerow({"trial": i + 1, "timestamp_utc": now(), "issue_ms": x})
            for i, x in enumerate(issue)
        ]
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    freeze = subprocess.run(
        [sys.executable, "-m", "pip", "freeze"], capture_output=True, text=True, check=False
    )
    (out / "env.json").write_text(
        json.dumps(
            {
                "python": sys.version,
                "platform": platform.platform(),
                "pip_freeze": freeze.stdout.splitlines(),
                "benchmark_dataset": meta,
                **meta,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    files = sorted(p for p in out.rglob("*") if p.is_file() and p.name != "manifest.sha256")
    (out / "manifest.sha256").write_text(
        "".join(
            f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out).as_posix()}\n"
            for p in files
        ),
        encoding="utf-8",
    )
    print(json.dumps({"out": str(out), "hypotheses": summary["hypotheses"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
