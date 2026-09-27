from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .audit import verify_audit_log
from .stats import wilson


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ephemeral-agent-secret-leasing")
    sub = parser.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify-audit")
    v.add_argument("path")
    v.add_argument("public_key")
    w = sub.add_parser("wilson")
    w.add_argument("k", type=int)
    w.add_argument("n", type=int)
    args = parser.parse_args(argv)
    if args.cmd == "verify-audit":
        key = load_pem_public_key(Path(args.public_key).read_bytes())
        res = verify_audit_log(Path(args.path), key)  # type: ignore[arg-type]
        print(json.dumps({"ok": res.ok, "records": res.records, "error": res.error}))
        return 0 if res.ok else 1
    print(json.dumps(wilson(args.k, args.n).as_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
