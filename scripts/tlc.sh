#!/usr/bin/env bash
set -euo pipefail

if ! command -v java >/dev/null 2>&1; then
  echo "SKIP TLC: java not available"
  exit 0
fi

TLA_JAR="${TLA_JAR:-tools/tla2tools.jar}"
if [[ ! -f "$TLA_JAR" ]]; then
  echo "SKIP TLC: tla2tools.jar not available"
  exit 0
fi

case "$TLA_JAR" in
  /* | [A-Za-z]:*) TLA_CP="$TLA_JAR" ;;
  *) TLA_CP="../$TLA_JAR" ;;
esac

mkdir -p .tlc-states
(
  cd specs
  java -XX:+UseParallelGC -cp "$TLA_CP" tlc2.TLC -workers auto -metadir ../.tlc-states -config LeaseLifecycle.cfg LeaseLifecycle.tla
)
