#!/usr/bin/env bash
# cacao-client — trainee CLI for the NG-SOAR CACAO Validator/Executor.
# Covers the Student side of UML steps 6, 9, 11 and 16.
set -euo pipefail

NG_SOAR="${NG_SOAR_URL:-http://10.10.30.10:9100}"
EVAL="${EVAL_URL:-http://10.10.30.30:9000}"
ACTION="${1:-help}"
FILE="${2:-}"

case "$ACTION" in
  validate)   # UML step 6 -> 7,8
    curl -s -X POST "$NG_SOAR/validate" -H 'Content-Type: application/json' \
         --data-binary "@${FILE}" | (jq . 2>/dev/null || cat)
    ;;
  execute)    # UML step 11 -> 12,13,14
    curl -s -X POST "$NG_SOAR/execute" -H 'Content-Type: application/json' \
         --data-binary "@${FILE}" | (jq . 2>/dev/null || cat)
    ;;
  summary)    # UML step 16
    curl -s "$EVAL/summary" | (jq . 2>/dev/null || cat)
    ;;
  *)
    echo "Usage: cacao-client {validate|execute} <playbook.json>"
    echo "       cacao-client summary"
    ;;
esac
