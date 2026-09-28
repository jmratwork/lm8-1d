#!/usr/bin/env bash
# soar-operator — NG-SOAR Operator console (runs on the ng-soar host).
# Covers the NG-SOAR Operator side of UML steps 10 and 11: review the playbooks
# NG-SOAR approved, and execute one (NG-SOAR then performs UML 12-13).
# The operator token is readable only by the soar-operator group.
set -euo pipefail

NG_SOAR="${NG_SOAR_URL:-http://127.0.0.1:9100}"
TOKEN_FILE="${OPERATOR_TOKEN_FILE:-/etc/ng-soar/operator.token}"
ACTION="${1:-help}"
ID="${2:-}"

if [ ! -r "$TOKEN_FILE" ]; then
  echo "soar-operator: cannot read $TOKEN_FILE - log in as the NG-SOAR Operator (soar-operator)." >&2
  exit 1
fi
TOKEN="$(cat "$TOKEN_FILE")"

call() {  # call METHOD PATH -> prints the JSON body; non-2xx -> 'HTTP <code>' on stderr
  local tmp code
  tmp="$(mktemp)"
  code=$(curl -s -o "$tmp" -w '%{http_code}' -X "$1" -H "X-Operator-Token: $TOKEN" "$NG_SOAR$2" || echo 000)
  (jq . "$tmp" 2>/dev/null || cat "$tmp")
  rm -f "$tmp"
  case "$code" in 2*) ;; *) echo "HTTP $code" >&2; return 1 ;; esac
}

case "$ACTION" in
  queue)      # UML 10 - approved playbooks ready for execution
    call GET /operator/queue
    ;;
  execute)    # UML 11 -> NG-SOAR applies the rule (12) and verifies the block (13)
    if [ -z "$ID" ]; then
      # No id: execute the only queued playbook (saves typing a UUID in the console).
      ids=$(curl -s -H "X-Operator-Token: $TOKEN" "$NG_SOAR/operator/queue" \
              | jq -r '.ready_for_execution[].kms_id')
      count=$(printf '%s' "$ids" | grep -c . || true)
      if [ "$count" -eq 0 ]; then
        echo "soar-operator: no playbook is ready for execution (the Student must get one approved first)" >&2
        exit 2
      fi
      if [ "$count" -ne 1 ]; then
        echo "soar-operator: $count playbooks ready for execution - pass the id:" >&2
        echo "  soar-operator execute <playbook-id>   (ids: soar-operator queue)" >&2
        exit 2
      fi
      ID="$ids"
      echo "soar-operator: executing the only queued playbook $ID" >&2
    fi
    call POST "/operator/execute/$ID"
    ;;
  *)
    echo "Usage: soar-operator queue"
    echo "       soar-operator execute [<playbook-id>]   (id optional if only one is queued)"
    ;;
esac
