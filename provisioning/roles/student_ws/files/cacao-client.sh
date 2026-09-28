#!/usr/bin/env bash
# cacao-client — trainee CLI for NG-SOAR (KMS + CACAO Validator) and
# Evaluation/Reporting. Covers the Student side of UML steps 4, 6, 9, 14, 16.
# Execution (UML 11) is reserved to the NG-SOAR Operator: 'execute' shows the 403.
set -euo pipefail

NG_SOAR="${NG_SOAR_URL:-http://10.10.30.10:9100}"
EVAL="${EVAL_URL:-http://10.10.30.30:9000}"
ACTION="${1:-help}"
FILE="${2:-}"

call() {  # call METHOD URL [FILE] -> prints the JSON body; non-2xx -> 'HTTP <code>'
  local tmp code
  tmp="$(mktemp)"
  if [ -n "${3:-}" ]; then
    code=$(curl -s -o "$tmp" -w '%{http_code}' -X "$1" "$2" \
                -H 'Content-Type: application/json' --data-binary "@$3" || echo 000)
  else
    code=$(curl -s -o "$tmp" -w '%{http_code}' -X "$1" "$2" || echo 000)
  fi
  (jq . "$tmp" 2>/dev/null || cat "$tmp")
  rm -f "$tmp"
  case "$code" in 2*) ;; *) echo "HTTP $code"; return 1 ;; esac
}

need_file() {
  [ -n "$FILE" ] && [ -f "$FILE" ] || { echo "cacao-client: playbook file '$FILE' not found" >&2; exit 2; }
}

playbook_id() {
  jq -er '.id' "$FILE" 2>/dev/null \
    || { echo "cacao-client: '$FILE' is not valid JSON or has no 'id'" >&2; exit 2; }
}

case "$ACTION" in
  create)     # UML 4 - create the playbook in NG-SOAR (KMS, status 'draft')
    need_file; call POST "$NG_SOAR/playbooks" "$FILE"
    ;;
  submit)     # UML 6 / 9 -> NG-SOAR validates (7) and answers (8); approved -> (10)
    need_file; call POST "$NG_SOAR/playbooks/submit" "$FILE"
    ;;
  status)     # KMS status of the playbook (draft / rejected / ready-for-execution / executed)
    need_file; pid=$(playbook_id); call GET "$NG_SOAR/playbooks/$pid"
    ;;
  report)     # UML 14 - execution logs, status and host firewall evidence
    need_file; pid=$(playbook_id); call GET "$NG_SOAR/playbooks/$pid/execution"
    ;;
  execute)    # UML 11 is NOT a Student action: NG-SOAR answers 403
    need_file; call POST "$NG_SOAR/execute" "$FILE"
    ;;
  summary)    # UML 16 - training summary from Evaluation/Reporting
    call GET "$EVAL/summary"
    ;;
  *)
    echo "Usage: cacao-client {create|submit|status|report} <playbook.json>"
    echo "       cacao-client summary"
    ;;
esac
