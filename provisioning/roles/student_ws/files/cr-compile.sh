#!/usr/bin/env bash
# cr-compile — Hands-on Educational Platform (Cyber Range) compiler, UML step 15.
# Compiles the student playbook, its validation results (NG-SOAR KMS) and the
# execution logs (NG-SOAR) and sends them to Evaluation/Reporting.
# Runs every 30 s from cr-compile.timer; 'cr-compile --now' runs it on demand.
set -euo pipefail

NG_SOAR="${NG_SOAR_URL:-http://10.10.30.10:9100}"
EVAL="${EVAL_URL:-http://10.10.30.30:9000}"
PLAYBOOK="${CR_PLAYBOOK:-/home/ubuntu/cacao/my_playbook.json}"
QUIET=1
[ "${1:-}" = "--now" ] && QUIET=0

say() { [ "$QUIET" -eq 1 ] || echo "$@"; }

if [ ! -f "$PLAYBOOK" ]; then
  say "cr-compile: no student playbook at $PLAYBOOK yet - nothing to compile"
  exit 0
fi
if ! PID=$(jq -er '.id' "$PLAYBOOK" 2>/dev/null); then
  say "cr-compile: $PLAYBOOK is not valid JSON or has no 'id' - nothing to compile"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Validation results live in the NG-SOAR KMS (404 = not created in NG-SOAR yet).
code=$(curl -s -o "$tmp/kms.json" -w '%{http_code}' "$NG_SOAR/playbooks/$PID" || echo 000)
if [ "$code" != "200" ]; then
  say "cr-compile: playbook $PID is not in the NG-SOAR KMS yet (HTTP $code) - nothing to compile"
  exit 0
fi
# Execution logs exist only once the NG-SOAR Operator has executed it.
code=$(curl -s -o "$tmp/exec.json" -w '%{http_code}' "$NG_SOAR/playbooks/$PID/execution" || echo 000)
[ "$code" = "200" ] || echo null > "$tmp/exec.json"

jq -n \
  --slurpfile pb   "$PLAYBOOK" \
  --slurpfile kms  "$tmp/kms.json" \
  --slurpfile exec "$tmp/exec.json" \
  '{
     compiled_by: "hands-on-educational-platform",
     compiled_at: (now | todate),
     playbook_id: $kms[0].kms_id,
     kms_status: $kms[0].status,
     student_playbook: $pb[0],
     validation_results: $kms[0].validation_history,
     execution_logs: $exec[0]
   }
   | .compiled_artifacts = ([
       "student_playbook",
       (if (.validation_results | length) > 0 then "validation_results" else empty end),
       (if .execution_logs != null then "execution_logs" else empty end)
     ])' > "$tmp/compiled.json"

code=$(curl -s -o "$tmp/resp.json" -w '%{http_code}' -X POST "$EVAL/ingest" \
            -H 'Content-Type: application/json' --data-binary "@$tmp/compiled.json" || echo 000)
if [ "$code" != "200" ]; then
  echo "cr-compile: Evaluation/Reporting did not accept the report (HTTP $code)" >&2
  exit 1
fi
say "cr-compile: sent $(jq -c '.compiled_artifacts' "$tmp/compiled.json") for $PID to Evaluation/Reporting"
