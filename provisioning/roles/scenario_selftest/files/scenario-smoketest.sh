#!/usr/bin/env bash
# =============================================================================
# scenario-smoketest.sh  ---  INSTRUCTOR TOOL  (contains the level answers!)
# -----------------------------------------------------------------------------
# Runs the PUC2 Sub Case 2d runtime checks and prints PASS/FAIL per level of the
# V3 training definition. Run it on ng-soar (needs the operator token, the
# executor key and the cr-compile copy installed there). Safe to re-run: at the
# end it restores lab-target's base ruleset and removes the smoke-test KMS entry
# and Evaluation report, so the trainee starts from a clean state. Run it BEFORE
# the trainee starts: it reuses the reference playbook id from the toolkit.
#
# Usage:  sudo /usr/local/sbin/scenario-smoketest.sh
# Env overrides: NG_SOAR_URL, EVAL_URL, TARGET_URL, SAMPLE, ENF_KEY, TOKEN_FILE
# =============================================================================
set -u

NG_SOAR_URL="${NG_SOAR_URL:-http://10.10.30.10:9100}"
EVAL_URL="${EVAL_URL:-http://10.10.30.30:9000}"
TARGET_URL="${TARGET_URL:-http://10.10.20.10/}"
MAL_IP="${MAL_IP:-10.10.10.10}"
# Host-based enforcement point = lab-target (nftables input).
ENF_HOST="${ENF_HOST:-10.10.20.10}"
ENF_USER="${ENF_USER:-soar-fw}"
ENF_KEY="${ENF_KEY:-/opt/ng-soar-cacao/keys/id_ed25519}"
TOKEN_FILE="${TOKEN_FILE:-/etc/ng-soar/operator.token}"

SAMPLE="${SAMPLE:-}"
for c in "$SAMPLE" /usr/local/share/cacao-training/sample_block_ip_playbook.json \
                   /home/ubuntu/cacao/sample_block_ip_playbook.json; do
  [ -n "$c" ] && [ -f "$c" ] && { SAMPLE="$c"; break; }
done
CR_COMPILE=""
for c in /usr/local/bin/cr-compile /usr/local/sbin/scenario-cr-compile; do
  [ -x "$c" ] && { CR_COMPILE="$c"; break; }
done
TOKEN=""
[ -r "$TOKEN_FILE" ] && TOKEN="$(cat "$TOKEN_FILE")"

pass=0; fail=0
ok()   { echo "  [PASS] $1"; pass=$((pass+1)); }
ko()   { echo "  [FAIL] $1"; fail=$((fail+1)); }
skip() { echo "  [SKIP] $1"; }

echo "=== PUC2 2d scenario smoke-test (training V3) ==="

# --- L6 / L25 : target reachable + title -----------------------------------
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$TARGET_URL" || echo 000)
[ "$code" = "200" ] && ok "L6/L25 target reachable (HTTP $code)" || ko "L6/L25 target HTTP=$code (expected 200)"
curl -s --max-time 6 "$TARGET_URL" | grep -q "Lab Target Service" \
  && ok "L6 page title 'Lab Target Service'" || ko "L6 page title not found"

if [ -z "$SAMPLE" ]; then
  ko "sample playbook not found; cannot run the NG-SOAR checks"
  echo "=== result: PASS=$pass FAIL=$fail ==="; exit 1
fi
PB="$(mktemp)"
jq --arg ip "$MAL_IP" '.playbook_variables.source_ip.value = $ip' "$SAMPLE" > "$PB"
PID="$(jq -r .id "$PB")"

# --- L16 : create -> draft -------------------------------------------------
st=$(curl -s -X POST "$NG_SOAR_URL/playbooks" -H 'Content-Type: application/json' \
          --data-binary "@$PB" | jq -r '.status')
[ "$st" = "draft" ] && ok "L16 create status=draft" || ko "L16 create status=$st"

# --- L21 / L22 : submit -> approved, ready-for-execution -------------------
sub=$(curl -s -X POST "$NG_SOAR_URL/playbooks/submit" -H 'Content-Type: application/json' \
           --data-binary "@$PB")
[ "$(echo "$sub" | jq -r .approved)" = "true" ] && ok "L21 submit approved=true" \
  || ko "L21 submit approved=$(echo "$sub" | jq -c .errors)"
st=$(curl -s "$NG_SOAR_URL/playbooks/$PID" | jq -r .status)
[ "$st" = "ready-for-execution" ] && ok "L22 status=ready-for-execution" || ko "L22 status=$st"

# --- L26 : Student execute refused ----------------------------------------
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$NG_SOAR_URL/execute" \
            -H 'Content-Type: application/json' --data-binary "@$PB")
[ "$code" = "403" ] && ok "L26 student execute -> HTTP 403" || ko "L26 student execute -> HTTP $code"

if [ -z "$TOKEN" ]; then
  skip "L27-L34 operator token $TOKEN_FILE not readable (run on ng-soar as root)"
else
  # --- L27 : operator queue shows the source IP ---------------------------
  q=$(curl -s -H "X-Operator-Token: $TOKEN" "$NG_SOAR_URL/operator/queue" \
        | jq -r --arg id "$PID" '.ready_for_execution[] | select(.kms_id == $id) | .source_ip')
  [ "$q" = "$MAL_IP" ] && ok "L27 operator queue source_ip=$q" || ko "L27 operator queue source_ip='$q'"

  # --- L28 : operator execute -> success ----------------------------------
  st=$(curl -s --max-time 120 -X POST -H "X-Operator-Token: $TOKEN" \
            "$NG_SOAR_URL/operator/execute/$PID" | jq -r .status)
  [ "$st" = "success" ] && ok "L28 operator execute status=success" || ko "L28 operator execute status=$st"

  # --- L29 / L30 : student report -> evidence + BLOCKED -------------------
  rep=$(curl -s "$NG_SOAR_URL/playbooks/$PID/execution")
  echo "$rep" | jq -r .firewall_evidence | grep -q "cacao-block-$MAL_IP" \
    && ok "L29 firewall_evidence has cacao-block-$MAL_IP" || ko "L29 rule comment missing"
  probe=$(echo "$rep" | jq -r .verification.probe_output)
  [ "$probe" = "BLOCKED" ] && ok "L30 probe_output=BLOCKED" || ko "L30 probe_output=$probe"

  # --- L33 / L34 : cr-compile -> 3 artifacts, summary PASS ---------------
  if [ -n "$CR_COMPILE" ]; then
    NG_SOAR_URL="$NG_SOAR_URL" EVAL_URL="$EVAL_URL" CR_PLAYBOOK="$PB" "$CR_COMPILE" --now >/dev/null
    sum=$(curl -s "$EVAL_URL/summary")
    n=$(echo "$sum" | jq -r '.compiled_artifacts | length')
    [ "$n" = "3" ] && ok "L33 compiled_artifacts=3" || ko "L33 compiled_artifacts=$n"
    g=$(echo "$sum" | jq -r .grade)
    [ "$g" = "PASS" ] && ok "L34 summary grade=PASS" || ko "L34 summary grade=$g"
  else
    skip "L33-L34 cr-compile not installed on this host"
  fi
fi

# --- ROLLBACK ----------------------------------------------------------------
if [ -n "$TOKEN" ]; then
  curl -s -o /dev/null -X DELETE -H "X-Operator-Token: $TOKEN" "$NG_SOAR_URL/operator/playbooks/$PID" \
    && echo "  [ROLLBACK] smoke-test playbook removed from the KMS"
else
  echo "  [ROLLBACK] WARNING: no operator token - KMS entry $PID left in place"
fi
curl -s -o /dev/null -X DELETE "$EVAL_URL/reports/$PID" \
  && echo "  [ROLLBACK] smoke-test report removed from Evaluation/Reporting"
rm -f "$PB"
if [ -f "$ENF_KEY" ]; then
  ssh -i "$ENF_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=8 "$ENF_USER@$ENF_HOST" "sudo nft -f /etc/nftables.conf" \
      && echo "  [ROLLBACK] base ruleset reloaded on lab-target ($ENF_HOST)" \
      || echo "  [ROLLBACK] WARNING: could not reload base ruleset"
  left=$(ssh -i "$ENF_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -o ConnectTimeout=8 "$ENF_USER@$ENF_HOST" "sudo nft list ruleset" | grep -c "cacao-block-")
  [ "$left" = "0" ] && echo "  [ROLLBACK] no cacao-block-* rules remain" \
                    || echo "  [ROLLBACK] WARNING: $left cacao-block-* rule(s) still present"
else
  echo "  [ROLLBACK] SKIP: executor key $ENF_KEY not on this host (run on ng-soar)"
fi

echo "=== result: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
