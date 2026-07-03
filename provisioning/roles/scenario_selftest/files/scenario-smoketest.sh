#!/usr/bin/env bash
# =============================================================================
# scenario-smoketest.sh  ---  INSTRUCTOR TOOL  (contains the level answers!)
# -----------------------------------------------------------------------------
# Runs the PUC2 Sub Case 2d runtime checks and prints PASS/FAIL per training
# level. Safe to re-run: it rolls the firewall back to its base ruleset at the
# end so no cacao-block-* rule is left in place (level 23 expects HTTP 200).
#
# Usage:  sudo /usr/local/sbin/scenario-smoketest.sh
# Env overrides: NG_SOAR_URL, EVAL_URL, TARGET_URL, EVIDENCE, SAMPLE, FW_KEY
# =============================================================================
set -u

NG_SOAR_URL="${NG_SOAR_URL:-http://10.10.30.10:9100}"
EVAL_URL="${EVAL_URL:-http://10.10.30.30:9000}"
TARGET_URL="${TARGET_URL:-http://10.10.20.10/}"
MAL_IP="${MAL_IP:-10.10.10.10}"
FW_HOST="${FW_HOST:-10.10.30.254}"
FW_USER="${FW_USER:-soar-fw}"
FW_KEY="${FW_KEY:-/opt/ng-soar-cacao/keys/id_ed25519}"

# Locate the evidence log and the sample playbook across likely hosts.
EVIDENCE="${EVIDENCE:-}"
for c in "$EVIDENCE" /home/ubuntu/cacao/detected_traffic.log /root/cacao/detected_traffic.log; do
  [ -n "$c" ] && [ -f "$c" ] && { EVIDENCE="$c"; break; }
done
SAMPLE="${SAMPLE:-}"
for c in "$SAMPLE" /opt/ng-soar-cacao/toolkit/sample_block_ip_playbook.json \
                   /home/ubuntu/cacao/sample_block_ip_playbook.json; do
  [ -n "$c" ] && [ -f "$c" ] && { SAMPLE="$c"; break; }
done

pass=0; fail=0
ok()   { echo "  [PASS] $1"; pass=$((pass+1)); }
ko()   { echo "  [FAIL] $1"; fail=$((fail+1)); }
skip() { echo "  [SKIP] $1"; }

echo "=== PUC2 2d scenario smoke-test ==="

# --- L6 / L23 : target reachable + title -----------------------------------
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$TARGET_URL" || echo 000)
[ "$code" = "200" ] && ok "L6/L23 target reachable (HTTP $code)" || ko "L6/L23 target HTTP=$code (expected 200)"
if curl -s --max-time 6 "$TARGET_URL" | grep -q "Lab Target Service"; then
  ok "L6 page title 'Lab Target Service'"
else
  ko "L6 page title not found"
fi

# --- L7 : detection evidence contains /.env --------------------------------
if [ -n "$SAMPLE" ]; then :; fi
if [ -n "$EVIDENCE" ] && grep -q '/\.env' "$EVIDENCE"; then
  ok "L7 /.env present in $EVIDENCE"
elif [ -n "$EVIDENCE" ]; then
  ko "L7 /.env NOT found in $EVIDENCE"
else
  skip "L7 detected_traffic.log not on this host (run on student-ws)"
fi

# --- L17-20 : validate approved --------------------------------------------
if [ -z "$SAMPLE" ]; then
  ko "sample playbook not found; cannot run validate/execute"
else
  approved=$(curl -s -X POST "$NG_SOAR_URL/validate" -H 'Content-Type: application/json' \
             --data-binary "@$SAMPLE" | jq -r '.approved')
  [ "$approved" = "true" ] && ok "L17-20 validate approved=true" || ko "L17-20 validate approved=$approved"

  # --- L24/25/26 : execute -> success / evidence / BLOCKED ------------------
  exec_json=$(curl -s -X POST "$NG_SOAR_URL/execute" -H 'Content-Type: application/json' \
              --data-binary "@$SAMPLE")
  status=$(echo "$exec_json"   | jq -r '.status')
  probe=$(echo "$exec_json"    | jq -r '.verification.probe_output')
  evidence=$(echo "$exec_json" | jq -r '.firewall_evidence')
  [ "$status" = "success" ] && ok "L24 execute status=success" || ko "L24 execute status=$status"
  echo "$evidence" | grep -q "cacao-block-$MAL_IP" \
    && ok "L25 firewall_evidence has cacao-block-$MAL_IP" || ko "L25 rule comment missing"
  [ "$probe" = "BLOCKED" ] && ok "L26 verification.probe_output=BLOCKED" || ko "L26 probe_output=$probe"

  # --- L29 : summary grade PASS --------------------------------------------
  grade=$(curl -s "$EVAL_URL/summary" | jq -r '.grade')
  [ "$grade" = "PASS" ] && ok "L29 summary grade=PASS" || ko "L29 summary grade=$grade"
fi

# --- ROLLBACK : restore base ruleset ---------------------------------------
if [ -f "$FW_KEY" ]; then
  ssh -i "$FW_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=8 "$FW_USER@$FW_HOST" "sudo nft -f /etc/nftables.conf" \
      && echo "  [ROLLBACK] base ruleset reloaded on $FW_HOST" \
      || echo "  [ROLLBACK] WARNING: could not reload base ruleset"
  left=$(ssh -i "$FW_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -o ConnectTimeout=8 "$FW_USER@$FW_HOST" "sudo nft list ruleset" | grep -c "cacao-block-")
  [ "$left" = "0" ] && echo "  [ROLLBACK] no cacao-block-* rules remain" \
                    || echo "  [ROLLBACK] WARNING: $left cacao-block-* rule(s) still present"
else
  echo "  [ROLLBACK] SKIP: firewall key $FW_KEY not on this host (run rollback from ng-soar)"
fi

echo "=== result: PASS=$pass FAIL=$fail ==="
[ "$fail" -eq 0 ]
