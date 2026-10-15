#!/usr/bin/env bash
# =============================================================================
# scenario-reset.sh  ---  INSTRUCTOR TOOL (run on ng-soar as root)
# -----------------------------------------------------------------------------
# Brings the shared scenario state back to a clean start, so a new training run
# on the SAME sandbox does not inherit what a previous run left behind:
#   - NG-SOAR KMS: every stored playbook, the last execution, the notifications
#   - Evaluation/Reporting: the compiled report of each of those playbooks
#   - lab-target: base nftables ruleset (no cacao-block-* rule left)
# The trainee's files on student-ws are reset there, with
#   sudo /usr/local/sbin/student-ws-reset.sh
#
# Usage:  sudo /usr/local/sbin/scenario-reset.sh
# =============================================================================
set -u

KMS_DIR="${KMS_DIR:-/var/log/ng-soar/kms}"
LOG_DIR="${LOG_DIR:-/var/log/ng-soar}"
EVAL_URL="${EVAL_URL:-http://10.10.30.30:9000}"
ENF_HOST="${ENF_HOST:-10.10.20.10}"
ENF_USER="${ENF_USER:-soar-fw}"
ENF_KEY="${ENF_KEY:-/opt/ng-soar-cacao/keys/id_ed25519}"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8"

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }
echo "=== PUC2 2d scenario reset ==="

# --- KMS entries and their evaluation reports -------------------------------
n=0
for f in "$KMS_DIR"/playbook--*.json; do
  [ -e "$f" ] || continue
  id="$(basename "$f" .json)"
  curl -s -o /dev/null -X DELETE "$EVAL_URL/reports/$id"
  rm -f "$f"
  echo "  [KMS] removed $id (and its evaluation report)"
  n=$((n + 1))
done
curl -s -o /dev/null -X DELETE "$EVAL_URL/reports/unknown"
rm -f "$LOG_DIR/last_execution.json"
: > "$LOG_DIR/operator-notifications.log" 2>/dev/null || true
echo "  [KMS] $n playbook(s) removed; execution log and notifications cleared"

summary="$(curl -s --max-time 8 "$EVAL_URL/summary")"
echo "  [EVAL] summary now: $summary" | tr -s ' \n' ' '; echo

# --- lab-target firewall back to its base ruleset ---------------------------
if ssh -i "$ENF_KEY" $SSH_OPTS "$ENF_USER@$ENF_HOST" "sudo nft -f /etc/nftables.conf"; then
  left=$(ssh -i "$ENF_KEY" $SSH_OPTS "$ENF_USER@$ENF_HOST" "sudo nft list ruleset" | grep -c "cacao-block-")
  echo "  [FW] lab-target base ruleset reloaded; cacao-block-* rules left: $left"
else
  echo "  [FW] WARNING: could not reach lab-target over SSH ($ENF_HOST); check its sshd"
fi

echo "Next: on student-ws run  sudo /usr/local/sbin/student-ws-reset.sh"
