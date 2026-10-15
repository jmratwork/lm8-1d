#!/usr/bin/env bash
# =============================================================================
# student-ws-reset.sh  ---  INSTRUCTOR TOOL (run on student-ws as root)
# -----------------------------------------------------------------------------
# Puts the trainee workspace ~ubuntu/cacao back to what the Cyber Range
# delivered (brief, evidence, toolkit) and removes the trainee's own files
# (my_playbook.json, backups, ...), so a new training run starts clean.
# Pair it with scenario-reset.sh on ng-soar.
#
# Usage:  sudo /usr/local/sbin/student-ws-reset.sh
# =============================================================================
set -u
WS="${WS:-/home/ubuntu/cacao}"
PRISTINE="${PRISTINE:-/usr/local/share/cacao-training/student-ws}"

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }
[ -d "$PRISTINE" ] || { echo "pristine copy $PRISTINE missing" >&2; exit 1; }

echo "=== student-ws workspace reset ==="
find "$WS" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
cp -a "$PRISTINE"/. "$WS"/
chown -R ubuntu:ubuntu "$WS"
echo "  [WS] $WS restored from $PRISTINE"
ls -l "$WS"
