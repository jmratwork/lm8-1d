#!/usr/bin/env bash
# UML step 2: generate suspicious traffic from the test IP towards the target.
# Loops HTTP requests (sensitive-file probing) every second, plus a light SSH
# port probe once a minute, so the malicious source IP is visible to defenders
# before the CACAO block rule is applied.
#
# The SSH probe is deliberately rare: lab-target's sshd is also the management
# channel NG-SOAR uses to apply the block (UML 12). Probing port 22 every second
# for days exhausted that sshd ("Connection reset by peer" for the executor).
set -u
TARGET="${1:-10.10.20.10}"
PORT="${2:-80}"
SSH_PROBE_EVERY="${SSH_PROBE_EVERY:-60}"   # seconds between port-22 probes
echo "[attacker] generating continuous suspicious traffic -> ${TARGET}:${PORT}"
# Run forever: the target's drop-rule counter must keep incrementing so the
# NG-SOAR executor can show it in the firewall evidence (UML 14). curl uses a
# short timeout so a blocked target does not stall the loop.
last_ssh=0
while true; do
    curl -s -o /dev/null --max-time 3 "http://${TARGET}:${PORT}/admin" || true
    curl -s -o /dev/null --max-time 3 "http://${TARGET}:${PORT}/.env" || true
    now=$(date +%s)
    if [ $((now - last_ssh)) -ge "$SSH_PROBE_EVERY" ]; then
        nc -z -w2 "${TARGET}" 22 >/dev/null 2>&1 || true
        last_ssh=$now
    fi
    sleep 1
done
