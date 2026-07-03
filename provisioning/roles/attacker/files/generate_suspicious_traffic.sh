#!/usr/bin/env bash
# UML step 2: generate suspicious traffic from the test IP towards the target.
# Loops HTTP requests + a light port scan so the malicious source IP is visible
# to defenders before the CACAO block rule is applied.
set -u
TARGET="${1:-10.10.20.10}"
PORT="${2:-80}"
echo "[attacker] generating continuous suspicious traffic -> ${TARGET}:${PORT}"
# Run forever: the firewall's drop-rule counter must keep incrementing so the
# NG-SOAR executor can confirm the block by counter (UML 13). curl uses a short
# timeout so a blocked target does not stall the loop.
while true; do
    curl -s -o /dev/null --max-time 3 "http://${TARGET}:${PORT}/admin" || true
    curl -s -o /dev/null --max-time 3 "http://${TARGET}:${PORT}/.env" || true
    nc -z -w2 "${TARGET}" 22 >/dev/null 2>&1 || true
    sleep 1
done
