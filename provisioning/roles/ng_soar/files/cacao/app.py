#!/usr/bin/env python3
"""
NG-SOAR :: KMS + CACAO Validator/Executor (training edition)
============================================================
Server side of UML Sub Case 2d. Three callers, three permission levels:

Student (no credentials)
  POST /playbooks                  create the playbook in the KMS -> 'draft'        (UML 4)
  POST /playbooks/submit           (re)submit for validation                       (UML 6, 9)
                                     validate syntax / workflow logic / params     (UML 7)
                                     return errors or approval                     (UML 8)
                                     approved -> 'ready-for-execution' and the
                                     NG-SOAR Operator is notified                  (UML 10)
  GET  /playbooks/<id>             KMS status + validation history
  GET  /playbooks/<id>/execution   execution logs, status, host firewall evidence  (UML 14)
  POST /execute                    always 403: execution is reserved to the operator
  POST /validate                   stateless dry-run of the validator (no KMS change)

NG-SOAR Operator (header X-Operator-Token)
  GET    /operator/queue            playbooks ready for execution                  (UML 10)
  POST   /operator/execute/<id>     execute a validated playbook from the KMS      (UML 11)
                                      apply host firewall rule on lab-target       (UML 12)
                                      verify the block from the malicious IP       (UML 13)
  DELETE /operator/playbooks/<id>   remove a KMS entry (instructor/self-test cleanup)

Compilation for Evaluation/Reporting (UML 15) is done by the Cyber Range
(`cr-compile` on the trainee console), not by NG-SOAR.
"""
import datetime
import hmac
import json
import os
import re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --- Environment (injected by docker-compose) --------------------------------
# Flat network, host-based enforcement: the block is applied on the Lab Target
# Service (nftables input) and verified by driving the attacker at the target.
ENFORCE_HOST = os.environ.get("ENFORCE_HOST", "10.10.20.10")   # lab-target mgmt IP
ENFORCE_USER = os.environ.get("ENFORCE_USER", "soar-fw")
ATTACKER_HOST = os.environ.get("ATTACKER_HOST", "10.10.10.10")
ATTACKER_USER = os.environ.get("ATTACKER_USER", "soar-fw")
TARGET_HOST = os.environ.get("TARGET_HOST", "10.10.20.10")     # HTTP target for the probe
TARGET_PORT = os.environ.get("TARGET_PORT", "80")
SSH_KEY = os.environ.get("SSH_KEY", "/keys/id_ed25519")
OPERATOR_TOKEN_FILE = os.environ.get("OPERATOR_TOKEN_FILE", "/secrets/operator.token")
LOG_DIR = os.environ.get("NG_SOAR_LOG_DIR", "/var/log/ng-soar")
KMS_DIR = os.path.join(LOG_DIR, "kms")
NOTIFY_LOG = os.path.join(LOG_DIR, "operator-notifications.log")

SSH_BASE = [
    "ssh", "-i", SSH_KEY,
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=8",
]

PLAYBOOK_ID_RE = re.compile(
    r"^playbook--[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

# KMS statuses
DRAFT, REJECTED, READY, EXECUTED = "draft", "rejected", "ready-for-execution", "executed"

_kms_lock = threading.Lock()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


# --- UML step 7: CACAO validation -------------------------------------------
REQUIRED_TOP = ["type", "spec_version", "id", "name", "workflow", "workflow_start"]
VALID_STEP_TYPES = {"start", "end", "action", "if-condition", "while-condition",
                    "switch-condition", "parallel", "playbook-action"}


def validate_cacao(pb):
    """Validate CACAO syntax, workflow logic and required parameters."""
    errors, warnings = [], []

    # --- syntax / required top-level fields ---
    for field in REQUIRED_TOP:
        if field not in pb:
            errors.append(f"missing required field: '{field}'")
    if pb.get("type") != "playbook":
        errors.append("field 'type' must be 'playbook'")
    if not str(pb.get("spec_version", "")).startswith("cacao-2"):
        errors.append("field 'spec_version' must be a CACAO 2.x value (e.g. 'cacao-2.0')")
    if "id" in pb and not PLAYBOOK_ID_RE.match(str(pb["id"])):
        errors.append("field 'id' must be a 'playbook--<uuid>' identifier")

    workflow = pb.get("workflow", {})
    if not isinstance(workflow, dict) or not workflow:
        errors.append("field 'workflow' must be a non-empty object of steps")
        return _verdict(errors, warnings)

    # --- workflow logic ---
    start = pb.get("workflow_start")
    if start and start not in workflow:
        errors.append(f"'workflow_start' ({start}) does not reference an existing step")

    start_steps = [s for s, v in workflow.items() if v.get("type") == "start"]
    end_steps = [s for s, v in workflow.items() if v.get("type") == "end"]
    if len(start_steps) != 1:
        errors.append("workflow must contain exactly one 'start' step")
    if not end_steps:
        errors.append("workflow must contain at least one 'end' step")

    action_steps = []
    for sid, step in workflow.items():
        stype = step.get("type")
        if stype not in VALID_STEP_TYPES:
            errors.append(f"step '{sid}': invalid step type '{stype}'")
        # 'on_completion' must reference a real step (except for 'end')
        nxt = step.get("on_completion")
        if stype not in ("end",) and nxt and nxt not in workflow:
            errors.append(f"step '{sid}': on_completion -> unknown step '{nxt}'")
        if stype == "action":
            action_steps.append((sid, step))

    if not action_steps:
        errors.append("workflow must contain at least one 'action' step (the firewall block)")

    # --- required parameters for the firewall-block action ---
    block_found = False
    for sid, step in action_steps:
        cmds = step.get("commands", [])
        if not cmds:
            errors.append(f"action step '{sid}': missing 'commands'")
            continue
        for c in cmds:
            ctype = c.get("type")
            cmdline = c.get("command", "")
            if ctype not in ("manual", "bash", "ssh", "http-api"):
                warnings.append(f"action step '{sid}': uncommon command type '{ctype}'")
            # The block command must reference a source IP variable/literal.
            if any(k in cmdline for k in ("drop", "block", "DROP", "REJECT", "deny")):
                if "__SOURCE_IP__" not in cmdline and "source_ip" not in json.dumps(pb.get("playbook_variables", {})):
                    warnings.append(
                        f"action step '{sid}': block command should parameterise the source IP "
                        "via the 'source_ip' playbook variable")
                block_found = True
    if not block_found:
        errors.append("no firewall *block/drop* command found in any action step")

    # --- required playbook variable: source_ip ---
    pvars = pb.get("playbook_variables", {})
    if "source_ip" not in pvars and "__SOURCE_IP__" not in json.dumps(workflow):
        errors.append("required parameter missing: define a 'source_ip' playbook_variable "
                      "or use the __SOURCE_IP__ placeholder in the block command")
    elif _extract_source_ip(pb) in (None, "", "__SOURCE_IP__"):
        warnings.append("source_ip is still the __SOURCE_IP__ placeholder: set it to the "
                        "malicious IP from the exercise brief before execution")

    return _verdict(errors, warnings)


def _verdict(errors, warnings):
    return {
        "approved": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "validated_at": now(),
        "validator": "NG-SOAR CACAO Validator (cacao-2.0)",
    }


def _extract_source_ip(pb):
    pvars = pb.get("playbook_variables", {})
    if "source_ip" in pvars:
        return pvars["source_ip"].get("value") or pvars["source_ip"].get("constant")
    return None


# --- KMS (one JSON document per playbook, read from disk on every request) ---
def _kms_path(pid):
    return os.path.join(KMS_DIR, f"{pid}.json")


def kms_get(pid):
    if not PLAYBOOK_ID_RE.match(pid or ""):
        return None
    try:
        with open(_kms_path(pid)) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def kms_put(entry):
    entry["updated"] = now()
    os.makedirs(KMS_DIR, exist_ok=True)
    tmp = _kms_path(entry["kms_id"]) + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(entry, fh, indent=2)
    os.replace(tmp, _kms_path(entry["kms_id"]))


def kms_all():
    entries = []
    if os.path.isdir(KMS_DIR):
        for name in sorted(os.listdir(KMS_DIR)):
            if name.endswith(".json"):
                e = kms_get(name[:-5])
                if e:
                    entries.append(e)
    return entries


def kms_public(entry):
    """KMS view returned to the Student (UML 8/10 status + validation history)."""
    return {
        "kms_id": entry["kms_id"],
        "name": entry["playbook"].get("name"),
        "status": entry["status"],
        "source_ip": _extract_source_ip(entry["playbook"]),
        "validation_attempts": len(entry["validation_history"]),
        "validation_history": entry["validation_history"],
        "executed": entry.get("execution") is not None,
        "created": entry["created"],
        "updated": entry["updated"],
    }


# --- UML step 4: create the playbook in NG-SOAR (KMS) ------------------------
def create_playbook(pb):
    pid = str(pb.get("id", ""))
    if not PLAYBOOK_ID_RE.match(pid):
        return 400, {"error": "field 'id' must be a 'playbook--<uuid>' identifier "
                              "(generate one with uuidgen) - playbook NOT stored"}
    with _kms_lock:
        entry = kms_get(pid) or {"kms_id": pid, "created": now(),
                                 "validation_history": [], "execution": None}
        entry.update(playbook=pb, status=DRAFT, execution=None)
        kms_put(entry)
    return 200, {"kms_id": pid, "status": DRAFT,
                 "message": "playbook stored in the NG-SOAR KMS; submit it for validation"}


# --- UML steps 6-10: submit / resubmit for validation -------------------------
def submit_playbook(pb):
    pid = str(pb.get("id", ""))
    verdict = validate_cacao(pb)
    with _kms_lock:
        entry = kms_get(pid)
        if entry is None:
            return 404, {**verdict, "approved": False, "status": None,
                         "errors": verdict["errors"] + [
                             f"playbook '{pid}' does not exist in the NG-SOAR KMS: "
                             "create it first with 'cacao-client create <file>' (UML 4)"]}
        entry["playbook"] = pb
        entry["validation_history"].append(verdict)
        entry["status"] = READY if verdict["approved"] else REJECTED
        entry["execution"] = None
        kms_put(entry)
    if verdict["approved"]:
        _notify_operator(entry)                               # UML 10
    return 200, {**verdict, "kms_id": pid, "status": entry["status"],
                 "attempt": len(entry["validation_history"])}


def _notify_operator(entry):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(NOTIFY_LOG, "a") as fh:
        fh.write(json.dumps({"ts": now(), "event": "approved-playbook-ready-for-execution",
                             "kms_id": entry["kms_id"], "name": entry["playbook"].get("name"),
                             "source_ip": _extract_source_ip(entry["playbook"])}) + "\n")


# --- UML steps 11-14: execution by the NG-SOAR Operator ----------------------
def operator_execute(pid):
    with _kms_lock:
        entry = kms_get(pid)
        if entry is None:
            return 404, {"error": f"playbook '{pid}' not found in the KMS"}
        if entry["status"] != READY:
            return 409, {"error": f"playbook status is '{entry['status']}', only "
                                  f"'{READY}' playbooks can be executed"}
        pb = entry["playbook"]

    report = execute_cacao(pb)
    report["executed_by"] = "ng-soar-operator"
    with _kms_lock:
        entry = kms_get(pid) or entry
        entry["execution"] = report
        entry["status"] = EXECUTED
        kms_put(entry)
    _persist(report)
    return 200, report


def execute_cacao(pb):
    log = []

    def step(msg, **kw):
        log.append({"ts": now(), "msg": msg, **kw})

    verdict = validate_cacao(pb)
    if not verdict["approved"]:
        step("refused to execute: playbook is not validated/approved", errors=verdict["errors"])
        return {"status": "rejected", "validation": verdict, "log": log}

    source_ip = _extract_source_ip(pb)
    if source_ip in (None, "", "__SOURCE_IP__"):
        source_ip = ATTACKER_HOST
        step("source_ip placeholder not filled in: resolved to the malicious test IP")
    step(f"executing approved playbook '{pb.get('name')}' (id={pb.get('id')})")
    step(f"resolved source_ip parameter -> {source_ip}")

    # UML step 12: apply the block on the Lab Target Service (nftables input).
    # Ensure the base table/chain exists, then append the source-IP drop rule.
    _ssh(ENFORCE_HOST, ENFORCE_USER, "sudo nft add table inet filter")
    _ssh(ENFORCE_HOST, ENFORCE_USER,
         "sudo nft 'add chain inet filter input { type filter hook input priority 0 ; policy accept ; }'")
    nft_cmd = (f"sudo nft add rule inet filter input ip saddr {source_ip} "
               f"counter drop comment \\\"cacao-block-{source_ip}\\\"")
    rc, out, err = _ssh(ENFORCE_HOST, ENFORCE_USER, nft_cmd)
    step("applied host firewall rule on the Lab Target Service (UML 12)",
         host=ENFORCE_HOST, command=nft_cmd, rc=rc, stdout=out, stderr=err)

    # UML step 13: verify the block by probing the target FROM the malicious IP.
    # Deterministic output: the remote command prints exactly REACHABLE or BLOCKED.
    verify_cmd = (f"curl -s -o /dev/null --max-time 6 "
                  f"http://{TARGET_HOST}:{TARGET_PORT}/ && echo REACHABLE || echo BLOCKED")
    rc3, vout, verr = _ssh(ATTACKER_HOST, ATTACKER_USER, verify_cmd)
    if rc3 != 0:
        blocked, verify_state = False, "inconclusive"
    elif "BLOCKED" in vout:
        blocked, verify_state = True, "blocked"
    elif "REACHABLE" in vout:
        blocked, verify_state = False, "reachable"
    else:
        blocked, verify_state = False, "inconclusive"
    probe_output = "BLOCKED" if blocked else (vout.strip() or "INCONCLUSIVE")
    step("verified malicious traffic is blocked (UML 13)",
         from_host=ATTACKER_HOST, to=f"{TARGET_HOST}:{TARGET_PORT}",
         result=vout, blocked=blocked, state=verify_state, rc=rc3, stderr=verr)

    # Evidence is captured AFTER the probe so the drop counter shows the match.
    rc2, ruleset, err2 = _ssh(ENFORCE_HOST, ENFORCE_USER, "sudo nft list chain inet filter input")
    step("captured host firewall evidence (lab-target input chain)", rc=rc2, stderr=err2)

    status = "success" if (rc == 0 and blocked) else "completed-with-warnings"
    return {
        "status": status,                       # UML step 14 payload
        "playbook_id": pb.get("id"),
        "playbook_name": pb.get("name"),
        "source_ip_blocked": source_ip,
        "enforcement_point": {"host": "lab-target", "ip": ENFORCE_HOST,
                              "table": "inet filter", "chain": "input"},
        "validation": verdict,
        "firewall_evidence": ruleset,
        "verification": {"blocked": blocked, "state": verify_state,
                         "probe_from": ATTACKER_HOST, "probe_output": probe_output},
        "log": log,
        "completed_at": now(),
    }


def _ssh(host, user, command):
    cmd = SSH_BASE + [f"{user}@{host}", command]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:  # noqa: BLE001
        return 255, "", f"ssh error: {e}"


def _persist(report):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(os.path.join(LOG_DIR, "last_execution.json"), "w") as fh:
        json.dump(report, fh, indent=2)


def _operator_token():
    try:
        with open(OPERATOR_TOKEN_FILE) as fh:
            return fh.read().strip()
    except OSError:
        return ""


# --- HTTP plumbing -----------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _is_operator(self):
        expected = _operator_token()
        given = self.headers.get("X-Operator-Token", "")
        return bool(expected) and hmac.compare_digest(given, expected)

    def _forbid_non_operator(self):
        if self._is_operator():
            return False
        self._send(403, {"error": "forbidden: operator credentials required"})
        return True

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        parts = self.path.strip("/").split("/")
        if self.path == "/healthz":
            return self._send(200, {"status": "ok", "ts": now()})
        if parts == ["operator", "queue"]:
            if self._forbid_non_operator():
                return None
            queue = [kms_public(e) for e in kms_all() if e["status"] == READY]
            for q in queue:
                q.pop("validation_history")
            return self._send(200, {"ready_for_execution": queue})
        if len(parts) == 2 and parts[0] == "playbooks":
            entry = kms_get(parts[1])
            if entry is None:
                return self._send(404, {"error": f"playbook '{parts[1]}' not found in the KMS"})
            return self._send(200, kms_public(entry))
        if len(parts) == 3 and parts[0] == "playbooks" and parts[2] == "execution":
            entry = kms_get(parts[1])
            if entry is None:
                return self._send(404, {"error": f"playbook '{parts[1]}' not found in the KMS"})
            if not entry.get("execution"):
                return self._send(404, {"error": "playbook has not been executed yet "
                                                 "(waiting for the NG-SOAR Operator)",
                                        "status": entry["status"]})
            return self._send(200, entry["execution"])
        self._send(404, {"error": "not found"})

    def do_POST(self):
        parts = self.path.strip("/").split("/")
        if self.path == "/execute":
            return self._send(403, {"error": "forbidden: execution is reserved to the "
                                             "NG-SOAR Operator (UML 11)"})
        if parts[:2] == ["operator", "execute"] and len(parts) == 3:
            if self._forbid_non_operator():
                return None
            return self._send(*operator_execute(parts[2]))
        try:
            pb = self._body()
        except json.JSONDecodeError as e:
            return self._send(400, {"error": f"invalid JSON: {e}"})
        if not isinstance(pb, dict):
            return self._send(400, {"error": "the playbook must be a JSON object"})
        if self.path == "/validate":
            return self._send(200, validate_cacao(pb))
        if self.path == "/playbooks":
            return self._send(*create_playbook(pb))
        if self.path == "/playbooks/submit":
            return self._send(*submit_playbook(pb))
        self._send(404, {"error": "not found"})

    def do_DELETE(self):
        parts = self.path.strip("/").split("/")
        if parts[:2] == ["operator", "playbooks"] and len(parts) == 3:
            if self._forbid_non_operator():
                return None
            with _kms_lock:
                if kms_get(parts[2]) is None:
                    return self._send(404, {"error": "not found"})
                os.remove(_kms_path(parts[2]))
            return self._send(200, {"deleted": parts[2]})
        self._send(404, {"error": "not found"})

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    os.makedirs(KMS_DIR, exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", 9100), Handler).serve_forever()
