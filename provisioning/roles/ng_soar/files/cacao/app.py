#!/usr/bin/env python3
"""
NG-SOAR :: CACAO Validator/Executor (training edition)
======================================================
Implements the server side of UML Sub Case 2d steps 7, 8, 10, 11, 12, 13, 14, 15.

Endpoints
---------
  POST /validate   ->  validate CACAO syntax, workflow logic, required params   (UML 7,8,10)
  POST /execute    ->  run a *validated* CACAO playbook:                          (UML 11)
                         - apply the firewall block rule on the Lab Firewall     (UML 12)
                         - verify the malicious source IP is blocked             (UML 13)
                         - return execution logs / status / firewall evidence    (UML 14)
                         - push the compiled report to Evaluation/Reporting       (UML 15)
  GET  /healthz    ->  liveness

The playbook is a CACAO v2.0 JSON document whose action step blocks a source IP
on the Lab Firewall. See /opt/ng-soar-cacao/templates for the template the
student fills in (UML step 5).
"""
import json
import os
import subprocess
import datetime
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --- Environment (injected by docker-compose) --------------------------------
FW_HOST = os.environ.get("FW_HOST", "10.10.10.1")            # lab-firewall mgmt IP (soar-net)
FW_USER = os.environ.get("FW_MGMT_USER", "soar-fw")
ATTACKER_HOST = os.environ.get("ATTACKER_HOST", "10.10.10.10")
TARGET_HOST = os.environ.get("TARGET_HOST", "10.10.20.10")
TARGET_PORT = os.environ.get("TARGET_PORT", "80")
EVAL_URL = os.environ.get("EVAL_URL", "http://10.10.30.30:9000/ingest")
SSH_KEY = os.environ.get("SSH_KEY", "/keys/id_ed25519")
LOG_DIR = "/var/log/ng-soar"

SSH_BASE = [
    "ssh", "-i", SSH_KEY,
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=8",
]


def now():
    return datetime.datetime.utcnow().isoformat() + "Z"


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
    if "id" in pb and not str(pb["id"]).startswith("playbook--"):
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
    if not start_steps:
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


# --- UML steps 11-14: execution ---------------------------------------------
def execute_cacao(pb):
    log = []

    def step(msg, **kw):
        entry = {"ts": now(), "msg": msg, **kw}
        log.append(entry)

    verdict = validate_cacao(pb)
    if not verdict["approved"]:
        step("refused to execute: playbook is not validated/approved", errors=verdict["errors"])
        return {"status": "rejected", "validation": verdict, "log": log}

    source_ip = _extract_source_ip(pb) or ATTACKER_HOST
    step(f"executing approved playbook '{pb.get('name')}' (id={pb.get('id')})")
    step(f"resolved source_ip parameter -> {source_ip}")

    # UML step 12: apply firewall rule (block malicious source IP) on Lab Firewall.
    nft_cmd = (f"sudo nft add rule inet filter forward ip saddr {source_ip} "
               f"counter drop comment \\\"cacao-block-{source_ip}\\\"")
    rc, out, err = _ssh(FW_HOST, FW_USER, nft_cmd)
    step("applied firewall block rule on Lab Firewall (UML 12)",
         host=FW_HOST, command=nft_cmd, rc=rc, stdout=out, stderr=err)

    # Capture firewall evidence (ruleset + counters).
    rc2, ruleset, err2 = _ssh(FW_HOST, FW_USER, "sudo nft list ruleset")
    step("captured firewall ruleset evidence", rc=rc2, ruleset=ruleset, stderr=err2)

    # UML step 13: verify the traffic from the malicious IP is blocked.
    # Drive the attacker host to attempt to reach the target; expect failure.
    verify_cmd = (f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 6 "
                  f"http://{TARGET_HOST}:{TARGET_PORT}/ || echo BLOCKED")
    rc3, vout, verr = _ssh(ATTACKER_HOST, FW_USER, verify_cmd)
    # Only trust the probe when the SSH to the probe host actually succeeded.
    # A failed SSH (rc != 0, typically empty output) is NOT evidence of a block
    # and must not yield a false "blocked" (which would produce a false PASS).
    if rc3 != 0:
        blocked, verify_state = False, "inconclusive"
    elif "BLOCKED" in vout or vout.strip() == "000":
        blocked, verify_state = True, "blocked"
    elif vout.strip().isdigit():
        blocked, verify_state = False, "reachable"
    else:
        blocked, verify_state = False, "inconclusive"
    step("verified malicious traffic is blocked (UML 13)",
         from_host=ATTACKER_HOST, to=f"{TARGET_HOST}:{TARGET_PORT}",
         result=vout, blocked=blocked, state=verify_state, rc=rc3, stderr=verr)

    status = "success" if (rc == 0 and blocked) else "completed-with-warnings"
    report = {
        "status": status,                       # UML step 14 payload
        "playbook_id": pb.get("id"),
        "playbook_name": pb.get("name"),
        "source_ip_blocked": source_ip,
        "validation": verdict,
        "firewall_evidence": ruleset,
        "verification": {"blocked": blocked, "state": verify_state, "probe_output": vout},
        "log": log,
        "completed_at": now(),
    }

    _persist(report)
    _push_to_evaluation(report)   # UML step 15
    return report


def _ssh(host, user, command):
    cmd = SSH_BASE + [f"{user}@{host}", command]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:  # noqa: BLE001
        return 255, "", f"ssh error: {e}"


def _persist(report):
    os.makedirs(LOG_DIR, exist_ok=True)
    path = os.path.join(LOG_DIR, "last_execution.json")
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)


def _push_to_evaluation(report):
    try:
        data = json.dumps(report).encode()
        req = urllib.request.Request(EVAL_URL, data=data,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=8)
    except Exception:  # noqa: BLE001
        pass  # evaluation host may be offline in standalone tests


# --- HTTP plumbing -----------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"status": "ok", "ts": now()})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            pb = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as e:
            return self._send(400, {"error": f"invalid JSON: {e}"})
        if self.path == "/validate":
            return self._send(200, validate_cacao(pb))
        if self.path == "/execute":
            return self._send(200, execute_cacao(pb))
        self._send(404, {"error": "not found"})

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    os.makedirs(LOG_DIR, exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", 9100), Handler).serve_forever()
