#!/usr/bin/env python3
"""
Evaluation / Reporting service (training edition)
=================================================
UML step 15: POST /ingest  - receives what the Cyber Range compiled
             (student playbook + validation results + execution logs).
UML step 16: GET  /summary - returns the training summary to the Student.
Cleanup:     DELETE /reports/<playbook-id> (instructor smoke-test rollback).
"""
import datetime
import glob
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STORE = os.environ.get("EVAL_STORE", "/var/log/cacao-training/reports")
EMPTY = {"summary": "No compiled report received yet."}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def build_summary(compiled):
    history = compiled.get("validation_results") or []
    last_val = history[-1] if history else {}
    execution = compiled.get("execution_logs") or {}
    ver = execution.get("verification", {})
    approved = bool(last_val.get("approved"))
    blocked = bool(ver.get("blocked"))
    return {
        "scenario": "PUC2 Sub Case 2d - CACAO Playbook Authoring (Malicious IP Block)",
        "compiled_by": compiled.get("compiled_by"),
        "compiled_artifacts": compiled.get("compiled_artifacts", []),
        "playbook_name": (compiled.get("student_playbook") or {}).get("name"),
        "playbook_id": compiled.get("playbook_id"),
        "kms_status": compiled.get("kms_status"),
        "validation_attempts": len(history),
        "validation_approved": approved,
        "validation_errors_seen": sorted({e for v in history for e in v.get("errors", [])}),
        "executed_by": execution.get("executed_by"),
        "execution_status": execution.get("status"),
        "source_ip_blocked": execution.get("source_ip_blocked"),
        "enforcement_point": execution.get("enforcement_point"),
        "traffic_blocked": blocked,
        "grade": "PASS" if (approved and blocked) else "REVIEW",
        "generated_at": now(),
    }


def _latest_summary():
    """Summary of the most recently stored compiled report (survives restarts)."""
    files = sorted(glob.glob(os.path.join(STORE, "report-*.json")), key=os.path.getmtime)
    if not files:
        return EMPTY
    try:
        with open(files[-1]) as fh:
            return build_summary(json.load(fh))
    except (OSError, json.JSONDecodeError):
        return EMPTY


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/ingest":
            return self._send(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", 0))
        try:
            compiled = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as e:
            return self._send(400, {"error": f"invalid JSON: {e}"})
        if not isinstance(compiled, dict):
            return self._send(400, {"error": "report must be a JSON object"})
        # One file per playbook: each compilation replaces the previous one.
        pid = str(compiled.get("playbook_id") or "unknown").replace("/", "_")
        with open(os.path.join(STORE, f"report-{pid}.json"), "w") as fh:
            json.dump(compiled, fh, indent=2)
        self._send(200, {"status": "stored", "summary": build_summary(compiled)})

    def do_GET(self):
        if self.path in ("/summary", "/"):
            return self._send(200, _latest_summary())
        if self.path == "/healthz":
            return self._send(200, {"status": "ok"})
        self._send(404, {"error": "not found"})

    def do_DELETE(self):
        # Instructor smoke-test cleanup: DELETE /reports/<playbook-id>
        parts = self.path.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "reports":
            path = os.path.join(STORE, f"report-{parts[1].replace('..', '_')}.json")
            if os.path.isfile(path):
                os.remove(path)
                return self._send(200, {"deleted": parts[1]})
        self._send(404, {"error": "not found"})

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    os.makedirs(STORE, exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
