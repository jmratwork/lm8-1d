#!/usr/bin/env python3
"""
Evaluation / Reporting service (training edition)
=================================================
UML step 15: POST /ingest  - receives the compiled report from NG-SOAR
             (student playbook + validation results + execution logs).
UML step 16: GET  /summary - returns the training summary to the Student.
"""
import json
import os
import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STORE = "/var/log/cacao-training/reports"
os.makedirs(STORE, exist_ok=True)
_last = {"summary": "No execution reported yet."}


def now():
    return datetime.datetime.utcnow().isoformat() + "Z"


def build_summary(report):
    val = report.get("validation", {})
    ver = report.get("verification", {})
    return {
        "scenario": "PUC2 Sub Case 2d - CACAO Playbook Authoring (Firewall IP Block)",
        "playbook_name": report.get("playbook_name"),
        "playbook_id": report.get("playbook_id"),
        "validation_approved": val.get("approved"),
        "validation_errors": val.get("errors", []),
        "validation_warnings": val.get("warnings", []),
        "source_ip_blocked": report.get("source_ip_blocked"),
        "traffic_blocked": ver.get("blocked"),
        "execution_status": report.get("status"),
        "grade": "PASS" if (val.get("approved") and ver.get("blocked")) else "REVIEW",
        "generated_at": now(),
    }


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
            report = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as e:
            return self._send(400, {"error": f"invalid JSON: {e}"})
        fname = os.path.join(STORE, f"report-{now().replace(':', '-')}.json")
        with open(fname, "w") as fh:
            json.dump(report, fh, indent=2)
        global _last
        _last = build_summary(report)
        self._send(200, {"status": "stored", "summary": _last})

    def do_GET(self):
        if self.path in ("/summary", "/"):
            return self._send(200, _last)
        if self.path == "/healthz":
            return self._send(200, {"status": "ok"})
        self._send(404, {"error": "not found"})

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
