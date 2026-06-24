import json, os, subprocess, tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

def run_semgrep(files):
    with tempfile.TemporaryDirectory() as d:
        for f in files:
            p = os.path.realpath(os.path.join(d, f["path"]))
            root = os.path.realpath(d)
            if not (p == root or p.startswith(root + os.sep)):
                raise ValueError("path traversal attempt: %s" % f["path"])
            os.makedirs(os.path.dirname(p), exist_ok=True) if os.path.dirname(p) else None
            with open(p, "w") as fh:
                fh.write(f["content"])
        proc = subprocess.run(
            ["semgrep", "--config", "p/default", "--json", "--quiet", "--timeout", "60", d],
            capture_output=True, text=True, timeout=120,
        )
        out = json.loads(proc.stdout or '{"results":[],"errors":[]}')
        # rewrite absolute temp paths back to relative
        for r in out.get("results", []):
            r["path"] = os.path.relpath(r["path"], d)
        return out

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/scan":
            self.send_response(404); self.end_headers(); return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            result = run_semgrep(body.get("files", []))
            payload = json.dumps(result).encode()
            self.send_response(200)
        except Exception as e:
            payload = json.dumps({"results": [], "errors": [str(e)]}).encode()
            self.send_response(500)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok"); return
        self.send_response(404); self.end_headers()

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), H).serve_forever()
