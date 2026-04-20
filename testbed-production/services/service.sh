#!/bin/bash
# Generic microservice simulator for the CausalTrace 20-container mesh.
# Uses python3 for both the inbound listener and the outbound worker so
# neither side triggers dup2(socket_fd, 0|1|2) — that pattern is the
# Tier-1 reverse-shell invariant and must never fire on legitimate traffic.
#
# Env vars:
#   APP_NAME         — service label (used in logs and health responses)
#   APP_PORT         — listen port (default 8080)
#   UPSTREAM_CALLS   — comma-separated host:port list
#   UPSTREAM_PERIOD  — seconds between outbound fan-out passes (default 2)
#   UPSTREAM_JITTER  — max random jitter seconds added to period (default 2)

PORT=${APP_PORT:-8080}
NAME=${APP_NAME:-service}
UPSTREAM=${UPSTREAM_CALLS:-}
PERIOD=${UPSTREAM_PERIOD:-2}
JITTER=${UPSTREAM_JITTER:-2}

echo "[$NAME] listen=$PORT upstream=$UPSTREAM"

# Outbound worker: connect, send 4 KiB of HTTP, read response, close.
# python's socket API never dup2s the socket onto stdio → no FD_REDIRECT.
if [ -n "$UPSTREAM" ]; then
  python3 -u - <<PY &
import os, random, socket, time, sys
upstream = os.environ.get("UPSTREAM_CALLS","").split(",")
period   = int(os.environ.get("UPSTREAM_PERIOD","2"))
jitter   = int(os.environ.get("UPSTREAM_JITTER","2"))
name     = os.environ.get("APP_NAME","service")
# Generate a 4096-byte padding string so outbound flows produce the
# ≥5120-byte, ≥1-second signal the L4 trust-promoter needs.
pad = "X" * 4096
while True:
    for hp in upstream:
        if not hp: continue
        host, _, port = hp.partition(":")
        try:
            with socket.create_connection((host, int(port)), timeout=2) as s:
                s.settimeout(2)
                req = (f"GET /health HTTP/1.0\r\nHost: {host}\r\n"
                       f"User-Agent: {name}\r\nX-Pad: {pad}\r\n\r\n").encode()
                s.sendall(req)
                # drain the response so tcp_close sees bytes_rx > 0
                end = time.time() + 1.2
                while time.time() < end:
                    try:
                        chunk = s.recv(4096)
                        if not chunk: break
                    except socket.timeout:
                        break
        except Exception:
            pass
    time.sleep(period + random.randint(0, jitter))
PY
fi

# Inbound HTTP listener: python's http.server — no dup2 socket→stdio.
APP_NAME="$NAME" python3 -u - <<PY
import json, os, time
from http.server import BaseHTTPRequestHandler, HTTPServer
NAME = os.environ.get("APP_NAME","service")
PORT = int(os.environ.get("APP_PORT","8080"))

class H(BaseHTTPRequestHandler):
    def _ok(self, body):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(b)))
        self.send_header("Connection","close")
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        self._ok(json.dumps({"service":NAME,"status":"ok","ts":int(time.time())}))
    def log_message(self, *a, **kw):  # silence per-request access log
        return

HTTPServer(("0.0.0.0", PORT), H).serve_forever()
PY
