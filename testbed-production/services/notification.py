"""Notification service — consumes from Kafka, serves health endpoint."""
import http.server
import threading
import time
import os
import socket

KAFKA_HOST = os.environ.get("KAFKA_HOST", "172.22.0.23")
APP_NAME = os.environ.get("APP_NAME", "notification-svc")

class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(f'{{"service":"{APP_NAME}","status":"ok"}}'.encode())
    def log_message(self, format, *args):
        pass

def kafka_consumer():
    """Simulate Kafka consumer — periodic TCP connect to Kafka broker."""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((KAFKA_HOST, 9092))
            s.close()
        except Exception:
            pass
        time.sleep(10)

if __name__ == "__main__":
    t = threading.Thread(target=kafka_consumer, daemon=True)
    t.start()
    server = http.server.HTTPServer(("0.0.0.0", 8080), HealthHandler)
    print(f"[{APP_NAME}] Running on port 8080")
    server.serve_forever()
