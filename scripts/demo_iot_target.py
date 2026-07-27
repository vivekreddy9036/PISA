"""Deliberately-vulnerable local test target for demoing PISA's M2
(protocol fingerprinting) and M4 (RouterSploit exploit verification)
when no real IoT hardware is available.

Runs three small local services on 127.0.0.1, each replicating exactly
what a real (unpatched) device would do — not a generic "fake camera",
but bytes-for-bytes what the specific RouterSploit modules' check()
functions look for, verified against the real modules during development:

- HTTP  (port 8080): D-Link "PingTest" RCE, CVE-2019-16920
  (routersploit.modules.exploits.routers.dlink.dir_655_866_652_rce).
  The real vulnerability: the device's CGI double-decodes the
  `ping_ipaddr` field, so a literal "%0a" in the (already form-decoded)
  value gets treated as a shell newline, and whatever follows runs as a
  command. This handler reproduces exactly that string-handling bug —
  nothing is actually executed, it just echoes back what a genuinely
  vulnerable device's `echo <mark>` injection would return — which is
  the only thing check() looks for (`mark in response`). Also serves a
  camera-flavored Server header + page title for M2's http_probe.
- CoAP  (port 5683): exposes two resources via /.well-known/core, for
  M2's coap_probe.
- RTSP  (port 554): replies to OPTIONS with a camera-flavored Server
  header, for M2's rtsp_probe.

MQTT is intentionally not included — no local broker was available in
this environment without adding a system service (e.g. mosquitto);
wiring one up is a natural follow-on if you want full 4-protocol
coverage.

Usage:
    sudo venv/bin/python scripts/demo_iot_target.py

(Needs root only because RTSP's default port, 554, is <1024 — HTTP and
CoAP's ports don't need it.) Then either add a device row pointing at
127.0.0.1 with open_ports [{"port":8080,...},{"port":554,...}], or just
call the API directly against an existing device you've retargeted.
Ctrl+C to stop.
"""
import asyncio
import re
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import aiocoap
import aiocoap.resource as resource

HTTP_PORT = 8080
COAP_PORT = 5683
RTSP_PORT = 554


class _CameraHTTPHandler(BaseHTTPRequestHandler):
    server_version = "IPCamera-WebServer/1.0"

    def log_message(self, *args):
        pass  # keep demo output readable

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><head><title>IP Camera Login</title></head><body>Camera Admin</body></html>")

    def do_POST(self):
        if self.path != "/apply_sec.cgi":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="ignore")
        ping_ipaddr = parse_qs(body).get("ping_ipaddr", [""])[0]

        # The real bug: the field is decoded twice by the vulnerable
        # firmware, so a literal "%0a" (not an actual newline at the
        # HTTP layer — confirmed on the wire during development) is
        # honored as a shell newline, and whatever follows executes.
        injected = ping_ipaddr.split("%0a", 1)[1] if "%0a" in ping_ipaddr else ""
        match = re.match(r"echo (.+)", injected)
        output = match.group(1) if match else ""

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(f"<html>{output}</html>".encode())


def _run_http_server():
    ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), _CameraHTTPHandler).serve_forever()


def _run_coap_server():
    site = resource.Site()
    site.add_resource([".well-known", "core"], resource.WKCResource(site.get_resources_as_linkheader))
    site.add_resource(["cam", "stream"], resource.Resource())
    site.add_resource(["cam", "status"], resource.Resource())

    async def _serve():
        await aiocoap.Context.create_server_context(site, bind=("0.0.0.0", COAP_PORT))
        await asyncio.get_event_loop().create_future()  # run forever

    asyncio.run(_serve())


def _run_rtsp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", RTSP_PORT))
    server.listen(5)
    while True:
        conn, _ = server.accept()
        try:
            conn.recv(4096)
            response = (
                "RTSP/1.0 200 OK\r\n"
                "CSeq: 1\r\n"
                "Server: IPCamera-RTSP/1.0\r\n"
                "Public: OPTIONS, DESCRIBE, SETUP, PLAY\r\n"
                "\r\n"
            )
            conn.sendall(response.encode())
        finally:
            conn.close()


if __name__ == "__main__":
    threads = [
        threading.Thread(target=_run_http_server, daemon=True, name="http"),
        threading.Thread(target=_run_coap_server, daemon=True, name="coap"),
        threading.Thread(target=_run_rtsp_server, daemon=True, name="rtsp"),
    ]
    for t in threads:
        t.start()

    print(f"[demo-target] HTTP  (camera + CVE-2019-16920) on 0.0.0.0:{HTTP_PORT}")
    print(f"[demo-target] CoAP  on 0.0.0.0:{COAP_PORT}")
    print(f"[demo-target] RTSP  on 0.0.0.0:{RTSP_PORT}")
    print("[demo-target] Ctrl+C to stop")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[demo-target] stopped")
