"""RTSP fingerprinting: send OPTIONS and inspect the response — no RTSP
client library in requirements.txt, so this speaks just enough of the
protocol over a raw socket. A well-formed RTSP status line is itself
strong evidence of an IP camera / video streaming device.
"""
import socket

_REQUEST = "OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"


def _send_options(ip: str, port: int, timeout: float) -> str | None:
    """The one networking seam in this module — tests monkeypatch this
    instead of touching real sockets."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.sendall(_REQUEST.format(ip=ip, port=port).encode())
            sock.settimeout(timeout)
            return sock.recv(4096).decode(errors="ignore")
    except Exception:
        return None


def probe(ip: str, port: int, timeout: float) -> list[dict]:
    data = _send_options(ip, port, timeout)
    if not data or not data.startswith("RTSP/"):
        return []

    lines = data.splitlines()
    features = [{
        "protocol": "rtsp",
        "feature_key": "rtsp.options",
        "feature_value": lines[0],
        "confidence": 0.9,
        "device_type_hint": "IP Camera",
    }]

    server = next(
        (line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("server:")),
        None,
    )
    if server:
        features.append({
            "protocol": "rtsp",
            "feature_key": "rtsp.server",
            "feature_value": server,
            "confidence": 0.5,
            "device_type_hint": None,
        })

    return features
