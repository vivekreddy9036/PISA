"""MQTT broker fingerprinting: anonymous CONNECT, inspect the CONNACK
reason code. A broker that responds with a well-formed CONNACK at all —
whether or not it accepts anonymous auth — is a strong signal the host is
running an MQTT broker (common on IoT hubs/gateways).
"""
import time

import paho.mqtt.client as mqtt


def _connect_and_get_reason_code(ip: str, port: int, timeout: float) -> int | None:
    """Anonymous MQTT CONNECT, return the CONNACK reason code (or None on
    no response / any transport error). The one networking seam in this
    module — tests monkeypatch this instead of touching real sockets."""
    result: dict = {}

    def on_connect(client, userdata, flags, reason_code, properties=None):
        result["reason_code"] = int(reason_code)
        client.disconnect()

    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.on_connect = on_connect
        client.connect(ip, port, keepalive=max(1, int(timeout)))

        deadline = time.time() + timeout
        while "reason_code" not in result and time.time() < deadline:
            client.loop(timeout=0.5)
        client.disconnect()
    except Exception:
        return None

    return result.get("reason_code")


def probe(ip: str, port: int, timeout: float) -> list[dict]:
    rc = _connect_and_get_reason_code(ip, port, timeout)
    if rc is None:
        return []

    return [{
        "protocol": "mqtt",
        "feature_key": "mqtt.connack",
        "feature_value": f"reason_code={rc}",
        "confidence": 0.9 if rc == 0 else 0.5,
        "device_type_hint": "MQTT Broker",
    }]
