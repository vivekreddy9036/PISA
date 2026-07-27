"""CoAP resource discovery: GET /.well-known/core (RFC 6690 CoRE Link
Format) and use the raw payload as evidence the host speaks CoAP —
common on constrained IoT devices (sensors, actuators) that don't run a
full HTTP stack.
"""
import asyncio

import aiocoap


async def _fetch_well_known_core(ip: str, port: int, timeout: float) -> bytes | None:
    protocol = await aiocoap.Context.create_client_context()
    try:
        request = aiocoap.Message(
            code=aiocoap.GET, uri=f"coap://{ip}:{port}/.well-known/core"
        )
        response = await asyncio.wait_for(protocol.request(request).response, timeout=timeout)
        if not response.code.is_successful():
            return None
        return response.payload
    finally:
        await protocol.shutdown()


def _get_well_known_core(ip: str, port: int, timeout: float) -> bytes | None:
    """Sync wrapper around the asyncio CoAP client — the one networking
    seam in this module — tests monkeypatch this instead of touching real
    sockets."""
    try:
        return asyncio.run(_fetch_well_known_core(ip, port, timeout))
    except Exception:
        return None


def probe(ip: str, port: int, timeout: float) -> list[dict]:
    payload = _get_well_known_core(ip, port, timeout)
    if not payload:
        return []

    resource_count = payload.count(b"<")
    return [{
        "protocol": "coap",
        "feature_key": "coap.well_known_core",
        "feature_value": payload.decode(errors="ignore")[:200],
        "confidence": 0.85 if resource_count else 0.4,
        "device_type_hint": "CoAP Device",
    }]
