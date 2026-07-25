"""Nmap port + OS scan per discovered host, restricted to IoT-relevant ports
(config.IOT_SCAN_PORTS: MQTT 1883, CoAP 5683, Modbus 502, RTSP 554, common
web/mgmt ports, per the FYP doc's device-triage design).
"""
import subprocess
import xml.etree.ElementTree as ET

import config


def _build_nmap_cmd(ip: str, ports: list[int]) -> list[str]:
    ports_csv = ",".join(str(p) for p in ports)
    return [
        "nmap", "-sV", "-O",
        "--host-timeout", f"{config.NMAP_HOST_TIMEOUT}s",
        "-p", ports_csv,
        "-oX", "-",
        ip,
    ]


def _run_nmap(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.stdout


def _parse_nmap_xml(xml_text: str) -> dict:
    open_ports: list[dict] = []
    os_guess = None

    if not xml_text.strip():
        return {"open_ports": open_ports, "os_guess": os_guess}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {"open_ports": open_ports, "os_guess": os_guess}

    for port in root.findall(".//port"):
        state = port.find("state")
        if state is not None and state.get("state") == "open":
            service = port.find("service")
            open_ports.append({
                "port": int(port.get("portid")),
                "service": service.get("name") if service is not None else None,
            })

    osmatch = root.find(".//osmatch")
    if osmatch is not None:
        os_guess = osmatch.get("name")

    return {"open_ports": open_ports, "os_guess": os_guess}


def scan_host(ip: str, ports: list[int] | None = None) -> dict:
    """Return {"open_ports": [{"port": int, "service": str|None}, ...], "os_guess": str|None}."""
    cmd = _build_nmap_cmd(ip, ports or config.IOT_SCAN_PORTS)
    xml_text = _run_nmap(cmd)
    return _parse_nmap_xml(xml_text)
