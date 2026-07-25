"""Join a target WiFi network on the managed-mode interface via nmcli.

Kept separate from the monitor-mode capture path (pisa/m0/beacon_capture.py)
because associating with a network requires a managed-mode radio — on the
target hardware that's the Pi's built-in adapter (config.JOIN_IFACE), not the
external monitor-mode adapter used for M0 (config.WIFI_IFACE).
"""
import subprocess
import time

import config


def _build_connect_cmd(iface: str, ssid: str, password: str) -> list[str]:
    return ["nmcli", "device", "wifi", "connect", ssid, "password", password, "ifname", iface]


def _run(cmd: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _rescan(iface: str) -> None:
    """Refresh NetworkManager's AP cache for iface before connecting.

    Without this, `nmcli device wifi connect` can build a connection profile
    without knowing the target's security type (stale/missing AP cache entry),
    and NetworkManager rejects it with "802-11-wireless-security.key-mgmt:
    property is missing" even though a correct password was given.
    """
    subprocess.run(["nmcli", "device", "wifi", "rescan", "ifname", iface], capture_output=True, text=True)
    time.sleep(2)


def _forget_profile(ssid: str) -> None:
    """Delete any existing NetworkManager connection profile for ssid.

    `nmcli device wifi connect` reuses an existing profile with the same
    name/SSID if one exists rather than building a fresh one — if that
    existing profile is stale or partially configured (e.g. left over from
    an earlier connection made outside PISA), it can be missing security
    settings entirely, producing the same "key-mgmt property is missing"
    error even with a correct password. Deleting it first forces a clean
    profile to be created. Best-effort: no-op if no such profile exists.
    """
    subprocess.run(["nmcli", "connection", "delete", ssid], capture_output=True, text=True)


def _read_ipv4(iface: str) -> tuple[str | None, str | None]:
    addr = _run(["nmcli", "-g", "IP4.ADDRESS", "device", "show", iface]).stdout.strip()
    gateway = _run(["nmcli", "-g", "IP4.GATEWAY", "device", "show", iface]).stdout.strip()
    ip = addr.split("|")[0].split("/")[0] if addr else None
    return (ip or None), (gateway or None)


def join_network(iface: str, ssid: str, password: str, timeout: int = config.JOIN_TIMEOUT) -> dict:
    """Associate iface with ssid/password and resolve its DHCP-assigned IPv4.

    Returns {"connected": bool, "ip": str|None, "gateway": str|None, "error": str|None}.
    """
    _forget_profile(ssid)
    _rescan(iface)
    cmd = _build_connect_cmd(iface, ssid, password)
    try:
        proc = _run(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"connected": False, "ip": None, "gateway": None, "error": "timed out connecting to network"}

    if proc.returncode != 0:
        error = (proc.stderr or proc.stdout or "nmcli connect failed").strip()
        return {"connected": False, "ip": None, "gateway": None, "error": error}

    ip, gateway = _read_ipv4(iface)
    return {"connected": True, "ip": ip, "gateway": gateway, "error": None}
