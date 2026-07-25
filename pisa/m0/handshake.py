"""PMKID / EAPOL handshake capture (Sprint 2).

Orchestrates hcxdumptool + hcxpcapngtool rather than reimplementing 802.11i
EAPOL-Key parsing — scapy 2.5's EAPOL layer only decodes the 4-byte header,
not the RSN key-data body, and hcxdumptool/hcxtools (listed in FYP doc S10)
are the purpose-built, correctly-tested way to do this.

Passive mode (default) never transmits: --disable_deauthentication plus
--disable_client_attacks/--disable_ap_attacks. It only picks up a PMKID or
handshake if the AP or a client generates one on its own (roaming PMKID
caching, a device reconnecting naturally). It can legitimately capture
nothing in a short window — that is expected, not a failure.

Active mode (authorized=True) allows hcxdumptool's default behavior, which
includes sending deauth/disassoc frames to force a handshake. This is the
FYP's ethics-gated "authorized mode" (S14) and must never be the default.
"""
import os
import signal
import subprocess
import time

import config
from pisa.db import queries
from pisa.db.connection import get_connection


def _captures_dir() -> str:
    return os.path.join(os.path.dirname(config.DB_PATH), "captures")


def _parse_hc22000_line(line: str) -> dict | None:
    """Parse one hashcat -m 22000 line into {'type','bssid','essid'}."""
    parts = line.strip().split("*")
    if len(parts) < 6 or parts[0] != "WPA":
        return None
    if parts[1] == "01":
        hash_type = "PMKID"
    elif parts[1] == "02":
        hash_type = "EAPOL"
    else:
        return None

    bssid_hex = parts[3]
    essid_hex = parts[5]
    if len(bssid_hex) != 12:
        return None
    bssid = ":".join(bssid_hex[i:i + 2] for i in range(0, 12, 2)).upper()
    try:
        essid = bytes.fromhex(essid_hex).decode("utf-8", errors="ignore")
    except ValueError:
        essid = ""
    return {"type": hash_type, "bssid": bssid, "essid": essid}


def _build_hcxdumptool_cmd(iface: str, pcapng_path: str, passive: bool) -> list[str]:
    """Build the hcxdumptool invocation. Flags verified against the installed
    6.3.5 binary's own -h output — its man page documents a newer version
    with different flag names (--silent, --filterlist_ap, etc. don't exist
    here), so this must stay pinned to what `hcxdumptool -h` actually lists.

    There's no BSSID pre-filter in this build; target_bssid narrowing happens
    in capture_handshakes() by filtering the parsed results instead.
    """
    cmd = ["hcxdumptool", "-i", iface, "-w", pcapng_path]
    if passive:
        cmd += [
            "--disable_deauthentication",
            "--disable_proberequest",
            "--disable_association",
            "--disable_reassociation",
            "--disable_beacon",
        ]
    else:
        cmd += ["-F"]
    return cmd


def _run_hcxdumptool(cmd: list[str], timeout: int) -> None:
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def _convert_to_hc22000(pcapng_path: str, out_path: str) -> list[str]:
    if not os.path.exists(pcapng_path) or os.path.getsize(pcapng_path) == 0:
        return []
    subprocess.run(
        ["hcxpcapngtool", "-o", out_path, pcapng_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if not os.path.exists(out_path):
        return []
    with open(out_path) as f:
        return [line.strip() for line in f if line.strip()]


def capture_handshakes(
    iface: str,
    timeout: int = 30,
    target_bssid: str | None = None,
    authorized: bool = False,
    output_dir: str | None = None,
) -> list[dict]:
    """Run a bounded hcxdumptool capture and return parsed PMKID/EAPOL hits.

    authorized=False (default): passive only, zero frames transmitted that
    could force a handshake. authorized=True: allows hcxdumptool's active
    deauth-based attack mode — caller is responsible for having obtained
    operator authorization before setting this.
    """
    passive = not authorized
    output_dir = output_dir or _captures_dir()
    os.makedirs(output_dir, exist_ok=True)

    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    pcapng_path = os.path.join(output_dir, f"capture_{ts}.pcapng")
    hc22000_path = os.path.join(output_dir, f"capture_{ts}.hc22000")

    cmd = _build_hcxdumptool_cmd(iface, pcapng_path, passive)
    _run_hcxdumptool(cmd, timeout)
    lines = _convert_to_hc22000(pcapng_path, hc22000_path)

    results = []
    for line in lines:
        parsed = _parse_hc22000_line(line)
        if not parsed:
            continue
        if target_bssid and parsed["bssid"].upper() != target_bssid.upper():
            continue
        parsed["hc22000_path"] = hc22000_path
        results.append(parsed)
    return results


def run_capture_session(
    session_id: int,
    iface: str,
    timeout: int = 30,
    target_bssid: str | None = None,
    authorized: bool = False,
    db_path: str = config.DB_PATH,
) -> list[dict]:
    """Capture handshakes and persist any hits against this session's networks."""
    results = capture_handshakes(iface, timeout, target_bssid, authorized)

    with get_connection(db_path) as conn:
        for r in results:
            network_id = queries.find_network_by_bssid(conn, session_id, r["bssid"])
            if network_id is None:
                continue
            queries.mark_handshake_captured(conn, network_id, r["type"], r["hc22000_path"])
            queries.insert_alert(
                conn, session_id, "info", "handshake",
                f"{r['type']} captured for {r['bssid']} ({r['essid'] or '<hidden>'})",
                related_id=network_id, related_type="network",
            )
    return results
