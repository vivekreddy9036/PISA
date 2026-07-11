import sqlite3
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sniff

import config
from pisa.db import queries
from pisa.m0.wsps import score_network


def _detect_security(pkt) -> tuple[str, bool]:
    """Parse beacon IEs and return (security_type, pmf_enabled)."""
    security = "Open"
    pmf = False

    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 48:  # RSN IE → WPA2 or WPA3
            security = "WPA2"
            try:
                data = bytes(elt.info)
                if len(data) > 8:
                    pairwise_count = int.from_bytes(data[4:6], "little")
                    akm_offset = 6 + pairwise_count * 4
                    if akm_offset + 2 <= len(data):
                        akm_count = int.from_bytes(data[akm_offset: akm_offset + 2], "little")
                        for i in range(akm_count):
                            akm = data[akm_offset + 2 + i * 4: akm_offset + 6 + i * 4]
                            if len(akm) == 4 and akm[3] == 8:  # AKM=8 is SAE (WPA3)
                                security = "WPA3"
                        cap_offset = akm_offset + 2 + akm_count * 4
                        if cap_offset + 2 <= len(data):
                            caps = int.from_bytes(data[cap_offset: cap_offset + 2], "little")
                            pmf = bool(caps & 0x0040)  # MFPR bit
            except Exception:
                pass
        elif elt.ID == 221 and bytes(elt.info)[:4] == b"\x00\x50\xf2\x01":
            # WPA vendor-specific IE
            if security == "Open":
                security = "WPA"
        try:
            elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            break

    return security, pmf


def _parse_beacon(pkt) -> dict | None:
    if not pkt.haslayer(Dot11Beacon):
        return None
    try:
        bssid = pkt[Dot11].addr3
        if not bssid:
            return None

        ssid = ""
        channel = None
        hidden = False

        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:  # SSID
                raw = bytes(elt.info)
                ssid = raw.decode("utf-8", errors="ignore").strip()
                hidden = len(ssid) == 0
            elif elt.ID == 3:  # DS Parameter Set
                channel = int.from_bytes(bytes(elt.info), "little")
            try:
                elt = elt.payload.getlayer(Dot11Elt)
            except Exception:
                break

        beacon_interval = getattr(pkt[Dot11Beacon], "beacon_interval", None)
        signal = getattr(pkt.getlayer(RadioTap), "dBm_AntSignal", None)
        security, pmf = _detect_security(pkt)

        return {
            "bssid": bssid.upper(),
            "ssid": ssid,
            "channel": channel,
            "signal_dbm": signal,
            "security": security,
            "encryption": security,
            "beacon_interval": beacon_interval,
            "pmf_enabled": int(pmf),
            "hidden": int(hidden),
        }
    except Exception:
        return None


def start_capture(
    session_id: int,
    db_path: str = config.DB_PATH,
    iface: str = config.WIFI_IFACE,
    timeout: int = 30,
) -> list[dict]:
    """Sniff beacons, score with WSPS, persist to DB. Returns list of seen networks."""
    seen: dict[str, dict] = {}

    def handler(pkt):
        data = _parse_beacon(pkt)
        if not data:
            return
        bssid = data["bssid"]
        if bssid in seen:
            return
        seen[bssid] = data

        score, grade = score_network(data)
        data["wsps_score"] = score
        data["wsps_grade"] = grade

        with sqlite3.connect(db_path) as conn:
            queries.insert_network(conn, session_id, data)

        label = data["ssid"] or "<hidden>"
        print(f"[M0] {bssid}  {label:<32}  {data['security']:<5}  ch{data['channel'] or '?'}  WSPS:{grade}({score})")

    sniff(
        iface=iface,
        prn=handler,
        store=0,
        timeout=timeout,
        lfilter=lambda p: p.haslayer(Dot11Beacon),
    )
    return list(seen.values())
