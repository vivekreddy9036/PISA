import os

WIFI_IFACE = "wlx00c0cab96bf1"
SCAN_DEFAULT_DURATION = 30
DB_PATH = os.path.join(os.path.dirname(__file__), "pisa.db")
# Loopback by default: the dashboard's API has no authentication, and its
# endpoints accept WiFi passwords and trigger real network actions (join,
# scan, device discovery) — binding to all interfaces by default would let
# anyone on the same network segment drive the tool. Set PISA_HOST=0.0.0.0
# (or pass --host) to explicitly opt into LAN exposure, e.g. to view the
# dashboard from a laptop while PISA runs headless on a field Pi.
FLASK_HOST = os.environ.get("PISA_HOST", "127.0.0.1")
FLASK_PORT = 5000
FLASK_DEBUG = False

# M1: managed-mode interface used to join a target network (distinct from the
# monitor-mode WIFI_IFACE used for M0 beacon capture) — the Pi's built-in
# adapter, per the dual-radio hardware layout.
JOIN_IFACE = "wlp0s20f3"
JOIN_TIMEOUT = 30
# Safety ceiling (seconds) for the arp-scan subprocess; arp-scan's own
# per-host timeout/retry/backoff governs actual sweep duration (~30s for an
# 8k-address /19 in practice) — this just bounds the worst case.
ARP_SWEEP_TIMEOUT = 60
NMAP_HOST_TIMEOUT = 30
# M1: number of hosts Nmap-scanned concurrently during discovery. Each host
# scan can take up to NMAP_HOST_TIMEOUT; on a subnet with hundreds of live
# hosts (see ARP_SWEEP_TIMEOUT above), doing this sequentially is a multi-hour
# bottleneck. Threaded, not multiprocess — each nmap call is a subprocess, so
# the GIL isn't in the way.
NMAP_MAX_WORKERS = 30
IOT_SCAN_PORTS = [22, 23, 80, 443, 502, 554, 1883, 5555, 5683, 8080, 8443]
MDNS_QUERY_TIMEOUT = 2.0

# M2: protocol fingerprinting. Maps an open TCP port to the probe that
# understands it. CoAP (5683) is UDP and never shows up in nmap_scan's
# TCP-only open_ports, so fingerprint_runner probes it unconditionally
# instead of gating on this map.
M2_PROTOCOL_PORTS = {
    1883: "mqtt",
    5683: "coap",
    80: "http",
    443: "http",
    8080: "http",
    8443: "http",
    554: "rtsp",
}
M2_PROBE_TIMEOUT = 3.0
# Every device gets an unconditional CoAP probe (it's UDP, so it never shows
# up in nmap_scan's TCP-only open_ports — see fingerprint_runner.py), which
# costs a full M2_PROBE_TIMEOUT on any host that doesn't speak it. Same
# sequential-vs-hundreds-of-hosts problem M1 hit — fan out concurrently.
M2_MAX_WORKERS = 30

# Phase 6: bounded timeout for a single verification test's network
# request(s) — matches M2_PROBE_TIMEOUT's role for fingerprinting; a hung
# target must never hang the Flask request/assessment worker that calls it.
VERIFICATION_TIMEOUT = 5.0

# Phase 7: bounded wall-clock timeout for one RouterSploit check()/run()
# call. Enforced via a thread-pool .result(timeout=...) wait, not true
# process-level termination (a real, documented limitation — see
# .scratch/pisa-phase7-exploitation.md) — but the caller (Flask request /
# assessment worker) is guaranteed to get control back within this bound
# regardless of what the underlying RouterSploit call is doing.
EXPLOIT_TIMEOUT = 20.0

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
AWS_REGION = "ap-south-1"
S3_BUCKET = "pisa-reports"
DYNAMO_PREFIX = "pisa_"

WSPS_WEIGHTS = {
    "encryption": {"WPA3": 35, "WPA2": 25, "WPA": 10, "Open": 0},
    "channel_bonus": 15,
    "signal_excellent": 20,
    "signal_good": 12,
    "signal_fair": 6,
    "beacon_interval_bonus": 12,
    "hidden_ssid_penalty": -10,
    "pmf_bonus": 15,
    "wps_penalty": -15,
}

WSPS_GRADES = [("A", 90), ("B", 75), ("C", 60), ("D", 45), ("E", 30)]
NON_OVERLAPPING_CHANNELS = {1, 6, 11}

# Monitor-mode capture stays on whatever channel the adapter is parked on —
# sniff() does not hop channels itself. This list covers the channels most
# consumer APs actually use (2.4GHz non-overlapping + common 5GHz UNII-1/3);
# it is not the full legal channel set. beacon_capture cycles through it
# during a scan so it doesn't just listen on one fixed channel.
SCAN_CHANNELS = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161, 165]
CHANNEL_HOP_INTERVAL = 0.5
