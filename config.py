import os

WIFI_IFACE = "wlx00c0cab96bf1"
SCAN_DEFAULT_DURATION = 30
DB_PATH = os.path.join(os.path.dirname(__file__), "pisa.db")
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
FLASK_DEBUG = False

# M1: managed-mode interface used to join a target network (distinct from the
# monitor-mode WIFI_IFACE used for M0 beacon capture) — the Pi's built-in
# adapter, per the dual-radio hardware layout.
JOIN_IFACE = "wlp0s20f3"
JOIN_TIMEOUT = 30
ARP_SWEEP_TIMEOUT = 5
NMAP_HOST_TIMEOUT = 30
IOT_SCAN_PORTS = [22, 23, 80, 443, 502, 554, 1883, 5555, 5683, 8080, 8443]

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
