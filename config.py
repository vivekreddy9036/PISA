import os

WIFI_IFACE = "wlan1"
SCAN_DEFAULT_DURATION = 30
DB_PATH = os.path.join(os.path.dirname(__file__), "pisa.db")
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
FLASK_DEBUG = False

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
