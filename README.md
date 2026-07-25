# PISA — Portable IoT Security Assessment

A Raspberry Pi 4-based tool that passively assesses the security posture of a
WiFi network from beacon frames alone, scores it (WSPS: WiFi Security Posture
Score, A–F), correlates the access point's vendor against known CVEs, joins a
target network on request, and enumerates the devices on it — all presented
in a browser dashboard.

**Current scope (v1):** WiFi assessment (beacon capture, WSPS scoring,
OUI→CVE correlation) plus M1 network join + device discovery (ARP sweep,
Nmap port/OS scan). Protocol fingerprinting, device-CVE correlation, the
exploit pipeline, and AWS cloud integration are designed but not yet
implemented (see [`docs/FYP_PROJECT_DOCUMENTATION.md`](docs/FYP_PROJECT_DOCUMENTATION.md#0-current-implementation-status)
for the full status).

This is a real-time tool: every capture, join, and scan talks to live
hardware and live networks — there is no synthetic/demo data path.

## Prerequisites

- Python 3.12+
- Two WiFi radios: one capable of monitor mode (e.g. Alfa AWUS036ACM,
  `config.WIFI_IFACE`) for beacon capture, and one in managed mode (e.g. the
  Pi's built-in adapter, `config.JOIN_IFACE`) for joining a target network to
  run device discovery.
- `nmcli`, `arp`/scapy raw-socket access, and `nmap` available on the host
  (Nmap's OS detection (`-O`) needs root).

## Setup

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
# for running tests / linting too:
pip install -r requirements-dev.txt
```

## Running

Put your monitor-mode adapter into monitor mode, then start the dashboard:

```bash
python run.py
```

Open `http://localhost:5000` and click **Start Scan** to capture real
beacons on `config.WIFI_IFACE` (override the interface/duration in the
form). You'll be taken to the session detail page with scored networks:

- **Check CVEs** — on-demand live NVD lookup for that network's vendor.
- **Join & Discover Devices** — enter that network's real WiFi password to
  join it on `config.JOIN_IFACE`, then ARP-sweep and Nmap-scan the joined
  subnet for live devices (IP, MAC, vendor, open ports, OS guess). This
  disconnects the join interface from whatever it's currently on.

Both can also be run headlessly from the CLI:

```bash
python run.py --scan --iface wlan1 --duration 30
python run.py --join-network "SomeSSID" --password "..." --join-iface wlan0
```

CLI flags: `--scan` (run one beacon scan and exit, no server), `--duration`
(seconds, default 30), `--iface` (monitor-mode interface, default
`config.WIFI_IFACE`), `--join-network`/`--password`/`--join-iface` (join a
network and run device discovery headlessly, default `config.JOIN_IFACE`),
`--host` (dashboard bind address, see below).

### Dashboard exposure

The dashboard binds to `127.0.0.1` by default — its API has no
authentication, and its endpoints accept WiFi passwords and trigger real
network actions, so it isn't exposed by default. To view it from another
device (e.g. a laptop while PISA runs headless on a field Pi), explicitly
opt in with `--host 0.0.0.0` or `PISA_HOST=0.0.0.0 python run.py`, and only
do so on a network you trust.

### Running tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v --cov=pisa --cov-report=term-missing
```

This is the same command CI (`.github/workflows/test.yml`) runs.

## Project layout

```
pisa/
  db/       — SQLite schema + query helpers
  m0/       — WiFi beacon capture, WSPS scoring, OUI→CVE correlation (implemented)
  m1/       — network join + device discovery: ARP sweep, Nmap port/OS scan (implemented)
  m2-m4/    — protocol fingerprinting, device CVE correlation, exploit
              pipeline (planned, not yet implemented)
  m5/       — Flask dashboard (implemented)
  aws/      — cloud integration (planned)
docs/       — full project documentation, SRS, literature survey
```

## Documentation

- [`docs/FYP_PROJECT_DOCUMENTATION.md`](docs/FYP_PROJECT_DOCUMENTATION.md) — full system design and research documentation
- [`docs/PISA_SRS.md`](docs/PISA_SRS.md) — formal Software Requirements Specification
