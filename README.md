# PISA — Portable IoT Security Assessment

A Raspberry Pi 4-based tool that passively assesses the security posture of a
WiFi network from beacon frames alone, scores it (WSPS: WiFi Security Posture
Score, A–F), correlates the access point's vendor against known CVEs, and
presents results in a browser dashboard.

**Current scope (v1):** WiFi assessment only — beacon capture, WSPS scoring,
OUI→CVE correlation, and the dashboard. Device discovery, protocol
fingerprinting, the exploit pipeline, and AWS cloud integration are designed
but not yet implemented (see [`docs/FYP_PROJECT_DOCUMENTATION.md`](docs/FYP_PROJECT_DOCUMENTATION.md#0-current-implementation-status)
for the full status).

## Prerequisites

- Python 3.12+
- A WiFi adapter capable of monitor mode (e.g. Alfa AWUS036ACM) — **optional**.
  Demo Mode generates synthetic scan data, so you can run and click through
  the full dashboard on any laptop with zero special hardware.

## Setup

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
# for running tests / linting too:
pip install -r requirements-dev.txt
```

## Running

Start the dashboard:

```bash
python run.py
```

Then open `http://localhost:5000`, check **Demo Mode**, and click **Start
Scan** — no hardware required. You'll be taken to the session detail page
with scored networks; click **Check CVEs** on any row for an on-demand CVE
lookup (canned data in demo mode, live NVD lookup for real captures).

### Running against real hardware

Put your adapter into monitor mode first, then either scan from the dashboard
(uncheck Demo Mode, set the interface name) or run headlessly from the CLI:

```bash
python run.py --scan --iface wlan1 --duration 30
```

CLI flags: `--scan` (run one scan and exit, no server), `--demo` (synthetic
data), `--duration` (seconds, default 30), `--iface` (default from
`config.WIFI_IFACE`).

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
  m1-m4/    — device discovery, protocol fingerprinting, CVE correlation,
              exploit pipeline (planned, not yet implemented)
  m5/       — Flask dashboard (implemented)
  aws/      — cloud integration (planned)
docs/       — full project documentation, SRS, literature survey
```

## Documentation

- [`docs/FYP_PROJECT_DOCUMENTATION.md`](docs/FYP_PROJECT_DOCUMENTATION.md) — full system design and research documentation
- [`docs/PISA_SRS.md`](docs/PISA_SRS.md) — formal Software Requirements Specification
