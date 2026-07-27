# PISA — Portable IoT Security Assessment

A Raspberry Pi 4-based tool — architecturally in the spirit of standalone
pentest hardware (Hak5-style gadgets), not just a laptop app — that
passively assesses the security posture of a WiFi network from beacon
frames alone, scores it (WSPS: WiFi Security Posture Score, A–F), correlates
the access point's vendor against known CVEs, joins a target network on
request, enumerates and fingerprints the devices on it, correlates their
CVEs (NVD + EPSS + CISA KEV into a single ExploitScore), and — only under
explicit, logged operator authorization — verifies specific CVEs against
those devices via RouterSploit. All presented in a browser dashboard.

**Current scope (v1):** WiFi assessment (beacon capture, WSPS scoring,
OUI→CVE correlation), M1 network join + device discovery (ARP sweep, Nmap
port/OS scan, mDNS device ID), M2 protocol behavioral fingerprinting
(MQTT/CoAP/HTTP/RTSP), M3 device CVE correlation (NVD + EPSS + CISA KEV +
ExploitScore), and M4 authorized RouterSploit exploit verification (5-second
confirm gate, full audit log). AWS cloud reporting is the only piece still
planned (see [`docs/FYP_PROJECT_DOCUMENTATION.md`](docs/FYP_PROJECT_DOCUMENTATION.md#0-current-implementation-status)
for the full status).

This is a real-time tool: every capture, join, scan, fingerprint probe, and
exploit check talks to live hardware and live networks/devices — there is
no synthetic/demo data path.

## Prerequisites

- Python 3.12+
- Two WiFi radios: one capable of monitor mode (e.g. Alfa AWUS036ACM,
  `config.WIFI_IFACE`) for beacon capture, and one in managed mode (e.g. the
  Pi's built-in adapter, `config.JOIN_IFACE`) for joining a target network to
  run device discovery.
- `nmcli`, `arp-scan`, and `nmap` available on the host (Nmap's OS detection
  (`-O`) needs root). `arp-scan` is used over a hand-rolled Scapy sweep for
  M1 host discovery — verified on a real ~8k-address subnet that Scapy's
  Python-level reply matching can't keep up with the reply volume, while
  `arp-scan` sweeps it completely in ~30s.
- **Root.** `iw` (channel hopping/monitor mode), scapy's raw-socket beacon
  sniffing, and `arp-scan` all need `CAP_NET_ADMIN`/`CAP_NET_RAW` — run the
  whole app as root (see [Running](#running)), not just the pieces that
  "look privileged."
- RouterSploit (M4) needs two Python-3.13 compatibility shims already
  pinned in `requirements.txt` — `setuptools<81` (recent setuptools dropped
  `pkg_resources`, which RouterSploit's wordlist loader imports) and
  `standard-telnetlib` (stdlib `telnetlib` was removed in 3.13, and
  RouterSploit's shell module still imports it unconditionally). Nothing
  extra to do — `pip install -r requirements.txt` handles it — but if you
  ever see `ModuleNotFoundError: pkg_resources` or `No module named
  'telnetlib'`, that's why.

## Setup

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
# for running tests / linting too:
pip install -r requirements-dev.txt
```

## Running

Put your monitor-mode adapter (`config.WIFI_IFACE`) into monitor mode
**before** starting the dashboard:

```bash
sudo nmcli device set <iface> managed no   # stop NetworkManager reclaiming it
sudo ip link set <iface> down
sudo iw dev <iface> set type monitor
sudo ip link set <iface> up
```

The `nmcli ... managed no` step matters more than it looks: without it,
NetworkManager silently reconnects the adapter back to managed mode the
moment you bring the link up, and a scan will complete with `status: done`,
zero errors logged, and zero beacons captured — the channel-hop/sniff code
runs fine, it's just quietly sniffing on a managed-mode socket that never
sees a raw 802.11 frame. If a scan finishes clean but empty, check `iw dev
<iface> info` still says `type monitor` and `nmcli device status` still
says `unmanaged` for it. (It reverts to `managed` on reboot — redo this
after every reboot, not just once.)

Then start the dashboard **as root** (needed for `iw`/raw-socket capture —
see Prerequisites):

```bash
sudo venv/bin/python run.py
```

Open `http://localhost:5000` and click **Start Scan** to capture real
beacons on `config.WIFI_IFACE` (override the interface/duration in the
form). You'll be taken to the session detail page with scored networks:

- **Check CVEs** — on-demand live NVD lookup for that network's vendor,
  enriched with a FIRST.org EPSS score, CISA KEV listing, and a combined
  0–100 ExploitScore. Click again any time to **Recheck** — this refreshes
  the existing row rather than appending a duplicate.
- **Join & Discover Devices** — enter that network's real WiFi password to
  join it on `config.JOIN_IFACE`, then ARP-sweep, Nmap-scan, and mDNS-query
  the joined subnet for live devices (IP, MAC, vendor, open ports, OS
  guess, self-announced name/device type). This disconnects the join
  interface from whatever it's currently on. Per device, from there:
  - **Fingerprint** — probes MQTT/CoAP/HTTP/RTSP behavior on the device's
    open ports and fuses the signals (plus any mDNS-derived type) into a
    device-type + confidence.
  - **Check CVEs** — same NVD+EPSS+KEV+ExploitScore lookup as networks,
    keyed off the device's Nmap OS guess.
  - **Verify Exploit** (per CVE, once found) — searches RouterSploit's
    module index for a match, then requires a named operator, an explicit
    authorization checkbox, and a mandatory 5-second countdown before
    either a safe **check-only** or a real **full-exploit** run becomes
    clickable. Every attempt is logged to `exploit_results` regardless of
    outcome. **Only ever point this at a device you own or have explicit
    authorization to test** — RouterSploit's `check()` is non-destructive,
    but `run()` performs a real exploitation attempt.

Both can also be run headlessly from the CLI (same root requirement as above):

```bash
sudo venv/bin/python run.py --scan --iface wlan1 --duration 30
sudo venv/bin/python run.py --join-network "SomeSSID" --password "..." --join-iface wlan0
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
  m1/       — network join + device discovery: ARP sweep, Nmap port/OS scan, mDNS ID (implemented)
  m2/       — protocol behavioral fingerprinting: MQTT/CoAP/HTTP/RTSP (implemented)
  m3/       — device CVE correlation: NVD + EPSS + CISA KEV + ExploitScore (implemented)
  m4/       — authorized RouterSploit exploit verification (implemented)
  m5/       — Flask dashboard (implemented)
  aws/      — cloud integration (planned)
docs/       — full project documentation, SRS, literature survey
```

## Documentation

- [`docs/FYP_PROJECT_DOCUMENTATION.md`](docs/FYP_PROJECT_DOCUMENTATION.md) — full system design and research documentation
- [`docs/PISA_SRS.md`](docs/PISA_SRS.md) — formal Software Requirements Specification
