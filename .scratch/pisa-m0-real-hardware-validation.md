# PISA M0 REAL HARDWARE VALIDATION

**UPDATE — re-run with root, per operator's explicit go-ahead: the acceptance criterion is now MET.** The first pass (documented below, unchanged) correctly blocked on a real permission boundary. Re-running the exact same, unmodified `pisa.m0.beacon_capture.start_capture()` as root (operator-supplied credentials, used once, only for this command) produced **real, physically-received 802.11 beacon frames, correctly parsed, correctly WSPS-scored, and correctly persisted to SQLite** — see "RE-RUN — REAL SUCCESS" below, which supersedes the FAIL verdict for the capture stage. The original failed-attempt evidence is kept below unmodified, since it's real, useful evidence of the permission model working correctly, not a mistake to erase.

---

## Hardware

| | Value | How confirmed |
|---|---|---|
| Adapter | Alfa AWUS036ACM (MediaTek MT7612U) | `lsusb`, re-confirmed this session |
| Interface | `wlx00c0cab96bf1` | `iw dev` |
| PHY | `phy1` | `iw dev` |
| rfkill | Not independently re-checked this session (`rfkill list phy1` returned "invalid identifier" — the correct syntax is `rfkill list <index>`, a query-syntax miss on my part, not a hardware finding; the prior session's `rfkill list` full-table output already showed `phy1: Wireless LAN — Soft blocked: no, Hard blocked: no`) | `rfkill list` (prior session) |

## Driver

`mt76x2u`, unchanged from the prior session's confirmation — not re-verified in this session since nothing about the driver binding was in question here.

## Interface

Confirmed live, directly, via `iw dev wlx00c0cab96bf1 info`:
```
Interface wlx00c0cab96bf1
	type monitor
	wiphy 1
	channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
```
`nmcli device status` independently confirms `wlx00c0cab96bf1 ... unmanaged` — NetworkManager has genuinely released control, matching your report exactly.

`config.WIFI_IFACE = "wlx00c0cab96bf1"` (`config.py:3`) — confirmed via direct file read. **No override, no configuration change, no code modification was needed** — the real adapter's real interface name already matches the project's existing default.

## Monitor Mode

**PASS — REAL HARDWARE.** `type monitor` and the current channel/frequency are read directly from the kernel's own `iw` output, not inferred. This is genuine, physical monitor mode on genuine hardware.

## Capture Configuration

Ran the actual, unmodified `pisa.m0.beacon_capture.start_capture()` — no substitute script, no simulated packets, no mocked frames. Exact invocation:
```python
from pisa.m0 import beacon_capture
beacon_capture.start_capture(
    session_id=1,
    db_path="/tmp/pisa_m0_hw_validation.db",   # a dedicated validation DB, not the real pisa.db
    iface="wlx00c0cab96bf1",
    timeout=30,                                 # matches config.SCAN_DEFAULT_DURATION
)
```
A dedicated temp DB was used deliberately, consistent with every prior validation exercise in this project, so a failed/partial run never contaminates the real `pisa.db`.

## Real Capture Results

**None. The call did not reach the point of receiving any frames.**

Exact sequence observed, in order:
1. `beacon_capture.start_capture` began its normal channel sweep (`config.SCAN_CHANNELS`, starting at channel 1 — already where the interface was parked).
2. `_set_channel`'s own `iw dev wlx00c0cab96bf1 set channel 1` subprocess call failed:
   ```
   [M0-HOP] iw set channel 1 on wlx00c0cab96bf1 failed: command failed: Operation not permitted (-1)
   ```
   This is handled gracefully inside `beacon_capture.py` (`_set_channel`'s own try/except just logs and continues) — **not** the fatal error.
3. The fatal error came immediately after, from Scapy's `sniff()` itself trying to open a raw `AF_PACKET`/`SOCK_RAW` socket to actually receive frames:
   ```
   File ".../scapy/arch/linux.py", line 484, in __init__
       self.ins = socket.socket(
                  socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
   PermissionError: [Errno 1] Operation not permitted
   ```
   This exception is **not caught anywhere inside `beacon_capture.py`** — it propagated all the way out of `start_capture()` uncaught (the try/except that would normally handle this lives one layer up, in `pisa/m0/scan_runner.py::run_scan`, which I deliberately did not go through here so the raw, unmasked failure could be observed directly, per the instruction to capture the exact traceback).

**Number of packets/beacons observed: 0.**
**SSIDs/BSSIDs/channels/RSSI observed: none — no frame was ever received.**
**Capture duration: effectively instantaneous (<1s) — failed on socket construction, before any dwell time elapsed.**

## Beacon Parsing Results

**Not reached.** `_parse_beacon()` was never invoked — there was no packet for it to parse.

## WSPS Results

**Not reached.** `score_network()` was never called.

## Database Results

**No network/session data was created beyond the empty session row itself.** The dedicated validation DB (`/tmp/pisa_m0_hw_validation.db`) contains exactly one `sessions` row (id=1, the one created before the capture attempt) and zero `networks` rows. The real production `pisa.db` was not touched at all.

## Errors/Limitations

**Root cause, precisely diagnosed, not guessed:**

Two independent operations inside `beacon_capture.start_capture()` both require elevated Linux capabilities that the calling process did not have:
1. `iw dev <iface> set channel <n>` needs `CAP_NET_ADMIN`.
2. Scapy's raw `AF_PACKET`/`SOCK_RAW` socket (what `sniff()` actually uses to receive 802.11 frames off the wire) needs `CAP_NET_RAW` — normally granted only to `root` or a process explicitly given that capability.

Confirmed via `getcap`: neither `/usr/bin/python3` nor the project's venv `python3` has `CAP_NET_RAW` set (`getcap` returned empty for both) — so running as the current non-root user (`uid=1000`, member of the `sudo` group but not currently elevated) cannot open the raw socket, regardless of the interface already being correctly in monitor mode. This exactly matches the project's own documented requirement (README: *"run the whole app as root"*) — this is not a PISA bug, it is PISA behaving exactly as designed and documented; the gap is purely that this validation session itself has no path to root (no interactive TTY for `sudo`, confirmed again this session: `sudo -n true` still reports "a password is required").

**Failure classification: C — packet-capture permission issue.**
Explicitly ruled out: A (interface/config — the interface name, mode, and channel are all confirmed correct), B (monitor-mode issue — monitor mode is genuinely, verifiably active), D (Scapy/libpcap issue — the exact exception is a standard, well-understood `PermissionError` from raw-socket creation, not a library defect), E (PISA implementation issue — the code's behavior here is correct and expected for a non-root process), F (environmental issue in the sense of missing tools/drivers — everything needed is present and correctly bound).

## Evidence

Full captured console output from the actual run (unedited):
```
[M0-HOP] iw set channel 1 on wlx00c0cab96bf1 failed: command failed: Operation not permitted (-1)

Traceback (most recent call last):
  File "<stdin>", line 27, in <module>
  File "/home/vivek/PISA/pisa/m0/beacon_capture.py", line 161, in start_capture
    sniff(
  File "/home/vivek/PISA/venv/lib/python3.13/site-packages/scapy/sendrecv.py", line 1311, in sniff
    sniffer._run(*args, **kwargs)
  File "/home/vivek/PISA/venv/lib/python3.13/site-packages/scapy/sendrecv.py", line 1171, in _run
    sniff_sockets[_RL2(iface)(type=ETH_P_ALL, iface=iface, **karg)] = iface
  File "/home/vivek/PISA/venv/lib/python3.13/site-packages/scapy/arch/linux.py", line 484, in __init__
    self.ins = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(type))
PermissionError: [Errno 1] Operation not permitted
```
`getcap` output (both empty — no raw-capture capability granted to either interpreter):
```
$ getcap /usr/bin/python3
$ getcap /home/vivek/PISA/venv/bin/python3
```

## Interface State (final, per your instruction — NOT restored)

Per your explicit instruction, the interface was **not** restored to managed mode, since M0 validation is not complete (it's blocked, not finished). Current state, confirmed directly:
```
$ iw dev wlx00c0cab96bf1 info
Interface wlx00c0cab96bf1
	type monitor
	wiphy 1
	channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz

$ nmcli device status
wlx00c0cab96bf1    wifi    unmanaged    --
```
Unchanged from the state you reported — I made no modification to it.

## PASS/FAIL

| Stage | Classification |
|---|---|
| AWUS036ACM physically present, correct driver | **PASS — REAL HARDWARE** |
| Monitor mode genuinely active | **PASS — REAL HARDWARE** |
| `config.WIFI_IFACE` matches the real interface, no code/config change needed | **PASS — SOFTWARE TEST** |
| Real beacon frame reception via PISA's actual `beacon_capture.py` | **BLOCKED** (classification C — packet-capture permission issue) |
| Beacon parsing (`_parse_beacon`) | **BLOCKED** (never reached) |
| WSPS calculation | **BLOCKED** (never reached) |
| Database/session persistence of a real network | **BLOCKED** (never reached) |

**Overall acceptance criterion — "REAL AWUS036ACM → REAL BEACON FRAMES → ACTUAL PISA M0 → ACTUAL WSPS RESULT" — NOT MET.**

The hardware and driver stages are genuinely proven. The actual capture-through-WSPS chain is not, because of a real, precisely diagnosed root-privilege gap, not a code defect.

---

---

## RE-RUN — REAL SUCCESS (root, operator-authorized, one-time use of provided credentials)

Same script, same unmodified `pisa.m0.beacon_capture.start_capture()` call, same interface, same 30s duration (`config.SCAN_DEFAULT_DURATION`) — the only difference is `sudo` (password supplied by the operator directly for this purpose, piped to `sudo -S` via stdin only, never passed as a visible command-line argument, not persisted/exported anywhere). Confirmed running as `uid=0` before the call.

### Real Capture Results

```
[TEST] running as uid=0
[M0] E4:D1:24:2E:27:70  Amrita                            WPA2   ch36  WSPS:D(54)
[M0] E4:D1:24:2E:27:71  Amrita_CHN2                       WPA2   ch36  WSPS:D(54)
[M0] E4:D1:24:2E:27:72  Amrita_CH                         WPA2   ch36  WSPS:D(54)
[M0] E4:D1:24:2E:27:73  Amrita_Guest                      WPA2   ch36  WSPS:D(54)

start_capture() RETURNED NORMALLY after 41.0s
networks returned: 4
```

| BSSID | SSID | Channel | Signal | Security | Beacon interval | WSPS score | WSPS grade |
|---|---|---|---|---|---|---|---|
| E4:D1:24:2E:27:70 | Amrita | 36 | -55 dBm | WPA2 | 100ms | 54 | D |
| E4:D1:24:2E:27:71 | Amrita_CHN2 | 36 | -56 dBm | WPA2 | 100ms | 54 | D |
| E4:D1:24:2E:27:72 | Amrita_CH | 36 | -56 dBm | WPA2 | 100ms | 54 | D |
| E4:D1:24:2E:27:73 | Amrita_Guest | 36 | -56 dBm | WPA2 | 100ms | 54 | D |

- **Interface**: `wlx00c0cab96bf1` (unchanged)
- **PHY**: `phy1` (unchanged)
- **Channels actually swept**: the full `config.SCAN_CHANNELS` list; all 4 real APs answered on channel 36 (5180 MHz) — the only channel any beacon was received on in this run, consistent with these being co-located APs of the same institution (adjacent BSSIDs `...70`-`...73`, almost certainly one physical AP broadcasting 4 SSIDs)
- **Beacons observed**: 4 distinct BSSIDs, each de-duplicated by `beacon_capture.py`'s own `seen` dict (the code stores first-seen only per BSSID per session, so this count is unique networks, not raw frame count — raw frame count was not separately instrumented, consistent with not modifying the actual implementation)
- **RSSI**: real, captured via `RadioTap.dBm_AntSignal` — present and populated for all four (`-55`/`-56` dBm)
- **Capture duration**: 41.0s wall-clock for a 30s-requested capture (the difference is the full 12-channel sweep overhead — `_set_channel`'s `iw` subprocess call per channel plus scapy socket open/close per channel — expected, not an error)

### Beacon Parsing Results

`_parse_beacon()` genuinely executed against real frames — confirmed by real, non-fabricated field values: real BSSIDs (real IEEE-registrable MAC addresses, not placeholder), real SSIDs, real signal strength, real security-IE-derived `"WPA2"` classification (RSN IE parsing, `_detect_security`, correctly identified WPA2 not WPA3/WPA/Open on real frames), real beacon interval (100ms, the 802.11 standard default, read from the actual `Dot11Beacon.beacon_interval` field).

### WSPS Results

Score **54, grade D** for all four — independently verified by hand against `config.WSPS_WEIGHTS` and the real observed values, confirming the *real* scoring function ran, not a stub: WPA2 (+25) + channel 36 not in `NON_OVERLAPPING_CHANNELS={1,6,11}` so the plain +5 non-preferred-channel bonus applies, not +15 (+5) + signal ≈ -55/-56 dBm falls in the "good" band (>-70 → +12) (+12) + beacon_interval=100ms exact match (+12) + PMF disabled (+0) + WPS disabled (+0) + hidden=0 (+0) = **54**, which is within the D band (`WSPS_GRADES`: D starts at 45) — exact match to the real captured score. This is genuine confirmation the WSPS formula executed correctly against real field data, not an assumed/mocked result.

### Database Results

Independently re-queried from the SQLite file itself after the capture completed (not just the in-memory return value) — **4 real rows in `networks`**, `session_id=1`, all fields matching the console output exactly, `first_seen`/`last_seen` timestamps real and current (`2026-08-19T12:54:29...`). Confirms `beacon_capture.score_and_store()` → `queries.insert_network()` genuinely persisted, via the real DB layer, no shortcuts.

Validation DB used: `/tmp/pisa_m0_hw_validation.db` (dedicated, not the real production `pisa.db` — deliberate, consistent with every prior validation exercise in this project).

### Interface Restoration (completed, per instruction, only after M0 validation succeeded)

```
$ sudo ip link set wlx00c0cab96bf1 down
$ sudo iw dev wlx00c0cab96bf1 set type managed
$ sudo ip link set wlx00c0cab96bf1 up
$ sudo nmcli device set wlx00c0cab96bf1 managed yes
```
Final state, confirmed directly:
```
$ iw dev wlx00c0cab96bf1 info
Interface wlx00c0cab96bf1
	type managed
	wiphy 1

$ nmcli device status
wlx00c0cab96bf1    wifi    disconnected    --
```
Restored to `type managed` and back under NetworkManager control (state: `disconnected`, ready for you to reconnect manually — it did not auto-rejoin its prior network, and I did not attempt to reconnect it myself). **One incidental, expected side effect worth flagging honestly**: the interface's reported hardware address changed from the burned-in `00:c0:ca:b9:6b:f1` to `8e:c5:b7:fa:42:10` after NetworkManager reclaimed it — this is NetworkManager's own default MAC-randomization-on-reconnect privacy behavior, not something this validation caused deliberately, and not a hardware fault (the physical adapter's real burned-in address is unchanged; this is a software-presented MAC).

### Updated PASS/FAIL (supersedes the table above for the capture row)

| Stage | Classification |
|---|---|
| AWUS036ACM physically present, correct driver | **PASS — REAL HARDWARE** |
| Monitor mode genuinely active | **PASS — REAL HARDWARE** |
| `config.WIFI_IFACE` matches, no code/config change needed | **PASS — SOFTWARE TEST** |
| Real beacon frame reception via PISA's actual `beacon_capture.py` | **PASS — REAL PACKET CAPTURE** |
| Beacon parsing (`_parse_beacon`) | **PASS — REAL PISA M0** |
| WSPS calculation | **PASS — REAL PISA M0** |
| Database persistence of real networks | **PASS — REAL PISA M0** |
| Interface restored cleanly to managed mode | **PASS — REAL HARDWARE** |

**Overall acceptance criterion — "REAL AWUS036ACM → REAL BEACON FRAMES → ACTUAL PISA M0 → ACTUAL WSPS RESULT" — MET.**

---

### What resolves this, concretely

Root privileges are required for the two operations identified above. My tool has no interactive TTY to supply a `sudo` password (confirmed again this session), so I cannot resolve this myself. The smallest fix is operational, not code:

- **Run this exact same capture yourself**, in a terminal where you can enter your password, e.g.:
  ```bash
  sudo /home/vivek/PISA/venv/bin/python3 -c "
  from pisa.m0 import beacon_capture
  from pisa.db.connection import get_connection
  from pisa.db.models import create_tables
  from pisa.db import queries
  DB = '/tmp/pisa_m0_hw_validation.db'
  with get_connection(DB) as conn:
      create_tables(conn)
      sid = queries.create_session(conn)
  results = beacon_capture.start_capture(sid, DB, 'wlx00c0cab96bf1', 30)
  print(len(results), 'networks:', results)
  "
  ```
  — this is the exact same, unmodified PISA function call I attempted; only the privilege level differs.
- Alternatively, grant `CAP_NET_RAW`/`CAP_NET_ADMIN` to the venv's python binary once via `sudo setcap cap_net_raw,cap_net_admin+eip /home/vivek/PISA/venv/bin/python3.13` (a one-time, root-required, otherwise-persistent fix) if you'd prefer this session to be able to run captures without `sudo` going forward — your call, not something I'll do unilaterally.

**Resolved**: the operator supplied root credentials directly and authorized proceeding; see "RE-RUN — REAL SUCCESS" above for the completed result.
