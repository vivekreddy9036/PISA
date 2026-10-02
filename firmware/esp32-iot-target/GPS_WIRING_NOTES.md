# NEO-M9N GPS wiring notes (ESP32 IoT target)

Session notes from swapping the demo GPS module from NEO-6M to a 7Semi
NEO-M9N breakout. Kept here so the setup can be picked up again from
another machine (e.g. continuing power work on the RPi).

## Confirmed working wiring (UART mode)

| NEO-M9N pin | Connects to | Notes |
|---|---|---|
| 5V | ESP32 5V (or RPi 5V, see below) | board has onboard regulator, needs 4.2–5.5V in |
| GND | ESP32 GND | common ground, mandatory |
| TX/MISO | ESP32 GPIO16 (RX2) | module → ESP32, required |
| RX/MOSI | ESP32 GPIO17 (TX2) | ESP32 → module, optional |
| 3V3, SDA, SCL, PPS, RST | not connected | 3V3 is a regulated *output*, not an input — don't feed power into it |

Verified by flashing a standalone passthrough test sketch (Serial2 →
USB serial) and capturing real NMEA sentences:

```
$GNRMC,,V,,,,,,,,,,N,V*37
$GNVTG,,,,,,,,,N*2E
$GNGGA,,,,,,0,00,99.99,,,,,,*56
```

(`V`/`00` = no satellite fix yet, just confirms the UART link itself works.)

## Firmware change

`esp32-iot-target.ino` originally targeted a NEO-6M at 9600 baud. The
NEO-M9N defaults to **38400 baud** on UART1. Updated:
- `GPS_BAUD` from `9600` → `38400` (esp32-iot-target.ino:28)
- comments/log strings from "NEO-6M" → "NEO-M9N"

## Known issue: brownout / reset loop

After wiring the M9N directly to the ESP32's own 5V pin (USB-derived,
not separately regulated), the board started crash-resetting in a
tight loop — serial output showed only a repeating tail fragment of
one `Serial.println()` call, consistent with the UART getting reset
mid-transmission on a fast, regular cycle. Likely cause: GPS module
current draw (higher during satellite search) + WiFi TX bursts
together sagging the ESP32's USB-supplied 5V rail past its brownout
threshold.

Did **not** confirm this by reading `Brownout detector was triggered`
directly (scripted serial captures from the dev machine were
unreliable — see below), but the symptom pattern matches it closely.

### Planned fix (in progress)

Power the GPS module from the **RPi's 5V pin** instead of the ESP32's,
with RPi fed by a direct USB-C wall connection (not a laptop port/hub)
for a stable supply. Data lines stay on the ESP32:

| NEO-M9N pin | Connects to |
|---|---|
| 5V | RPi 5V (physical pin 2 or 4) |
| GND | RPi GND **and** ESP32 GND (both — shared ground is mandatory for the UART link to work) |
| TX/MISO | ESP32 GPIO16 |
| RX/MOSI | ESP32 GPIO17 |

Not yet verified end-to-end after this change.

## Network note

The ESP32 firmware joins WiFi SSID `"root"` (esp32-iot-target.ino:34-35).
The dev machine used for this session was on a different network
(`Amrita_CHN2`), so `/cgi-bin/status.cgi` couldn't be checked over HTTP
from there — needs a device actually on the `"root"` network, or the
dev machine switched onto it.

## How to check GPS fix status once running

From a device on the same WiFi network as the ESP32:
```
curl http://<esp32-ip>/cgi-bin/status.cgi
```
Returns `{"gps_fix":false}` until a fix, then
`{"gps_fix":true,"lat":...,"lon":...,"alt_m":...,"sats":...,"age_ms":...}`.

## Serial monitor (CLI)

```bash
arduino-cli monitor -p /dev/ttyUSB0 -c baudrate=115200
```
Press the board's EN/RESET button after starting the monitor. If that
tool's reset handling is flaky (it was, on this board), fall back to:
```bash
screen /dev/ttyUSB0 115200
```
