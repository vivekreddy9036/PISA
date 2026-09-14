# ESP32 simulated IoT target

A single ESP32 sketch that answers just enough of HTTP, MQTT, CoAP, and
RTSP to be detected by PISA's Module 2 probes (`pisa/m2/http_probe.py`,
`mqtt_probe.py`, `coap_probe.py`, `rtsp_probe.py`), standing in for a real
IP camera while HW-2 (Alfa AWUS036ACM) is still unavailable.

## 1. Install the ESP32 board package

Arduino IDE → **File → Preferences** → Additional Board Manager URLs:

```
https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
```

Then **Tools → Board → Boards Manager** → search `esp32` → install
(Espressif Systems). No extra libraries needed — the sketch only uses
`WiFi.h`, `WebServer.h`, `WiFiUdp.h` from the core.

## 2. Configure

Open `esp32-iot-target.ino` and set:

```cpp
const char *WIFI_SSID = "YOUR_SSID";
const char *WIFI_PASSWORD = "YOUR_PASSWORD";
```

Use the same network/subnet your PISA host (Raspberry Pi or dev machine)
runs on, so Module 1 (ARP/Nmap discovery) and Module 2 can reach it.

## 3. Flash

**Tools** menu: Board = `ESP32 Dev Module`, Upload Speed = `115200`, Port =
your board's serial port. Hit **Upload**. Open the Serial Monitor at
115200 baud — it prints the assigned IP once connected, e.g.:

```
Connected, IP: 192.168.1.42
Simulated IoT target up: HTTP:80 MQTT:1883 RTSP:554 CoAP:5683
```

## 4. Verify against PISA

From the repo root, with the ESP32's IP:

```bash
python -c "from pisa.m2.http_probe import probe; print(probe('192.168.1.42', 80, 3))"
python -c "from pisa.m2.mqtt_probe import probe; print(probe('192.168.1.42', 1883, 3))"
python -c "from pisa.m2.coap_probe import probe; print(probe('192.168.1.42', 5683, 3))"
python -c "from pisa.m2.rtsp_probe import probe; print(probe('192.168.1.42', 554, 3))"
```

Each should return a non-empty feature list (HTTP: `device_type_hint="IP
Camera"` via the "camera" keyword; MQTT: `reason_code=0`; CoAP: the
`/sensors/...` link-format payload; RTSP: the `RTSP/1.0` status line +
`Server` header). Or point `fingerprint_runner.py` at the IP directly to
exercise the full cross-protocol fusion path.

## Notes / limitations

- This is a **fingerprinting target only** — it doesn't implement a real
  MQTT broker, CoAP server, or RTSP media stream, just the minimum
  handshake each probe checks for. Don't expect a real MQTT client to
  publish/subscribe against it.
- The `Server: GoAhead-Webs` HTTP banner is deliberately realistic (a
  real embedded web server historically bundled in IP cameras with known
  CVEs) so Module 3's CVE correlation has something plausible to match
  against — swap it for other banners to test different device profiles.
- This does **not** replace the Alfa AWUS036ACM adapter — it has nothing
  to do with WiFi monitor mode / beacon capture (Module 0). It only helps
  validate Module 2/3 against a real network endpoint.
