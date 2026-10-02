// Simulated vulnerable IoT device for PISA Module 2 (fingerprinting) and
// Module 3 (CVE correlation) testing. Answers just enough of HTTP, MQTT,
// CoAP, and RTSP to be detected by pisa/m2/*_probe.py, standing in for a
// real IP camera / hub while HW-2 (Alfa adapter) is still unavailable.
//
// A NEO-M9N GPS module is wired to Serial2 (RX2=GPIO16, TX2=GPIO17; only
// GPS-TX -> ESP32-RX2 is required) and its last fix is leaked, unauthenticated,
// from GET /cgi-bin/status.cgi. This is NOT a reproduction of a specific CVE
// (unlike scripts/demo_iot_target.py's CVE-2019-16920, which is exact because
// it has to satisfy RouterSploit's real check() for M4) — this board is only
// exercised through M2/M3, so it's a stand-in for the common real-world
// pattern of IoT cameras/dashcams exposing live location without auth,
// giving M2/M3 an info-disclosure-class finding with a physically
// demonstrable payload (a real lat/lon) instead of just a banner match.
//
// Board: any ESP32 Dev Module. Requires the TinyGPSPlus library (Arduino
// Library Manager) in addition to WiFi.h / WebServer.h / WiFiUdp.h from the
// ESP32 Arduino core.

#include <WiFi.h>
#include <WebServer.h>
#include <WiFiUdp.h>
#include <TinyGPSPlus.h>

// ---- NEO-M9N on Serial2: GPS-TX -> ESP32 GPIO16 (RX2), GPS-RX -> GPIO17 (TX2, optional) ----
static const int GPS_RX_PIN = 16;
static const int GPS_TX_PIN = 17;
static const uint32_t GPS_BAUD = 38400;

TinyGPSPlus gps;
HardwareSerial GpsSerial(2);

// ---- Configure before flashing ----
const char *WIFI_SSID = "root";
const char *WIFI_PASSWORD = "root@123";

const uint16_t HTTP_PORT = 80;
const uint16_t MQTT_PORT = 1883;
const uint16_t RTSP_PORT = 554;
const uint16_t COAP_PORT = 5683;

WebServer httpServer(HTTP_PORT);
WiFiServer mqttServer(MQTT_PORT);
WiFiServer rtspServer(RTSP_PORT);
WiFiUDP coapUdp;

// ---------------- HTTP: banner + "camera" keyword ----------------
void handleHttpRoot() {
  httpServer.sendHeader("Server", "GoAhead-Webs");
  httpServer.send(200, "text/html",
                   "<html><head><title>IP Camera Web Interface</title></head>"
                   "<body><h1>Camera Login</h1></body></html>");
}

// ---------------- HTTP: unauthenticated GPS location leak ----------------
// No login/session is checked here — that's the point of the demo finding:
// a would-be attacker can hit this without credentials and get the
// device's live coordinates.
void handleHttpStatusCgi() {
  httpServer.sendHeader("Server", "GoAhead-Webs");
  if (!gps.location.isValid()) {
    httpServer.send(200, "application/json", "{\"gps_fix\":false}");
    return;
  }
  String body = "{\"gps_fix\":true,\"lat\":" + String(gps.location.lat(), 6) +
                ",\"lon\":" + String(gps.location.lng(), 6) +
                ",\"alt_m\":" + String(gps.altitude.meters(), 1) +
                ",\"sats\":" + String(gps.satellites.value()) +
                ",\"age_ms\":" + String(gps.location.age()) + "}";
  httpServer.send(200, "application/json", body);
}

// Feed any bytes waiting on the NEO-M9N's UART into the NMEA parser. Called
// from loop() so gps.location always reflects the most recent fix.
void serviceGps() {
  while (GpsSerial.available()) {
    gps.encode(GpsSerial.read());
  }
}

// ---------------- MQTT: reply to CONNECT with CONNACK ----------------
void serviceMqtt() {
  WiFiClient client = mqttServer.available();
  if (!client) return;

  unsigned long deadline = millis() + 2000;
  while (client.connected() && !client.available() && millis() < deadline) {
    delay(10);
  }
  if (client.available() && (client.peek() & 0xF0) == 0x10) {  // CONNECT packet
    client.read();  // discard the byte we peeked
    // Drain the rest of the CONNECT packet (we don't need to parse it).
    while (client.available()) client.read();

    uint8_t connack[] = {0x20, 0x02, 0x00, 0x00};  // CONNACK, session-present=0, reason=0 (success)
    client.write(connack, sizeof(connack));
  }
  client.stop();
}

// ---------------- RTSP: reply to OPTIONS ----------------
void serviceRtsp() {
  WiFiClient client = rtspServer.available();
  if (!client) return;

  unsigned long deadline = millis() + 2000;
  while (client.connected() && !client.available() && millis() < deadline) {
    delay(10);
  }
  String request = client.readStringUntil('\n');
  if (request.startsWith("OPTIONS")) {
    client.print(
        "RTSP/1.0 200 OK\r\n"
        "CSeq: 1\r\n"
        "Server: IPCam-RTSP/1.0\r\n"
        "Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN, PAUSE\r\n"
        "\r\n");
  }
  client.stop();
}

// ---------------- CoAP: reply to GET /.well-known/core ----------------
void serviceCoap() {
  int packetSize = coapUdp.parsePacket();
  if (packetSize <= 4) return;

  uint8_t buf[64];
  int len = coapUdp.read(buf, sizeof(buf));
  if (len < 4) return;

  uint8_t tkl = buf[0] & 0x0F;
  uint8_t messageIdHi = buf[2];
  uint8_t messageIdLo = buf[3];

  // Header (4) + token (tkl, up to 15 per the 0x0F mask above) + payload
  // marker (1) + the 97-byte resource-discovery payload below: 64 bytes
  // overflowed this on every real CoAP GET, smashing the stack canary and
  // rebooting the board (found by testing M2's coap_probe against real
  // hardware, not by the mocked unit tests).
  uint8_t response[128];
  int idx = 0;
  response[idx++] = 0x60 | tkl;  // Ver=1, Type=ACK, same TKL
  response[idx++] = 0x45;        // Code 2.05 Content
  response[idx++] = messageIdHi;
  response[idx++] = messageIdLo;
  for (int i = 0; i < tkl && (4 + i) < len; i++) {
    response[idx++] = buf[4 + i];  // echo token
  }
  response[idx++] = 0xFF;  // payload marker

  const char *payload =
      "</sensors/temperature>;rt=\"temperature\";if=\"sensor\","
      "</sensors/humidity>;rt=\"humidity\";if=\"sensor\"";
  int payloadLen = strlen(payload);
  memcpy(response + idx, payload, payloadLen);
  idx += payloadLen;

  coapUdp.beginPacket(coapUdp.remoteIP(), coapUdp.remotePort());
  coapUdp.write(response, idx);
  coapUdp.endPacket();
}

void setup() {
  Serial.begin(115200);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.print("\nConnected, IP: ");
  Serial.println(WiFi.localIP());

  httpServer.on("/", handleHttpRoot);
  httpServer.on("/cgi-bin/status.cgi", handleHttpStatusCgi);
  httpServer.begin();

  mqttServer.begin();
  rtspServer.begin();
  coapUdp.begin(COAP_PORT);

  GpsSerial.begin(GPS_BAUD, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);

  Serial.println("Simulated IoT target up: HTTP:80 MQTT:1883 RTSP:554 CoAP:5683");
  Serial.println("GPS: waiting for NEO-M9N fix on Serial2 (GET /cgi-bin/status.cgi to read it)");
}

void loop() {
  httpServer.handleClient();
  serviceMqtt();
  serviceRtsp();
  serviceCoap();
  serviceGps();
}
