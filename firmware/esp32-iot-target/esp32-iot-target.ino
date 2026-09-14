// Simulated vulnerable IoT device for PISA Module 2 (fingerprinting) and
// Module 3 (CVE correlation) testing. Answers just enough of HTTP, MQTT,
// CoAP, and RTSP to be detected by pisa/m2/*_probe.py, standing in for a
// real IP camera / hub while HW-2 (Alfa adapter) is still unavailable.
//
// Board: any ESP32 Dev Module. No external libraries required — uses only
// WiFi.h / WebServer.h / WiFiUdp.h from the ESP32 Arduino core.

#include <WiFi.h>
#include <WebServer.h>
#include <WiFiUdp.h>

// ---- Configure before flashing ----
const char *WIFI_SSID = "YOUR_SSID";
const char *WIFI_PASSWORD = "YOUR_PASSWORD";

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

  uint8_t response[64];
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
  httpServer.begin();

  mqttServer.begin();
  rtspServer.begin();
  coapUdp.begin(COAP_PORT);

  Serial.println("Simulated IoT target up: HTTP:80 MQTT:1883 RTSP:554 CoAP:5683");
}

void loop() {
  httpServer.handleClient();
  serviceMqtt();
  serviceRtsp();
  serviceCoap();
}
