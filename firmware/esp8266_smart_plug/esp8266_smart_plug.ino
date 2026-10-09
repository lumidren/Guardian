/*
  GUARDIAN IoT Security Framework - ESP8266 Smart Plug & Relay Node Firmware
  Hardware: ESP8266 (NodeMCU / Sonoff S20 / Relay Module)
  Protocol: MQTT over TCP (Port 1883)
  Author: lumidren (GUARDIAN IoT Project)
*/

#include <ESP8266WiFi.h>
#include <PubSubClient.h>

// Wi-Fi Credentials
const char* ssid = "GUARDIAN_SECURE_IOT";
const char* password = "GuardianPassword2026!";

// Gateway & MQTT Configuration
const char* mqtt_server = "192.168.1.1";
const int mqtt_port = 1883;
const char* device_id = "ESP8266_Plug_01";
const char* telemetry_topic = "guardian/actuators/plug_01/telemetry";
const char* command_topic = "guardian/actuators/plug_01/switch";

#define RELAY_PIN 12 // GPIO12 controls relay switch
#define LED_PIN 13   // GPIO13 status LED

WiFiClient espClient;
PubSubClient client(espClient);

unsigned long lastMsg = 0;
const long interval = 10000; // 10-second heartbeat
bool relay_state = true;
float power_watts = 42.5;

void setup_wifi() {
  delay(10);
  Serial.print("Connecting to Wi-Fi: ");
  Serial.println(ssid);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nWi-Fi connected.");
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());
}

void callback(char* topic, byte* payload, unsigned int length) {
  String message = "";
  for (int i = 0; i < length; i++) {
    message += (char)payload[i];
  }
  Serial.print("Command received [");
  Serial.print(topic);
  Serial.print("]: ");
  Serial.println(message);

  if (message == "ON") {
    relay_state = true;
    digitalWrite(RELAY_PIN, HIGH);
    digitalWrite(LED_PIN, LOW);
  } else if (message == "OFF") {
    relay_state = false;
    digitalWrite(RELAY_PIN, LOW);
    digitalWrite(LED_PIN, HIGH);
  }
}

void reconnect() {
  while (!client.connected()) {
    Serial.print("Attempting MQTT connection to GUARDIAN gateway...");
    String clientId = "ESP8266-Plug-" + String(random(0xffff), HEX);
    if (client.connect(clientId.c_str())) {
      Serial.println("connected!");
      client.subscribe(command_topic);
    } else {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      Serial.println(" retrying in 5 seconds...");
      delay(5000);
    }
  }
}

void setup() {
  pinMode(RELAY_PIN, OUTPUT);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, relay_state ? HIGH : LOW);
  Serial.begin(115200);
  setup_wifi();
  client.setServer(mqtt_server, mqtt_port);
  client.setCallback(callback);
}

void loop() {
  if (!client.connected()) {
    reconnect();
  }
  client.loop();

  unsigned long now = millis();
  if (now - lastMsg > interval) {
    lastMsg = now;

    power_watts = relay_state ? (40.0 + (random(0, 50) / 10.0)) : 0.0;
    char payload[128];
    snprintf(payload, sizeof(payload),
      "{\"device\":\"%s\",\"relay\":%s,\"power_w\":%.1f,\"voltage\":230.0}",
      device_id, relay_state ? "true" : "false", power_watts
    );

    client.publish(telemetry_topic, payload);
  }
}
