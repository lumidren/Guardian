/*
  GUARDIAN IoT Security Framework - ESP32 Sensor Node Firmware
  Hardware: ESP32 DevKit v1 + DHT22 / BME280 / PIR Motion Sensor
  Protocol: MQTT over TCP (Port 1883)
  Author: lumidren (GUARDIAN IoT Project)
*/

#include <WiFi.h>
#include <PubSubClient.h>

// Wi-Fi Credentials
const char* ssid = "GUARDIAN_SECURE_IOT";
const char* password = "GuardianPassword2026!";

// Gateway & MQTT Configuration
const char* mqtt_server = "192.168.1.1";
const int mqtt_port = 1883;
const char* device_id = "ESP32_Temp_01";
const char* telemetry_topic = "guardian/sensors/temp_01/telemetry";
const char* status_topic = "guardian/sensors/temp_01/status";

WiFiClient espClient;
PubSubClient client(espClient);

// Sensor simulation & timing
unsigned long lastMsg = 0;
const long interval = 5000; // 5-second reporting cycle
float simulated_temperature = 22.5;
float simulated_humidity = 48.0;

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
  Serial.print("MAC Address: ");
  Serial.println(WiFi.macAddress());
}

void callback(char* topic, byte* payload, unsigned int length) {
  Serial.print("Message received [");
  Serial.print(topic);
  Serial.print("]: ");
  for (int i = 0; i < length; i++) {
    Serial.print((char)payload[i]);
  }
  Serial.println();
}

void reconnect() {
  while (!client.connected()) {
    Serial.print("Attempting MQTT connection to GUARDIAN gateway...");
    String clientId = "ESP32-TempNode-" + String(random(0xffff), HEX);
    
    // Connect with Last Will and Testament (LWT)
    if (client.connect(clientId.c_str(), status_topic, 1, true, "{\"status\":\"OFFLINE\"}")) {
      Serial.println("connected!");
      client.publish(status_topic, "{\"status\":\"ONLINE\",\"device_type\":\"ESP32_Sensor\"}", true);
      client.subscribe("guardian/sensors/temp_01/cmd");
    } else {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      Serial.println(" retrying in 5 seconds...");
      delay(5000);
    }
  }
}

void setup() {
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

    // Small realistic ambient drift
    simulated_temperature += (random(-5, 6) / 10.0);
    simulated_humidity += (random(-8, 9) / 10.0);

    char payload[128];
    snprintf(payload, sizeof(payload), 
      "{\"device\":\"%s\",\"temp\":%.2f,\"humidity\":%.2f,\"rssi\":%d,\"uptime\":%lu}",
      device_id, simulated_temperature, simulated_humidity, WiFi.RSSI(), millis() / 1000
    );

    Serial.print("Publishing telemetry: ");
    Serial.println(payload);
    client.publish(telemetry_topic, payload);
  }
}
