// ESP-01 door actuator. Pulses GPIO2 (active low) for a signed open command.
// Check order matches contract/policy.js classifyOpen.

#include <Arduino.h>
#include <ArduinoJson.h>
#include <EEPROM.h>
#include <ESP8266WiFi.h>
#include <MQTT.h>
#include <bearssl/bearssl_hmac.h>
#include <esp8266_peri.h>
#include <time.h>

#include "secrets.h"

static const char *FW = "0.1.0";
static const char *TOPIC_OPEN = "door/actuator/open";
static const char *TOPIC_RESULT = "door/actuator/result";
static const char *TOPIC_STATUS = "door/actuator/status";
static const char *LWT = "{\"online\":false,\"reason\":\"lwt\"}";

static const int RELAY_PIN = 2;
static const uint32_t HEARTBEAT_MS = 30000;
static const int32_t OPEN_MIN_MS = 200;
static const int32_t OPEN_MAX_MS = 10000;
static const int32_t OPEN_SKEW_S = 30;
static const int NONCE_SLOTS = 32;
static const uint32_t NONCE_MAGIC = 0x314E4F4Eu;
static const time_t TIME_FLOOR = 1700000000;

static const uint8_t KEY_LEN = 32;

struct NonceStore {
  uint32_t magic;
  uint8_t next;
  uint8_t filled;
  uint8_t nonce[NONCE_SLOTS][16];
};

static NonceStore nonceStore;
static uint8_t hmacKey[KEY_LEN];
static bool keyOk = false;

static WiFiClient net;
static MQTTClient mqtt(768);

static char rx[640];
static volatile bool rxReady = false;

static char pendingResult[192];
static bool resultPending = false;

static bool pulseOn = false;
static uint32_t pulseStart = 0;
static uint32_t pulseMs = 0;

static uint32_t lastWifiTry = 0;
static uint32_t lastMqttTry = 0;
static uint32_t lastStatus = 0;
static bool statusDue = false;
static bool ntpStarted = false;

static StaticJsonDocument<640> doc;

static int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

static bool isHex(const char *s, size_t n) {
  if (!s) return false;
  for (size_t i = 0; i < n; i++) {
    if (hexNibble(s[i]) < 0) return false;
  }
  return s[n] == '\0';
}

static bool hexToBytes(const char *hex, uint8_t *out, size_t bytes) {
  for (size_t i = 0; i < bytes; i++) {
    int hi = hexNibble(hex[i * 2]);
    int lo = hexNibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

static bool decodeKey() {
  return isHex(DOOR_HMAC_SECRET, KEY_LEN * 2) && hexToBytes(DOOR_HMAC_SECRET, hmacKey, KEY_LEN);
}

static void hmacSha256(const char *msg, uint8_t out[32]) {
  br_hmac_key_context kc;
  br_hmac_context ctx;
  br_hmac_key_init(&kc, &br_sha256_vtable, hmacKey, KEY_LEN);
  br_hmac_init(&ctx, &kc, 0);
  br_hmac_update(&ctx, msg, strlen(msg));
  br_hmac_out(&ctx, out);
}

static bool macMatches(const char *msg, const char *macHex) {
  uint8_t raw[32];
  char got[65];
  hmacSha256(msg, raw);
  for (int i = 0; i < 32; i++) sprintf(got + i * 2, "%02x", raw[i]);
  got[64] = '\0';
  uint8_t diff = 0;
  for (int i = 0; i < 64; i++) diff |= (uint8_t)(got[i] ^ macHex[i]);
  return diff == 0;
}

static void makeId(char out[33]) {
  for (int i = 0; i < 16; i++) {
    uint8_t b = (uint8_t)(RANDOM_REG32 ^ micros() ^ ESP.getCycleCount());
    sprintf(out + i * 2, "%02x", b);
  }
  out[32] = '\0';
}

static int32_t unixNow() {
  time_t t = time(nullptr);
  if (t < TIME_FLOOR) return 0;
  return (int32_t)t;
}

static bool clockSynced() {
  return unixNow() != 0;
}

static void relayIdle() {
  digitalWrite(RELAY_PIN, HIGH);
  pulseOn = false;
}

static void relayPulse(uint32_t ms) {
  if (ms > (uint32_t)OPEN_MAX_MS) ms = OPEN_MAX_MS;
  pulseMs = ms;
  pulseStart = millis();
  pulseOn = true;
  digitalWrite(RELAY_PIN, LOW);
}

static void loadNonces() {
  EEPROM.begin(sizeof(NonceStore));
  EEPROM.get(0, nonceStore);
  if (nonceStore.magic != NONCE_MAGIC || nonceStore.next >= NONCE_SLOTS || nonceStore.filled > NONCE_SLOTS) {
    memset(&nonceStore, 0, sizeof(nonceStore));
    nonceStore.magic = NONCE_MAGIC;
    EEPROM.put(0, nonceStore);
    EEPROM.commit();
  }
}

static bool nonceSeen(const uint8_t raw[16]) {
  for (uint8_t i = 0; i < nonceStore.filled; i++) {
    uint8_t idx = (uint8_t)((nonceStore.next + NONCE_SLOTS - 1 - i) % NONCE_SLOTS);
    if (memcmp(nonceStore.nonce[idx], raw, 16) == 0) return true;
  }
  return false;
}

static bool nonceRemember(const uint8_t raw[16]) {
  NonceStore copy = nonceStore;
  memcpy(copy.nonce[copy.next], raw, 16);
  copy.next = (uint8_t)((copy.next + 1) % NONCE_SLOTS);
  if (copy.filled < NONCE_SLOTS) copy.filled++;
  EEPROM.put(0, copy);
  if (!EEPROM.commit()) return false;
  nonceStore = copy;
  return true;
}

static bool copyText(char *dest, size_t destLen, JsonVariant v) {
  if (!v.is<const char *>()) return false;
  const char *s = v.as<const char *>();
  size_t n = strlen(s);
  if (n + 1 > destLen) return false;
  memcpy(dest, s, n + 1);
  return true;
}

static bool readI32(JsonVariant v, int32_t *out) {
  if (v.is<bool>() || !v.is<int32_t>()) return false;
  *out = v.as<int32_t>();
  return true;
}

static void queueResult(const char *id, bool ok, const char *reason, int32_t duration) {
  if (!isHex(id, 32)) return;
  int32_t ts = unixNow();
  snprintf(pendingResult, sizeof(pendingResult),
           "{\"schema\":1,\"id\":\"%s\",\"ts\":%ld,\"ok\":%s,\"reason\":\"%s\",\"duration_ms\":%ld}",
           id, (long)ts, ok ? "true" : "false", reason, (long)duration);
  resultPending = true;
}

static void serviceResult() {
  if (!resultPending || !mqtt.connected()) return;
  if (mqtt.publish(TOPIC_RESULT, pendingResult, false, 1)) resultPending = false;
}

static void publishStatus() {
  if (!mqtt.connected()) {
    statusDue = true;
    return;
  }
  char id[33];
  char ip[16];
  makeId(id);
  IPAddress addr = WiFi.localIP();
  snprintf(ip, sizeof(ip), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
  char body[256];
  snprintf(body, sizeof(body),
           "{\"schema\":1,\"id\":\"%s\",\"online\":true,\"ts\":%ld,\"fw\":\"%s\",\"uptime_s\":%lu,\"ip\":\"%s\",\"rssi\":%d,\"ntp\":%s,\"relay\":\"%s\"}",
           id, (long)unixNow(), FW, millis() / 1000UL, ip, WiFi.RSSI(),
           clockSynced() ? "true" : "false", pulseOn ? "on" : "off");
  if (mqtt.publish(TOPIC_STATUS, body, true, 1)) {
    lastStatus = millis();
    statusDue = false;
  } else {
    statusDue = true;
  }
}

static bool oneOf(const char *s, const char *a, const char *b, const char *c = nullptr) {
  return strcmp(s, a) == 0 || strcmp(s, b) == 0 || (c && strcmp(s, c) == 0);
}

static void handleOpen(const char *json) {
  doc.clear();
  char id[33] = {0};
  char nonce[33] = {0};
  char mac[65] = {0};
  char source[8] = {0};
  char reason[8] = {0};
  int32_t ts = 0;
  int32_t duration = 0;

  if (deserializeJson(doc, json)) {
    Serial.println("open malformed");
    return;
  }

  bool idOk = copyText(id, sizeof(id), doc["id"]) && isHex(id, 32);
  bool nonceOk = copyText(nonce, sizeof(nonce), doc["nonce"]) && isHex(nonce, 32);
  bool macOk = copyText(mac, sizeof(mac), doc["mac"]) && isHex(mac, 64);
  bool sourceOk = copyText(source, sizeof(source), doc["source"]) && oneOf(source, "server", "reader");
  bool reasonOk = copyText(reason, sizeof(reason), doc["reason"]) && oneOf(reason, "tag", "manual", "offline");
  bool tsOk = readI32(doc["ts"], &ts);
  bool durationOk = readI32(doc["duration_ms"], &duration);
  bool schemaOk = doc["schema"].is<int32_t>() && !doc["schema"].is<bool>() && doc["schema"].as<int32_t>() == 1;

  if (!schemaOk || !idOk || !nonceOk || !macOk || !sourceOk || !reasonOk || !tsOk || !durationOk) {
    Serial.println("open malformed");
    if (idOk) queueResult(id, false, "malformed", durationOk ? duration : 0);
    return;
  }

  char canon[160];
  snprintf(canon, sizeof(canon), "v1|%s|%ld|%s|%ld|%s|%s", id, (long)ts, nonce, (long)duration, source, reason);
  if (!keyOk || !macMatches(canon, mac)) {
    Serial.println("open bad_mac");
    queueResult(id, false, "bad_mac", duration);
    return;
  }
  if (!clockSynced()) {
    Serial.println("open time_unsynced");
    queueResult(id, false, "time_unsynced", duration);
    return;
  }

  uint8_t rawNonce[16];
  hexToBytes(nonce, rawNonce, 16);
  if (nonceSeen(rawNonce)) {
    Serial.println("open replay");
    queueResult(id, false, "replay", duration);
    return;
  }

  int32_t now = unixNow();
  int32_t skew = now > ts ? now - ts : ts - now;
  if (skew > OPEN_SKEW_S) {
    Serial.println("open stale");
    queueResult(id, false, "stale", duration);
    return;
  }
  if (duration < OPEN_MIN_MS || duration > OPEN_MAX_MS) {
    Serial.println("open duration");
    queueResult(id, false, "duration", duration);
    return;
  }
  if (pulseOn) {
    Serial.println("open busy");
    queueResult(id, false, "busy", duration);
    return;
  }
  if (!nonceRemember(rawNonce)) {
    Serial.println("open nonce store failed");
    return;
  }

  relayPulse((uint32_t)duration);
  Serial.printf("open opened %ld ms\n", (long)duration);
  queueResult(id, true, "opened", duration);
  statusDue = true;
}

static void onMqttMessage(MQTTClient *client, char topic[], char bytes[], int length) {
  (void)client;
  if (rxReady) return;
  if (strcmp(topic, TOPIC_OPEN) != 0) return;
  if (length <= 0 || length >= (int)sizeof(rx)) return;
  memcpy(rx, bytes, length);
  rx[length] = '\0';
  rxReady = true;
}

static void serviceWifi() {
  if (WiFi.status() == WL_CONNECTED) {
    if (!ntpStarted) {
      configTime(0, 0, "pool.ntp.org", "time.google.com");
      ntpStarted = true;
      Serial.print("wifi ");
      Serial.println(WiFi.localIP());
    }
    return;
  }
  ntpStarted = false;
  if (lastWifiTry != 0 && millis() - lastWifiTry < 8000) return;
  lastWifiTry = millis();
  Serial.println("wifi connecting");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
}

static void serviceMqtt() {
  if (WiFi.status() != WL_CONNECTED) return;
  if (mqtt.connected()) return;
  if (lastMqttTry != 0 && millis() - lastMqttTry < 3000) return;
  lastMqttTry = millis();
  Serial.println("mqtt connecting");
  if (!mqtt.connect("door-actuator", MQTT_USER, MQTT_PASS)) {
    Serial.println("mqtt failed");
    return;
  }
  mqtt.subscribe(TOPIC_OPEN, 1);
  statusDue = true;
  Serial.println("mqtt connected");
}

static void servicePulse() {
  if (!pulseOn) return;
  if ((uint32_t)(millis() - pulseStart) < pulseMs) return;
  relayIdle();
  statusDue = true;
  Serial.println("relay off");
}

void setup() {
  digitalWrite(RELAY_PIN, HIGH);
  pinMode(RELAY_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, HIGH);

  Serial.begin(115200);
  Serial.println();
  Serial.println("door-actuator 0.1.0");

  keyOk = decodeKey();
  if (!keyOk) Serial.println("hmac key rejected");
  loadNonces();

  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.setSleepMode(WIFI_NONE_SLEEP);
  WiFi.setAutoReconnect(true);
  WiFi.hostname("door-actuator");

  mqtt.begin(MQTT_HOST, MQTT_PORT, net);
  mqtt.setTimeout(2500);
  mqtt.setKeepAlive(60);
  mqtt.setCleanSession(true);
  mqtt.setWill(TOPIC_STATUS, LWT, true, 1);
  mqtt.onMessageAdvanced(onMqttMessage);
}

void loop() {
  serviceWifi();
  mqtt.loop();
  serviceMqtt();
  servicePulse();
  if (rxReady) {
    char local[sizeof(rx)];
    noInterrupts();
    memcpy(local, rx, sizeof(rx));
    rxReady = false;
    interrupts();
    handleOpen(local);
  }
  serviceResult();
  if (mqtt.connected() && (statusDue || millis() - lastStatus >= HEARTBEAT_MS)) publishStatus();
  yield();
}
