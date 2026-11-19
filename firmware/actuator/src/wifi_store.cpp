#include "wifi_store.h"

#include <Arduino.h>
#include <EEPROM.h>
#include <string.h>

static const uint32_t WIFI_MAGIC = 0x31464957u;

struct WifiRecord {
  uint32_t magic;
  char ssid[33];
  char password[64];
};

static_assert(WIFI_EEPROM_OFFSET + sizeof(WifiRecord) <= DOOR_EEPROM_BYTES, "wifi record fits in EEPROM");

static bool printable(const char *value) {
  if (!value) return false;
  for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
    if (*p < 32 || *p == 127) return false;
  }
  return true;
}

bool credentialsOk(const char *ssid, const char *password) {
  if (!ssid || !password || !printable(ssid) || !printable(password)) return false;
  size_t name = strlen(ssid);
  if (name < 1 || name > 32) return false;
  size_t secret = strlen(password);
  if (secret == 0) return true;
  return secret >= 8 && secret <= 63;
}

bool setupSecretOk(const char *value) {
  if (!value || !printable(value)) return false;
  size_t n = strlen(value);
  return n >= 8 && n <= 63;
}

static void copyField(char *dest, size_t destLen, const char *src) {
  size_t i = 0;
  if (!src) src = "";
  if (destLen == 0) return;
  while (src[i] && i + 1 < destLen) {
    dest[i] = src[i];
    i++;
  }
  dest[i] = '\0';
}

bool wifiLoad(char *ssid, size_t ssidLen, char *password, size_t passwordLen) {
  if (!ssid || ssidLen < 2 || !password || passwordLen < 2) return false;
  WifiRecord rec;
  EEPROM.get(WIFI_EEPROM_OFFSET, rec);
  if (rec.magic != WIFI_MAGIC) return false;
  if (strnlen(rec.ssid, sizeof(rec.ssid)) == sizeof(rec.ssid)) return false;
  if (strnlen(rec.password, sizeof(rec.password)) == sizeof(rec.password)) return false;
  if (rec.ssid[0] == '\0') {
    ssid[0] = '\0';
    password[0] = '\0';
    return true;
  }
  if (!credentialsOk(rec.ssid, rec.password)) return false;
  copyField(ssid, ssidLen, rec.ssid);
  copyField(password, passwordLen, rec.password);
  return true;
}

void wifiSave(const char *ssid, const char *password) {
  WifiRecord rec;
  memset(&rec, 0, sizeof(rec));
  rec.magic = WIFI_MAGIC;
  if (!ssid) ssid = "";
  if (!password) password = "";
  strncpy(rec.ssid, ssid, sizeof(rec.ssid) - 1);
  strncpy(rec.password, password, sizeof(rec.password) - 1);
  EEPROM.put(WIFI_EEPROM_OFFSET, rec);
  if (!EEPROM.commit()) Serial.println("wifi store failed");
}
