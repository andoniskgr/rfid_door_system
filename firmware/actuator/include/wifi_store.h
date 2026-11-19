#pragma once

#include <stddef.h>

// Nonce ring stays at the start of the EEPROM sector. Wi-Fi credentials sit
// above it. A saved record wins over secrets.h, including a cleared record
// after a reset from the settings page.
static const int DOOR_EEPROM_BYTES = 1024;
static const int WIFI_EEPROM_OFFSET = 768;

// ssid is 1–32 printable characters. password is empty for an open network,
// or 8–63 printable characters.
bool credentialsOk(const char *ssid, const char *password);
bool setupSecretOk(const char *value);

// True when a record is stored, even if the network name is empty.
bool wifiLoad(char *ssid, size_t ssidLen, char *password, size_t passwordLen);
void wifiSave(const char *ssid, const char *password);
