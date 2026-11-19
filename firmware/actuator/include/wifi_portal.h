#pragma once

#include <Arduino.h>

// Setup access point. A phone joins Actuator-Setup and opens http://192.168.4.1.
// The point runs only while serveSetup is on the stack, then it is turned off.

static const int WIFI_SCAN_MAX = 8;
static const char *const ACTUATOR_AP_SSID = "Actuator-Setup";

struct FoundNet {
  char ssid[33];
  int16_t rssi;
  bool secure;
};

// Copies the strongest networks into out. Returns how many were kept.
int scanNetworks(FoundNet *out, int max, uint32_t budgetMs, void (*pump)());

// True only after the station has an address on that network.
// keepAp leaves Actuator-Setup running so the phone can see a failure.
bool joinNetwork(const char *ssid, const char *password, uint32_t timeoutMs, bool keepAp, void (*pump)());

// Returns true only after the chosen network has given the actuator an address.
// The access point is off before this returns.
bool serveSetup(uint32_t timeoutMs, const char *apPassword, const char *notice,
                char *ssidOut, size_t ssidLen, char *passwordOut, size_t passwordLen,
                void (*pump)());
