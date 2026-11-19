#include "wifi_portal.h"

#include "wifi_store.h"

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <string.h>

static const uint8_t AP_ADDR[4] = {192, 168, 4, 1};

static char httpBuf[1024];
static uint8_t dnsPacket[512];

static int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
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

static void trimSpaces(char *value) {
  if (!value) return;
  char *start = value;
  while (*start == ' ') start++;
  if (start != value) memmove(value, start, strlen(start) + 1);
  size_t n = strlen(value);
  while (n > 0 && value[n - 1] == ' ') {
    value[n - 1] = '\0';
    n--;
  }
}

static bool keepNet(FoundNet *out, int *count, int max, const char *ssid, int rssi, bool secure) {
  if (!ssid || !ssid[0] || strlen(ssid) > 32) return false;
  for (int i = 0; i < *count; i++) {
    if (strcmp(out[i].ssid, ssid) != 0) continue;
    if (rssi > out[i].rssi) {
      out[i].rssi = (int16_t)rssi;
      out[i].secure = secure;
    }
    return true;
  }
  int slot = *count;
  if (*count >= max) {
    slot = 0;
    for (int i = 1; i < *count; i++) {
      if (out[i].rssi < out[slot].rssi) slot = i;
    }
    if (rssi <= out[slot].rssi) return false;
  } else {
    *count += 1;
  }
  copyField(out[slot].ssid, sizeof(out[slot].ssid), ssid);
  out[slot].rssi = (int16_t)rssi;
  out[slot].secure = secure;
  return true;
}

static void sortNets(FoundNet *out, int count) {
  for (int i = 1; i < count; i++) {
    FoundNet item = out[i];
    int j = i;
    while (j > 0 && out[j - 1].rssi < item.rssi) {
      out[j] = out[j - 1];
      j--;
    }
    out[j] = item;
  }
}

int scanNetworks(FoundNet *out, int max, uint32_t budgetMs, void (*pump)()) {
  if (!out || max < 1) return 0;
  if (max > WIFI_SCAN_MAX) max = WIFI_SCAN_MAX;
  if (WiFi.scanComplete() != WIFI_SCAN_RUNNING) WiFi.scanDelete();
  WiFi.scanNetworks(true, true);
  uint32_t start = millis();
  int found = WIFI_SCAN_RUNNING;
  while ((uint32_t)(millis() - start) < budgetMs) {
    if (pump) pump();
    found = WiFi.scanComplete();
    if (found != WIFI_SCAN_RUNNING) break;
    delay(25);
  }
  if (found < 0) {
    WiFi.scanDelete();
    return 0;
  }
  int count = 0;
  for (int i = 0; i < found; i++) {
    String name = WiFi.SSID(i);
    bool secure = WiFi.encryptionType(i) != ENC_TYPE_NONE;
    keepNet(out, &count, max, name.c_str(), WiFi.RSSI(i), secure);
  }
  WiFi.scanDelete();
  sortNets(out, count);
  return count;
}

static void stopAp() {
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);
}

static bool stationOn(const char *ssid) {
  if (!ssid || !ssid[0] || WiFi.status() != WL_CONNECTED) return false;
  IPAddress ip = WiFi.localIP();
  if (ip[0] == 0) return false;
  if (ip == IPAddress(AP_ADDR[0], AP_ADDR[1], AP_ADDR[2], AP_ADDR[3])) return false;
  String got = WiFi.SSID();
  if (got.length() == 0) return true;
  return strcmp(got.c_str(), ssid) == 0;
}

bool joinNetwork(const char *ssid, const char *password, uint32_t timeoutMs, bool keepAp, void (*pump)()) {
  if (!ssid || !ssid[0]) return false;
  if (keepAp) {
    if (WiFi.getMode() != WIFI_AP_STA) WiFi.mode(WIFI_AP_STA);
  } else {
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
  }
  WiFi.persistent(false);
  WiFi.setSleepMode(WIFI_NONE_SLEEP);
  WiFi.setAutoReconnect(false);
  WiFi.hostname("door-actuator");
  if (pump) pump();
  WiFi.disconnect(false);
  uint32_t start = millis();
  while (WiFi.status() == WL_CONNECTED && (uint32_t)(millis() - start) < 2000) {
    if (pump) pump();
    delay(50);
  }
  Serial.print("wifi joining ");
  Serial.println(ssid);
  if (password && password[0]) WiFi.begin(ssid, password);
  else WiFi.begin(ssid);
  start = millis();
  while ((uint32_t)(millis() - start) < timeoutMs) {
    if (pump) pump();
    if (stationOn(ssid)) {
      WiFi.setAutoReconnect(true);
      Serial.print("wifi ");
      Serial.println(WiFi.localIP());
      return true;
    }
    delay(100);
  }
  Serial.println("wifi rejected");
  return false;
}

static bool startAp(const char *password) {
  IPAddress ip(AP_ADDR[0], AP_ADDR[1], AP_ADDR[2], AP_ADDR[3]);
  IPAddress mask(255, 255, 255, 0);
  const char *pass = (password && strlen(password) >= 8) ? password : nullptr;
  for (int attempt = 0; attempt < 4; attempt++) {
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_OFF);
    delay(100);
    WiFi.mode(WIFI_AP_STA);
    delay(200);
    bool ok = WiFi.softAP(ACTUATOR_AP_SSID, pass, 1, 0, 4);
    delay(100);
    if (ok) WiFi.softAPConfig(ip, ip, mask);
    IPAddress got = WiFi.softAPIP();
    Serial.print("setup ");
    Serial.print(ACTUATOR_AP_SSID);
    Serial.print(' ');
    Serial.println(got);
    if (ok && got[0] != 0) return true;
    delay(300);
  }
  return false;
}

static void printEsc(WiFiClient &client, const char *value) {
  for (const unsigned char *p = (const unsigned char *)(value ? value : ""); *p; p++) {
    if (*p == '&') client.print(F("&amp;"));
    else if (*p == '<') client.print(F("&lt;"));
    else if (*p == '>') client.print(F("&gt;"));
    else if (*p == '"') client.print(F("&quot;"));
    else client.write(*p);
  }
}

static void sendHead(WiFiClient &client) {
  client.print(F("HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n"));
}

static void sendForm(WiFiClient &client, const char *notice, const FoundNet *nets, int count) {
  sendHead(client);
  client.print(F("<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
                 "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                 "<title>Door actuator Wi-Fi</title>"
                 "<style>label.net{display:block;margin:.4rem 0}</style></head><body>"
                 "<h1>Door actuator Wi-Fi</h1>"));
  if (notice && notice[0]) {
    client.print(F("<p>"));
    printEsc(client, notice);
    client.print(F("</p>"));
  }
  client.print(F("<p><a href=\"/?rescan=1\">Scan again</a></p><form method=\"post\" action=\"/\">"));
  if (count > 0) {
    client.print(F("<p>Choose a network:</p>"));
    for (int i = 0; i < count; i++) {
      client.print(F("<label class=\"net\"><input type=\"radio\" name=\"pick\" value=\""));
      printEsc(client, nets[i].ssid);
      client.print(F("\"> "));
      printEsc(client, nets[i].ssid);
      client.print(F(" ("));
      client.print(nets[i].rssi);
      client.print(F(" dBm"));
      if (!nets[i].secure) client.print(F(", open"));
      client.print(F(")</label>"));
    }
  } else {
    client.print(F("<p>No networks found. Scan again, or type the name.</p>"));
  }
  client.print(F("<p><label>Hidden network<br><input name=\"other\" maxlength=\"32\"></label></p>"
                 "<p><label>Password<br><input name=\"password\" type=\"password\" maxlength=\"63\"></label></p>"
                 "<p><button type=\"submit\">Save and connect</button></p></form>"
                 "<p>Use at least 8 characters. Leave the password empty only for an open network.</p>"
                 "</body></html>"));
}

static void sendDone(WiFiClient &client, const char *ssid) {
  sendHead(client);
  client.print(F("<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
                 "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                 "<title>Saved</title></head><body><h1>Saved</h1>"
                 "<p>The actuator joined "));
  printEsc(client, ssid);
  client.print(F(" at "));
  client.print(WiFi.localIP());
  client.print(F(". Reconnect this phone to the home Wi-Fi.</p></body></html>"));
}

static int contentLengthOf(const char *head) {
  const char *p = head;
  while (p && *p) {
    bool atLine = (p == head) || p[-1] == '\n';
    if (atLine) {
      const char *lit = "content-length:";
      const char *q = p;
      bool match = true;
      for (size_t i = 0; lit[i]; i++, q++) {
        char c = *q;
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (c != lit[i]) {
          match = false;
          break;
        }
      }
      if (match) {
        while (*q == ' ' || *q == '\t') q++;
        return atoi(q);
      }
    }
    p++;
  }
  return 0;
}

static int readHttp(WiFiClient &client) {
  size_t n = 0;
  uint32_t start = millis();
  int length = -1;
  size_t headerEnd = 0;
  httpBuf[0] = '\0';
  while ((uint32_t)(millis() - start) < 3000 && n + 1 < sizeof(httpBuf)) {
    if (!client.available()) {
      if (!client.connected() && n > 0) break;
      delay(10);
      continue;
    }
    int raw = client.read();
    if (raw < 0) break;
    httpBuf[n++] = (char)raw;
    httpBuf[n] = '\0';
    if (length < 0 && n >= 4) {
      char *split = strstr(httpBuf, "\r\n\r\n");
      if (split) {
        headerEnd = (size_t)(split - httpBuf) + 4;
        length = contentLengthOf(httpBuf);
        if (length < 0 || length > 300) length = 0;
      }
    }
    if (length >= 0 && n >= headerEnd + (size_t)length) break;
  }
  return (int)n;
}

// 1 when the field is present, 0 when it is absent, -1 when the value does not fit.
static int formValue(const char *body, const char *key, char *out, size_t outLen) {
  if (!body || !key || !out || outLen < 2) return -1;
  out[0] = '\0';
  size_t keyLen = strlen(key);
  const char *p = body;
  while (*p) {
    bool boundary = (p == body) || p[-1] == '&';
    if (boundary && strncmp(p, key, keyLen) == 0 && p[keyLen] == '=') {
      p += keyLen + 1;
      size_t n = 0;
      while (*p && *p != '&') {
        char decoded;
        if (*p == '+') {
          decoded = ' ';
          p++;
        } else if (*p == '%' && hexNibble(p[1]) >= 0 && hexNibble(p[2]) >= 0) {
          decoded = (char)((hexNibble(p[1]) << 4) | hexNibble(p[2]));
          p += 3;
        } else {
          decoded = *p++;
        }
        if (n + 1 >= outLen) {
          out[0] = '\0';
          return -1;
        }
        out[n++] = decoded;
      }
      out[n] = '\0';
      return 1;
    }
    while (*p && *p != '&') p++;
    if (*p == '&') p++;
  }
  return 0;
}

static void serviceDns(WiFiUDP &dns) {
  int n = dns.parsePacket();
  if (n <= 0) return;
  if (n < 12 || n > 480) {
    while (dns.available()) dns.read();
    return;
  }
  int len = dns.read(dnsPacket, n);
  if (len < 12) return;
  uint8_t reply[512];
  memcpy(reply, dnsPacket, 2);
  reply[2] = 0x81;
  reply[3] = 0x80;
  memcpy(reply + 4, dnsPacket + 4, 2);
  memcpy(reply + 6, dnsPacket + 4, 2);
  reply[8] = 0;
  reply[9] = 0;
  reply[10] = 0;
  reply[11] = 0;
  memcpy(reply + 12, dnsPacket + 12, len - 12);
  size_t at = (size_t)len;
  static const uint8_t answer[16] = {
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
    AP_ADDR[0], AP_ADDR[1], AP_ADDR[2], AP_ADDR[3],
  };
  memcpy(reply + at, answer, sizeof(answer));
  dns.beginPacket(dns.remoteIP(), dns.remotePort());
  dns.write(reply, at + sizeof(answer));
  dns.endPacket();
}

static bool firstLineHas(const char *needle) {
  const char *end = strstr(httpBuf, "\r\n");
  if (!end) return strstr(httpBuf, needle) != nullptr;
  size_t span = (size_t)(end - httpBuf);
  for (size_t i = 0; i + strlen(needle) <= span; i++) {
    if (memcmp(httpBuf + i, needle, strlen(needle)) == 0) return true;
  }
  return false;
}

bool serveSetup(uint32_t timeoutMs, const char *apPassword, const char *notice,
                char *ssidOut, size_t ssidLen, char *passwordOut, size_t passwordLen,
                void (*pump)()) {
  if (ssidOut && ssidLen) ssidOut[0] = '\0';
  if (passwordOut && passwordLen) passwordOut[0] = '\0';
  if (timeoutMs < 1000 || !ssidOut || !passwordOut) return false;
  if (!startAp(apPassword)) {
    stopAp();
    if (pump) pump();
    return false;
  }
  if (pump) pump();
  WiFiServer http(80);
  WiFiUDP dns;
  http.begin();
  dns.begin(53);
  uint32_t deadline = millis() + timeoutMs;
  const char *message = notice ? notice : "";
  bool haveScan = false;
  FoundNet nets[WIFI_SCAN_MAX];
  int netCount = 0;
  bool chosen = false;
  while ((int32_t)(deadline - millis()) > 0) {
    if (pump) pump();
    serviceDns(dns);
    WiFiClient client = http.accept();
    if (!client) {
      delay(10);
      continue;
    }
    readHttp(client);
    bool post = strncmp(httpBuf, "POST ", 5) == 0;
    bool rescan = !post && firstLineHas("rescan=1");
    int32_t remain = (int32_t)(deadline - millis());
    if (remain < 200) {
      client.stop();
      break;
    }
    if (!haveScan || rescan) {
      uint32_t budget = (uint32_t)remain > 8000 ? 8000 : (uint32_t)remain;
      netCount = scanNetworks(nets, WIFI_SCAN_MAX, budget, pump);
      haveScan = true;
    }
    if (post) {
      const char *body = strstr(httpBuf, "\r\n\r\n");
      body = body ? body + 4 : "";
      char typed[40];
      char pick[40];
      char secret[80];
      int typedRc = formValue(body, "other", typed, sizeof(typed));
      int pickRc = formValue(body, "pick", pick, sizeof(pick));
      int secretRc = formValue(body, "password", secret, sizeof(secret));
      trimSpaces(typed);
      trimSpaces(pick);
      const char *ssid = typed[0] ? typed : pick;
      if (typedRc >= 0 && pickRc >= 0 && secretRc >= 0 && credentialsOk(ssid, secret)) {
        client.setTimeout(25000);
        if (joinNetwork(ssid, secret, 20000, true, pump)) {
          copyField(ssidOut, ssidLen, ssid);
          copyField(passwordOut, passwordLen, secret);
          sendDone(client, ssid);
          client.flush();
          delay(400);
          if (pump) pump();
          client.stop();
          chosen = true;
          break;
        }
        message = "That network did not connect. Check the name and password.";
      } else {
        message = "Choose a network, and use a password of at least 8 characters.";
      }
    }
    sendForm(client, message, nets, netCount);
    client.stop();
  }
  dns.stop();
  http.stop();
  if (chosen && stationOn(ssidOut)) {
    WiFi.softAPdisconnect(true);
    if (!stationOn(ssidOut)) joinNetwork(ssidOut, passwordOut, 15000, false, pump);
  } else {
    stopAp();
  }
  if (pump) pump();
  return chosen;
}
