/* AEGISChain v2: software-controlled pre-application gate, not ROM secure boot.
 * ATECC persistent configuration/provisioning/locking is prohibited.
 */
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <Wire.h>
#include <time.h>
#include <math.h>
#include "esp_mac.h"
#include "esp_random.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/platform_util.h"
#include "ECCX08.h"
#include <AegisImage.h>
#include <AegisPolicy.h>
#include <AegisHandoff.h>
#include <AegisResponse.h>
#include <AegisEncoding.h>
#if __has_include("config.h")
#include "config.h"
#else
#include "config.example.h"
#endif
#include "tamper_temperature.h"
#include "tamper_voltage.h"
static_assert(AEGIS_MODE>=0 && AEGIS_MODE<=2,"Invalid signer mode");
static_assert(AEGIS_KEY_SLOT>=0 && AEGIS_KEY_SLOT<=15,"Invalid key slot");
static_assert(AEGIS_ENABLE_TEMPERATURE==0 || AEGIS_ENABLE_TEMPERATURE==1,"Invalid sensor flag");
static_assert(AEGIS_ENABLE_VOLTAGE==0 || AEGIS_ENABLE_VOLTAGE==1,"Invalid sensor flag");
ECCX08Class chip(Wire,0x60);
mbedtls_ecdsa_context demoKey;
GateChecks checks;
String hardwareId,ateccSerial="000000000000000000",publicKey;
const char *modeName=AEGIS_MODE==1?"atecc":"software_demo";
AegisMeasurement gateImage,payloadImage;
const esp_partition_t *gatePartition=nullptr,*payloadPartition=nullptr;
uint32_t minimumVersion=1,authenticationStart=0;
uint8_t temperatureState=0,voltageState=0;
int32_t temperatureMilli=AEGIS_DISABLED,voltageMilli=AEGIS_DISABLED;
void stopHere(const char *reason) {
  checks=GateChecks{};
  Serial.printf("[GATE] FAILED: %s\n[GATE] APPLICATION BLOCKED\n",reason);
  WiFi.disconnect(true);
  while(true) delay(1000);
}
void jitter() { delayMicroseconds(100+esp_random()%1901); }
String hexOf(const uint8_t *data, size_t length) {
  const char chars[] = "0123456789abcdef";
  String result; result.reserve(length * 2);
  for (size_t i = 0; i < length; i++) { result += chars[data[i] >> 4]; result += chars[data[i] & 15]; }
  return result;
}

bool decodeHex(const String &value, uint8_t *out, size_t length) {
  if (value.length() != length * 2) return false;
  for (size_t i = 0; i < length; i++) {
    int v = 0;
    for (size_t j = 0; j < 2; j++) {
      char c = value[2 * i + j];
      int n = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
      if (n < 0) return false;
      v = (v << 4) | n;
    }
    out[i] = v;
  }
  return true;
}

int randomBytes(void *, unsigned char *out, size_t n) { esp_fill_random(out, n); return 0; }

void connectNetwork() {
  if (!strcmp(WIFI_SSID, "CHANGE_ME")) stopHere("Set Wi-Fi in config.h");
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA); WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED) {
    if (millis() - start > 20000) stopHere("Wi-Fi timeout");
    delay(100);
  }
  // Time is needed for TLS certificate validity, not used as attestation evidence.
  configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");
  start = millis();
  while (time(nullptr) < 1735689600) {
    if (millis() - start > 20000) stopHere("Clock sync timeout");
    delay(100);
  }
}

void prepareSigner(const uint8_t config[128], bool found) {
#if AEGIS_MODE == 1
  if (!found || config[86] != 0 || config[87] != 0) stopHere("ATECC not ready: zones are not already locked; left unchanged");
  uint16_t slotConfig = config[20 + 2 * AEGIS_KEY_SLOT] | (uint16_t(config[21 + 2 * AEGIS_KEY_SLOT]) << 8);
  uint16_t keyConfig = config[96 + 2 * AEGIS_KEY_SLOT] | (uint16_t(config[97 + 2 * AEGIS_KEY_SLOT]) << 8);
  if ((slotConfig & 0x20) || !(keyConfig & 1) || ((keyConfig >> 2) & 7) != 4 || (keyConfig & 0x80))
    stopHere("Unsupported key policy (requires ECC private key, no LimitedUse, no ReqAuth)");
  uint8_t pub[65]; pub[0] = 4;
  if (!chip.generatePublicKey(AEGIS_KEY_SLOT, pub + 1)) stopHere("Existing public-key derivation failed; no key created");
  publicKey = hexOf(pub, sizeof(pub));
  Serial.printf("MODE=atecc\nPUBLIC_KEY=%s\n", publicKey.c_str());
#elif AEGIS_MODE == 2
  Serial.println("[CRYPTO] SOFTWARE DEMO ONLY: private key in ESP32 NVS; NOT hardware-backed authentication");
  mbedtls_ecdsa_init(&demoKey);
  auto *grp = &demoKey.MBEDTLS_PRIVATE(grp);
  auto *d = &demoKey.MBEDTLS_PRIVATE(d);
  auto *q = &demoKey.MBEDTLS_PRIVATE(Q);
  if (mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1)) stopHere("ECC group failed");
  Preferences prefs;
  if (!prefs.begin("aegis-demo", false)) stopHere("Demo NVS open failed");
  uint8_t secret[32] = {};
  size_t existing = prefs.getBytesLength("private");
  if (existing == 0) {
    if (mbedtls_ecp_gen_keypair(grp, d, q, randomBytes, nullptr) || mbedtls_mpi_write_binary(d, secret, 32)) stopHere("Demo key generation failed");
    if (prefs.putBytes("private", secret, 32) != 32) stopHere("Demo key persistence failed");
  } else {
    if (existing != 32 || prefs.getBytes("private", secret, 32) != 32 || mbedtls_mpi_read_binary(d, secret, 32) ||
        mbedtls_ecp_check_privkey(grp, d) || mbedtls_ecp_mul(grp, q, d, &grp->G, randomBytes, nullptr)) stopHere("Demo key load failed");
  }
  mbedtls_platform_zeroize(secret, sizeof(secret)); prefs.end();
  uint8_t pub[65]; size_t length = 0;
  if (mbedtls_ecp_point_write_binary(grp, q, MBEDTLS_ECP_PF_UNCOMPRESSED, &length, pub, sizeof(pub)) || length != 65) stopHere("Demo public key failed");
  publicKey = hexOf(pub, sizeof(pub));
  Serial.printf("MODE=software_demo\nPUBLIC_KEY=%s\n", publicKey.c_str());
#endif
}

bool postJSON(const char *path, JsonDocument &request, JsonDocument &response) {
  if (!String(API_BASE).startsWith("https://") || !strstr(TLS_ROOT_CA, "BEGIN CERTIFICATE")) return false;
  WiFiClientSecure tls;
  tls.setCACert(TLS_ROOT_CA); tls.setHandshakeTimeout(10);
  HTTPClient http;
  http.setConnectTimeout(5000); http.setTimeout(5000);
  http.setFollowRedirects(HTTPC_DISABLE_FOLLOW_REDIRECTS);
  if (!http.begin(tls, String(API_BASE) + path)) return false;
  http.addHeader("Content-Type", "application/json");
  String body; serializeJson(request, body);
  int status = http.POST(body);
  int length = http.getSize();
  if (status != 200 || length < 1 || length > 2048) {
    Serial.printf("HTTPS rejected: status=%d length=%d\n", status, length); http.end(); return false;
  }
  // Require Content-Length and bound memory and total read duration.
  char buffer[2049]; size_t count = 0; uint32_t start = millis();
  auto *stream = http.getStreamPtr();
  while (count < size_t(length) && millis() - start < 5000) {
    if (stream->available()) {
      int c = stream->read(); if (c >= 0) buffer[count++] = char(c);
    } else if (!http.connected()) break;
    else delay(1);
  }
  http.end();
  if (count != size_t(length)) return false;
  return !deserializeJson(response, buffer, count) && response.is<JsonObject>();
}

bool signDigest(const uint8_t digest[32], uint8_t signature[64]) {
#if AEGIS_MODE == 1
  return chip.ecSign(AEGIS_KEY_SLOT, digest, signature) == 1;
#elif AEGIS_MODE == 2
  mbedtls_mpi r, s; mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
  int rc = mbedtls_ecdsa_sign(&demoKey.MBEDTLS_PRIVATE(grp), &r, &s, &demoKey.MBEDTLS_PRIVATE(d), digest, 32, randomBytes, nullptr);
  if (!rc) rc = mbedtls_mpi_write_binary(&r, signature, 32);
  if (!rc) rc = mbedtls_mpi_write_binary(&s, signature + 32, 32);
  mbedtls_mpi_free(&r); mbedtls_mpi_free(&s); return rc == 0;
#else
  return false;
#endif
}


void initializeGate() {
  gatePartition=esp_partition_find_first(ESP_PARTITION_TYPE_APP,ESP_PARTITION_SUBTYPE_APP_FACTORY,"aegis");
  payloadPartition=esp_partition_find_first(ESP_PARTITION_TYPE_APP,ESP_PARTITION_SUBTYPE_APP_OTA_0,"payload");
  const esp_partition_t *running=esp_ota_get_running_partition();
  if(!running || !gatePartition || running->address!=gatePartition->address) stopHere("not executing factory AEGIS gate");
  // Self-select factory first; no failed check should leave a payload selected.
  if(esp_ota_set_boot_partition(gatePartition)!=ESP_OK) stopHere("cannot select AEGIS next boot");
  Preferences state;
  if(!state.begin("aegis-chain",false)) stopHere("cannot open handoff state");
  if(state.isKey("ticket") && !state.remove("ticket")) stopHere("cannot clear stale handoff");
  state.end();
  uint8_t mac[6]={};
  if(esp_efuse_mac_get_default(mac)!=ESP_OK) stopHere("hardware ID read failed");
  hardwareId=hexOf(mac,6);hardwareId.toUpperCase();checks.identity=true;
  Serial.printf("HARDWARE_ID=%s\n",hardwareId.c_str());
}
bool inspectChip(uint8_t config[128]) {
  Wire.setBufferSize(256);
  if(!Wire.begin(21,22,100000) || !chip.begin() || !chip.readConfiguration(config)) return false;
  String serial=chip.serialNumber(); if(serial.length()!=18) return false;
  ateccSerial=serial;
  Serial.printf("ATECC_SERIAL=%s\n[ATECC] data lock=0x%02x config lock=0x%02x (unchanged)\n",serial.c_str(),config[86],config[87]);
  return true;
}
void measureBoth() {
  if(!measureImage(gatePartition,false,gateImage)) stopHere("gate image invalid");
  if(!measureImage(payloadPartition,true,payloadImage)) stopHere("payload partition missing or image/descriptor corrupted");
  checks.image=true;
  Serial.printf("GATE_HASH=%s\nPAYLOAD_HASH=%s\nPAYLOAD_VERSION=%lu\n",gateImage.hash,payloadImage.hash,(unsigned long)payloadImage.version);
  Serial.printf("[MEASURE] Gate bytes=%lu Payload bytes=%lu (padding excluded)\n",(unsigned long)gateImage.length,(unsigned long)payloadImage.length);
}
uint32_t highestVersion() {
  Preferences state; if(!state.begin("aegis-chain",false)) stopHere("version storage unavailable");
  uint32_t highest=0;
  if(state.isKey("highest") && (state.getBytesLength("highest")!=sizeof(highest) || state.getBytes("highest",&highest,sizeof(highest))!=sizeof(highest))) stopHere("version state malformed");
  state.end(); return highest;
}
void checkVersion() {
  checks.version=versionAllowed(payloadImage.version,minimumVersion,highestVersion());
  if(!checks.version) stopHere("payload downgrade (server/NVS policy)");
}
void checkTamper(bool capture) {
  int32_t temp,volts; uint8_t ts=readTemperature(temp),vs=readVoltage(volts);
  const char *names[]={"DISABLED","PASS","TAMPER","ERROR"};
  Serial.printf("[TAMPER] Temperature: %s, Voltage: %s\n",names[ts],names[vs]);
  checks.tamper=sensorAllowed(ts,temp,AEGIS_ENABLE_TEMPERATURE,AEGIS_TEMP_MIN_MILLI,AEGIS_TEMP_MAX_MILLI) &&
    sensorAllowed(vs,volts,AEGIS_ENABLE_VOLTAGE,AEGIS_VOLTAGE_MIN_MILLI,AEGIS_VOLTAGE_MAX_MILLI);
  if(!checks.tamper) stopHere("tamper condition or enabled sensor read failure");
  if(capture) {temperatureState=ts;temperatureMilli=temp;voltageState=vs;voltageMilli=volts;}
}
void fillReport(JsonDocument &doc) {
  doc["protocol"]="AEGISChain-v2";doc["hardware_id"]=hardwareId;doc["atecc_serial"]=ateccSerial;
  doc["gate_hash"]=gateImage.hash;doc["payload_hash"]=payloadImage.hash;
  doc["payload_version"]=payloadImage.version;doc["mode"]=modeName;
  doc["temperature_state"]=temperatureState;doc["temperature_milli"]=temperatureMilli;
  doc["voltage_state"]=voltageState;doc["voltage_milli"]=voltageMilli;
}
void authenticate() {
  JsonDocument report,response;fillReport(report);
  uint32_t requestStart=millis();authenticationStart=requestStart;
  if(!postJSON("/api/v2/device/challenge",report,response)) stopHere("challenge request rejected/unavailable; check enrollment");
  if(!validChallenge(response.as<JsonVariantConst>(),report.as<JsonVariantConst>())) stopHere("malformed or mismatched challenge");
  String id=response["challenge_id"].as<String>(),nonce=response["nonce"].as<String>();
  Serial.println("[SERVER] Challenge received");
  uint8_t message[AEGIS_REPORT_BYTES],digest[32],signature[64];
  if(!encodeReport(report.as<JsonVariantConst>(),id.c_str(),nonce.c_str(),message,sizeof(message)) ||
     mbedtls_sha256(message,sizeof(message),digest,0)) stopHere("report encoding failed");
  jitter(); if(!signDigest(digest,signature)) stopHere("signing failed; no provisioning attempted");
  Serial.println("[CRYPTO] Challenge signed");checkTamper(false);
  JsonDocument request;request["hardware_id"]=hardwareId;request["challenge_id"]=id;request["signature"]=hexOf(signature,64);
  response.clear();
  if(!postJSON("/api/v2/device/verify",request,response)) stopHere("server rejected signature/policy or is unavailable");
  if(millis()-requestStart>=30000 || !validApproval(response.as<JsonVariantConst>(),report.as<JsonVariantConst>(),id.c_str(),nonce.c_str()))
    stopHere("expired, malformed, or mismatched approval");
  checks.server=true;checks.binding=true;minimumVersion=response["minimum_payload_version"].as<uint32_t>();
  Serial.println("[SERVER] Signature accepted\n[ATTEST] PASS (application-reported measurements)");
}
void finalHandoff() {
  jitter(); checkVersion();checkTamper(false);
  AegisMeasurement currentGate,currentPayload;
  if(!measureImage(gatePartition,false,currentGate) || !measureImage(payloadPartition,true,currentPayload) ||
     strcmp(currentGate.hash,gateImage.hash) || strcmp(currentPayload.hash,payloadImage.hash) || currentPayload.version!=payloadImage.version)
    stopHere("image changed before handoff");
  // Re-read identity as an independent final consistency check.
  uint8_t mac[6]; if(esp_efuse_mac_get_default(mac)!=ESP_OK) stopHere("final identity read failed");
  String finalId=hexOf(mac,6);finalId.toUpperCase();
  if(finalId!=hardwareId) stopHere("identity changed");
  if(AEGIS_REQUIRE_ATECC || AEGIS_MODE==1) {
    if(chip.serialNumber()!=ateccSerial) stopHere("ATECC identity changed/unavailable");
  }
  if(!checks.passed()) stopHere("incomplete gate decision");
  Preferences state;if(!state.begin("aegis-chain",false)) stopHere("handoff storage unavailable");
  uint32_t version=payloadImage.version;
  if(state.putBytes("highest",&version,sizeof(version))!=sizeof(version)) stopHere("cannot persist version floor");
  uint32_t stored=0;
  if(state.getBytes("highest",&stored,sizeof(stored))!=sizeof(stored) || stored!=version) stopHere("version floor readback failed");
  AegisTicket ticket={};ticket.magic=AEGIS_TICKET_MAGIC;ticket.version=version;memcpy(ticket.payloadHash,payloadImage.hash,65);
  if(state.putBytes("ticket",&ticket,sizeof(ticket))!=sizeof(ticket)) stopHere("cannot persist handoff record");
  AegisTicket readback={};
  if(state.getBytes("ticket",&readback,sizeof(readback))!=sizeof(readback) || memcmp(&readback,&ticket,sizeof(ticket))) stopHere("handoff readback failed");
  state.end();
  jitter();if(!checks.passed() || millis()-authenticationStart>=30000) stopHere("final gate decision failed or approval expired");
  // Only this site selects payload. esp_ota_set_boot_partition validates it again.
  if(esp_ota_set_boot_partition(payloadPartition)!=ESP_OK) stopHere("payload boot selection failed");
  const esp_partition_t *next=esp_ota_get_boot_partition();
  if(!next || next->address!=payloadPartition->address) {
    esp_ota_set_boot_partition(gatePartition);stopHere("payload selection readback failed");
  }
  Serial.println("[GATE] ALL CHECKS PASSED\n[GATE] Launching application...");
  Serial.flush();esp_restart();stopHere("restart unexpectedly returned");
}
void setup() {
  Serial.begin(115200);delay(300);Serial.println("========== AEGISChain ==========\n[GATE] Starting security checks");
  initializeGate();uint8_t config[128]={};bool found=inspectChip(config);
  if(!found) Serial.println("[ATECC] unavailable");
  checks.atecc=found || (!AEGIS_REQUIRE_ATECC && AEGIS_MODE!=1);
  if(!checks.atecc) stopHere("ATECC identity required but unavailable");
  measureBoth();checkVersion();checkTamper(true);
#if AEGIS_MODE==0
  stopHere("diagnostics only; choose a signer mode explicitly");
#else
  connectNetwork();jitter();prepareSigner(config,found);
  // Capture current readings immediately before constructing signed report.
  checkTamper(true);authenticate();finalHandoff();
#endif
}
void loop() { stopHere("unexpected return to gate loop"); }
