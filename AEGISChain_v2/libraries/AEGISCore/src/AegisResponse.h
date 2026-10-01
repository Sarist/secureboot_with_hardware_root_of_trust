#pragma once
#include <ArduinoJson.h>
#include <stdint.h>
#include <string.h>
// Used by the actual gate and compiled in native tests with ArduinoJson.
inline bool hexText(const char *s,size_t n) {
  if(!s || strlen(s)!=n) return false;
  for(size_t i=0;i<n;i++) if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f'))) return false;
  return true;
}
inline bool exactReport(JsonVariantConst response, JsonVariantConst expected) {
  const char* texts[]={"protocol","hardware_id","atecc_serial","gate_hash","payload_hash","mode"};
  for(auto key:texts) if(!response[key].is<const char*>() || !expected[key].is<const char*>() || strcmp(response[key].as<const char*>(),expected[key].as<const char*>())) return false;
  const char* ints[]={"payload_version","temperature_state","temperature_milli","voltage_state","voltage_milli"};
  for(auto key:ints) if(!response[key].is<int32_t>() || response[key].as<int32_t>()!=expected[key].as<int32_t>()) return false;
  return true;
}
inline bool validChallenge(JsonVariantConst doc, JsonVariantConst report) {
  return doc.is<JsonObjectConst>() && doc.size()==14 && exactReport(doc,report) &&
    doc["expires_in"].is<int>() && doc["expires_in"].as<int>()==30 &&
    doc["challenge_id"].is<const char*>() && hexText(doc["challenge_id"],32) &&
    doc["nonce"].is<const char*>() && hexText(doc["nonce"],64);
}
inline bool validApproval(JsonVariantConst doc, JsonVariantConst report, const char *id, const char *nonce) {
  return doc.is<JsonObjectConst>() && doc.size()==16 && exactReport(doc,report) &&
    doc["authenticated"].is<bool>() && doc["authenticated"].as<bool>() &&
    doc["scope"].is<const char*>() && !strcmp(doc["scope"],"application_gate_poc") &&
    doc["challenge_id"].is<const char*>() && !strcmp(doc["challenge_id"],id) &&
    doc["nonce"].is<const char*>() && !strcmp(doc["nonce"],nonce) &&
    doc["minimum_payload_version"].is<uint32_t>() && doc["minimum_payload_version"].as<uint32_t>()>0 &&
    doc["minimum_payload_version"].as<uint32_t>()<=report["payload_version"].as<uint32_t>();
}
