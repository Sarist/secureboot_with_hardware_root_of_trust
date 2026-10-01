#pragma once
#include <ArduinoJson.h>
#include <stdint.h>
#include <string.h>
inline bool aegisHex(const char *s,uint8_t *out,size_t n) {
  if(!s || strlen(s)!=n*2) return false;
  for(size_t i=0;i<n;i++) {
    int value=0;
    for(size_t j=0;j<2;j++) {char c=s[i*2+j];int nibble=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1;
      if(nibble<0) return false;value=(value<<4)|nibble;}
    out[i]=uint8_t(value);
  }
  return true;
}
inline void aegisBE32(uint8_t *out,uint32_t n) {out[0]=n>>24;out[1]=n>>16;out[2]=n>>8;out[3]=n;}
constexpr size_t AEGIS_REPORT_BYTES=sizeof("AEGISChain-v2")+12+9+16+32+32+32+4+1+1+4+1+4;
inline bool encodeReport(JsonVariantConst r,const char *id,const char *nonce,uint8_t *out,size_t capacity) {
  if(capacity<AEGIS_REPORT_BYTES || !r["protocol"].is<const char*>() || strcmp(r["protocol"],"AEGISChain-v2")) return false;
  size_t at=0;const char domain[]="AEGISChain-v2";memcpy(out,domain,sizeof(domain));at+=sizeof(domain);
  const char *hw=r["hardware_id"]|"";if(strlen(hw)!=12) return false;
  memcpy(out+at,hw,12);at+=12;
  if(!aegisHex(r["atecc_serial"]|"",out+at,9)) return false;at+=9;
  if(!aegisHex(id,out+at,16)) return false;at+=16;
  if(!aegisHex(nonce,out+at,32)) return false;at+=32;
  if(!aegisHex(r["gate_hash"]|"",out+at,32)) return false;at+=32;
  if(!aegisHex(r["payload_hash"]|"",out+at,32)) return false;at+=32;
  aegisBE32(out+at,r["payload_version"].as<uint32_t>());at+=4;
  const char *mode=r["mode"]|"";if(strcmp(mode,"atecc") && strcmp(mode,"software_demo")) return false;
  out[at++]=!strcmp(mode,"atecc")?1:2;
  out[at++]=r["temperature_state"].as<uint8_t>();aegisBE32(out+at,uint32_t(r["temperature_milli"].as<int32_t>()));at+=4;
  out[at++]=r["voltage_state"].as<uint8_t>();aegisBE32(out+at,uint32_t(r["voltage_milli"].as<int32_t>()));at+=4;
  return at==AEGIS_REPORT_BYTES;
}
