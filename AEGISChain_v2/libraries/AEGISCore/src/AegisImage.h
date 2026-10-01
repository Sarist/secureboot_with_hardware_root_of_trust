#pragma once
#include <Arduino.h>
#include "esp_image_format.h"
#include "esp_ota_ops.h"
#include "esp_app_desc.h"
#include "mbedtls/sha256.h"
#include "AegisImageLayout.h"
struct AegisPayloadDescriptor { char magic[16]; uint32_t version; };
constexpr char AEGIS_PAYLOAD_MAGIC[16] = "AEGIS-PAYLOAD-2";
struct AegisMeasurement { char hash[65] = {}; uint32_t length=0, version=0; };
inline bool aegisPartitionRead(void *ctx,uint32_t offset,void *out,size_t n) {
  return esp_partition_read(static_cast<const esp_partition_t*>(ctx),offset,out,n)==ESP_OK;
}
inline bool measureImage(const esp_partition_t *part, bool payload, AegisMeasurement &out) {
  if (!part || part->type != ESP_PARTITION_TYPE_APP) return false;
  esp_partition_pos_t pos={part->address,part->size}; esp_image_metadata_t metadata={};
  if (esp_image_verify(ESP_IMAGE_VERIFY,&pos,&metadata)!=ESP_OK) return false;
  if (!aegisImageLength(aegisPartitionRead,const_cast<esp_partition_t*>(part),part->size,out.length)) return false;
  if (payload) {
    AegisPayloadDescriptor desc={};
    constexpr size_t at=sizeof(esp_image_header_t)+sizeof(esp_image_segment_header_t)+sizeof(esp_app_desc_t);
    if (at+sizeof(desc)>out.length || esp_partition_read(part,at,&desc,sizeof(desc))!=ESP_OK ||
        memcmp(desc.magic,AEGIS_PAYLOAD_MAGIC,16) || desc.version==0 || desc.version>INT32_MAX) return false;
    out.version=desc.version;
  }
  mbedtls_sha256_context ctx; mbedtls_sha256_init(&ctx);
  bool ok=mbedtls_sha256_starts(&ctx,0)==0; uint8_t block[1024],hash[32];
  for(uint32_t offset=0;ok && offset<out.length;) {
    size_t n=min(sizeof(block),size_t(out.length-offset));
    ok=esp_partition_read(part,offset,block,n)==ESP_OK && mbedtls_sha256_update(&ctx,block,n)==0;
    offset+=n; delay(1);
  }
  if(ok) ok=mbedtls_sha256_finish(&ctx,hash)==0;
  mbedtls_sha256_free(&ctx);
  if(!ok) return false;
  constexpr char chars[]="0123456789abcdef";
  for(size_t i=0;i<32;i++) {out.hash[2*i]=chars[hash[i]>>4];out.hash[2*i+1]=chars[hash[i]&15];}
  out.hash[64]=0; return true;
}
