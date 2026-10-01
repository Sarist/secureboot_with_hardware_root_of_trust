// Separate demonstration application. No networking and no authentication shortcuts.
#include <Arduino.h>
#include <Preferences.h>
#include "esp_system.h"
#include <AegisImage.h>
#include <AegisHandoff.h>
#ifndef PAYLOAD_VERSION
#define PAYLOAD_VERSION 1
#endif
static_assert(PAYLOAD_VERSION>0 && PAYLOAD_VERSION<=INT32_MAX,"Invalid payload version");
__attribute__((section(".rodata_custom_desc"),used))
const AegisPayloadDescriptor payloadDescriptor={"AEGIS-PAYLOAD-2",PAYLOAD_VERSION};
void blocked(const char *reason) {
  Serial.begin(115200); Serial.printf("[PAYLOAD] BLOCKED: %s\n",reason);
  while(true) delay(1000);
}
void setup() {
  // Keep custom descriptor linked, and restore the factory BEFORE delay or application work.
  asm volatile("" : : "r"(&payloadDescriptor) : "memory");
  const esp_partition_t *factory=esp_partition_find_first(ESP_PARTITION_TYPE_APP,ESP_PARTITION_SUBTYPE_APP_FACTORY,"aegis");
  if(!factory || esp_ota_set_boot_partition(factory)!=ESP_OK) blocked("cannot restore AEGIS next boot");
  const esp_partition_t *next=esp_ota_get_boot_partition();
  if(!next || next->address!=factory->address) blocked("factory selection did not persist");
  Preferences state;
  if(!state.begin("aegis-chain",false)) blocked("handoff storage unavailable");
  AegisTicket ticket={};
  bool have=state.getBytesLength("ticket")==sizeof(ticket) && state.getBytes("ticket",&ticket,sizeof(ticket))==sizeof(ticket);
  // Consume before any success action. Missing tickets are not successes.
  bool removed=!state.isKey("ticket") || state.remove("ticket"); state.end();
  AegisMeasurement image;
  const esp_partition_t *running=esp_ota_get_running_partition();
  bool selected=running && running->subtype==ESP_PARTITION_SUBTYPE_APP_OTA_0 && !strcmp(running->label,"payload");
  if(!removed) blocked("cannot consume handoff record");
  bool imageValid=selected && measureImage(running,true,image);
  if(!aegisTicketAllows(ticket,have,removed,esp_reset_reason()==ESP_RST_SW,true,imageValid,image.hash,image.version)) {
    Serial.begin(115200); Serial.println("[PAYLOAD] No valid one-use handoff; returning to AEGIS");
    Serial.flush(); esp_restart(); blocked("restart returned");
  }
  Serial.begin(115200); delay(300);
  Serial.println("Booted successfully");
}
void loop() { delay(1000); }
