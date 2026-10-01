#pragma once
#include <stdint.h>
constexpr uint32_t AEGIS_TICKET_MAGIC=0xAE615202;
struct AegisTicket { uint32_t magic; uint32_t version; char payloadHash[65]; uint8_t reserved[3]; };

#include <string.h>
inline bool aegisTicketAllows(const AegisTicket &ticket,bool present,bool consumed,bool softwareReset,bool factoryRestored,bool imageValid,const char *hash,uint32_t version) {
  return present && consumed && softwareReset && factoryRestored && imageValid && ticket.magic==AEGIS_TICKET_MAGIC &&
    ticket.payloadHash[64]==0 && ticket.version==version && !strcmp(ticket.payloadHash,hash);
}
