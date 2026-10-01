#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>
#include <AegisPolicy.h>
#include <AegisResponse.h>
#include <AegisEncoding.h>
#include <AegisImageLayout.h>
#include <AegisHandoff.h>
bool readBytes(void *ctx,uint32_t off,void *out,size_t n) {
  auto &v=*static_cast<std::vector<uint8_t>*>(ctx);
  if(off>v.size() || n>v.size()-off)return false;memcpy(out,v.data()+off,n);return true;
}
int main(int argc,char **argv) {
  if(argc<2)return 2;std::string op=argv[1];
  if(op=="image") {
    if(argc!=3)return 2;std::ifstream file(argv[2],std::ios::binary);std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),{});
    uint32_t length=0;bool ok=aegisImageLength(readBytes,&data,data.size(),length);std::cout<<(ok?length:0);return 0;
  }
  std::string input((std::istreambuf_iterator<char>(std::cin)),{});JsonDocument doc;
  if(deserializeJson(doc,input)){std::cout<<"BLOCK";return 0;}
  bool ok=false;
  if(op=="challenge")ok=validChallenge(doc["response"],doc["report"]);
  else if(op=="approval")ok=validApproval(doc["response"],doc["report"],doc["id"],doc["nonce"]);
  else if(op=="checks") {
    GateChecks c; c.identity=doc[0];c.atecc=doc[1];c.image=doc[2];c.version=doc[3];c.tamper=doc[4];c.server=doc[5];c.binding=doc[6];ok=c.passed();
  } else if(op=="version")ok=versionAllowed(doc["version"],doc["floor"],doc["highest"]);
  else if(op=="sensor")ok=sensorAllowed(doc["state"],doc["value"],doc["required"],doc["min"],doc["max"]);
  else if(op=="ticket") {
    AegisTicket t={};t.magic=doc["magic"];t.version=doc["version"];strncpy(t.payloadHash,doc["hash"]|"",64);
    ok=aegisTicketAllows(t,doc["present"],doc["consumed"],doc["software_reset"],doc["factory_restored"],doc["image_valid"],doc["actual_hash"],doc["actual_version"]);
  } else if(op=="encode") {
    uint8_t data[AEGIS_REPORT_BYTES];if(!encodeReport(doc["report"],doc["id"],doc["nonce"],data,sizeof(data))){std::cout<<"BLOCK";return 0;}
    const char *hex="0123456789abcdef";for(auto b:data)std::cout<<hex[b>>4]<<hex[b&15];return 0;
  }
  std::cout<<(ok?"ALLOW":"BLOCK");return 0;
}
