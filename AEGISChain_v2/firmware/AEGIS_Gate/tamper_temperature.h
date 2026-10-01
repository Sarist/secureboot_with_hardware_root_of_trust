#pragma once
#if AEGIS_ENABLE_TEMPERATURE
#include <OneWire.h>
#endif
// 0 disabled, 1 pass, 2 out-of-range, 3 read/configuration error.
inline uint8_t readTemperature(int32_t &milli) {
#if AEGIS_ENABLE_TEMPERATURE
  milli=0;
  if(AEGIS_TEMP_MIN_MILLI>AEGIS_TEMP_MAX_MILLI) return 3;
  OneWire bus(AEGIS_TEMPERATURE_PIN); uint8_t rom[8],second[8],data[9];
  bus.reset_search();
  if(!bus.search(rom) || rom[0]!=0x28 || OneWire::crc8(rom,7)!=rom[7] || bus.search(second)) return 3;
  if(!bus.reset()) return 3;
  bus.select(rom); bus.write(0xb4); if(bus.read_bit()!=1) return 3; // external power only
  if(!bus.reset()) return 3;
  bus.select(rom); bus.write(0x44); delay(800);
  if(bus.read_bit()!=1 || !bus.reset()) return 3;
  bus.select(rom); bus.write(0xbe);
  for(auto &v:data) v=bus.read();
  if(OneWire::crc8(data,8)!=data[8]) return 3;
  int16_t raw=int16_t(uint16_t(data[0]) | uint16_t(data[1])<<8);
  milli=int32_t(raw)*1000/16;
  if(milli < -55000 || milli > 125000) return 3;
  return milli>=AEGIS_TEMP_MIN_MILLI && milli<=AEGIS_TEMP_MAX_MILLI ? 1:2;
#else
  milli=AEGIS_DISABLED; return 0;
#endif
}
