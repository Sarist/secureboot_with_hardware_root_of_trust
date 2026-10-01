#pragma once
#include <stdint.h>
struct GateChecks {
  bool identity=false, atecc=false, image=false, version=false, tamper=false, server=false, binding=false;
  bool passed() const { return identity && atecc && image && version && tamper && server && binding; }
};
constexpr int32_t AEGIS_DISABLED = INT32_MIN;
inline bool sensorAllowed(uint8_t state, int32_t value, bool required, int32_t low, int32_t high) {
  if (low > high) return false;
  if (state == 0) return !required && value == AEGIS_DISABLED;
  return state == 1 && value != AEGIS_DISABLED && value >= low && value <= high;
}
inline bool versionAllowed(uint32_t version, uint32_t floor, uint32_t highest) {
  return version > 0 && version <= INT32_MAX && version >= floor && version >= highest;
}
