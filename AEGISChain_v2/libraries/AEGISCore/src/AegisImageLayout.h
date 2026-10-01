#pragma once
#include <stddef.h>
#include <stdint.h>
// Callback reads offsets relative to one partition/file. Same parser runs in host tests.
using AegisReader = bool (*)(void*, uint32_t, void*, size_t);
inline uint32_t aegisLE32(const uint8_t *p) { return uint32_t(p[0]) | uint32_t(p[1])<<8 | uint32_t(p[2])<<16 | uint32_t(p[3])<<24; }
inline bool aegisImageLength(AegisReader read, void *ctx, uint32_t capacity, uint32_t &length) {
  uint8_t h[24]; length = 0;
  if (capacity < 24 || !read(ctx, 0, h, 24) || h[0] != 0xe9 || h[1] == 0 || h[1] > 16 || h[23] != 1) return false;
  uint32_t pos=24;
  for (uint8_t i=0; i<h[1]; ++i) {
    uint8_t seg[8];
    if (pos > capacity || capacity-pos < 8 || !read(ctx,pos,seg,8)) return false;
    uint32_t n=aegisLE32(seg+4); pos += 8;
    if (n > capacity-pos || (n & 3)) return false;
    pos += n;
  }
  // ESP image checksum is last byte of next 16-byte block, then 32-byte SHA.
  if (pos > UINT32_MAX-48) return false;
  uint32_t end=((pos+16)&~uint32_t(15))+32;
  if (end > capacity) return false;
  length=end; return true;
}
