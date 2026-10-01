#pragma once
inline uint8_t readVoltage(int32_t &milli) {
#if AEGIS_ENABLE_VOLTAGE
  static_assert(AEGIS_VOLTAGE_PIN>=32 && AEGIS_VOLTAGE_PIN<=39,"Use ADC1 with Wi-Fi");
  milli=0;
  if(AEGIS_VOLTAGE_MIN_MILLI>AEGIS_VOLTAGE_MAX_MILLI || AEGIS_VOLTAGE_DIVIDER<=0 || AEGIS_VOLTAGE_CALIBRATION<=0) return 3;
  analogReadResolution(12); analogSetPinAttenuation(AEGIS_VOLTAGE_PIN,ADC_11db);
  uint32_t sum=0;
  for(int i=0;i<16;i++) { sum+=analogReadMilliVolts(AEGIS_VOLTAGE_PIN); delay(1); }
  float pinMv=sum/16.0f;
  if(pinMv<100 || pinMv>3000) return 3; // open/short/near saturation; calibrate your actual divider
  float rail=pinMv*AEGIS_VOLTAGE_DIVIDER*AEGIS_VOLTAGE_CALIBRATION;
  if(!isfinite(rail) || rail<=0 || rail>100000) return 3;
  milli=int32_t(rail+0.5f);
  return milli>=AEGIS_VOLTAGE_MIN_MILLI && milli<=AEGIS_VOLTAGE_MAX_MILLI ? 1:2;
#else
  milli=AEGIS_DISABLED; return 0;
#endif
}
