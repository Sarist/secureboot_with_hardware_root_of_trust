#pragma once
// 0=diagnostics, 1=existing provisioned ATECC signer, 2=explicit software demo.
#define AEGIS_MODE 0
#define AEGIS_KEY_SLOT 0
#define AEGIS_REQUIRE_ATECC 1
#define AEGIS_ENABLE_TEMPERATURE 0
#define AEGIS_ENABLE_VOLTAGE 0
#define AEGIS_TEMPERATURE_PIN 4
#define AEGIS_TEMP_MIN_MILLI 0
#define AEGIS_TEMP_MAX_MILLI 70000
// GPIO34 ADC1; 10k/10k divider on measured rail, NOT direct 5V into ADC.
#define AEGIS_VOLTAGE_PIN 34
#define AEGIS_VOLTAGE_DIVIDER 2.0f
#define AEGIS_VOLTAGE_CALIBRATION 1.0f
#define AEGIS_VOLTAGE_MIN_MILLI 3000
#define AEGIS_VOLTAGE_MAX_MILLI 3600
static const char WIFI_SSID[]="CHANGE_ME";
static const char WIFI_PASSWORD[]="CHANGE_ME";
static const char API_BASE[]="https://192.168.1.10:8443";
static const char TLS_ROOT_CA[]=R"PEM(PASTE_YOUR_CA_CERTIFICATE_HERE)PEM";
