# Setup and first hardware test

Run commands from the extracted `AEGISChain_v2` directory (or this repository's `aegischain` directory). Use an ESP32-WROOM board with 4 MB flash. Keep the old v1 installation as a backup. This workflow replaces bootloader, partition table and both application images while preserving NVS at `0x9000`–`0xdfff`; it is not a general migration for arbitrary flash layouts.

## 1. Connect the hardware

Keep power off while wiring. SparkFun ATECC608A: 3.3 V, common GND, SDA → GPIO21, SCL → GPIO22; I2C address `0x60`. Your chip was detected as `01238B9993793ACCEE`, both zones unlocked. **Use mode 2 for this chip.** Mode 1 requires a previously provisioned, compatible existing key and fails if the zones are unlocked; it never fixes/provisions them automatically.

Sensors default to explicitly DISABLED. To enable later, change the corresponding flags in private `config.h`, rebuild, and approve the new gate hash:

- DS18B20: external 3.3 V power, common GND, data GPIO4 with 4.7 kΩ pull-up to 3.3 V; exactly one supported sensor. Parasite power is rejected. Thresholds are milli-degrees Celsius (`70000` = 70 °C).
- Voltage: 3.3 V rail → 10 kΩ → GPIO34 → 10 kΩ → GND. Divider factor 2; common ground; ADC1. Never connect an out-of-range voltage directly to ESP32 GPIO. Verify/calibrate against a meter before enabling; thresholds are millivolts (`3300` = 3.3 V).

These are sampled startup checks, not high-speed glitch detectors or continuous payload monitoring.

## 2. Install tools and dependencies

Install Python 3.11 or later and Arduino CLI, and put `arduino-cli` on PATH. Core/library versions below match the existing project. OneWire is used only when temperature checking is enabled. No external ECCX08 library is needed.

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.lock.txt
arduino-cli core update-index --additional-urls https://espressif.github.io/arduino-esp32/package_esp32_index.json
arduino-cli core install esp32:esp32@3.3.2 --additional-urls https://espressif.github.io/arduino-esp32/package_esp32_index.json
arduino-cli lib install ArduinoJson@7.4.2
arduino-cli lib install OneWire@2.3.8
```

If PowerShell disallows activation, use `.\.venv\Scripts\python.exe` wherever these instructions say `python`; changing execution policy is unnecessary.

Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock.txt
arduino-cli core update-index --additional-urls https://espressif.github.io/arduino-esp32/package_esp32_index.json
arduino-cli core install esp32:esp32@3.3.2 --additional-urls https://espressif.github.io/arduino-esp32/package_esp32_index.json
arduino-cli lib install ArduinoJson@7.4.2
arduino-cli lib install OneWire@2.3.8
```

You may need your distribution's `python3-venv` package and serial-port group permissions. Host validation was performed on Linux/Python 3.14; Windows execution remains to be checked on your machine.

## 3. Configure TLS and Wi-Fi

Find the server PC's LAN IPv4 address using `ipconfig` (Windows) or `ip -4 addr` (Linux). The board must reach it on the same network. Substitute that address for the example below:

```text
python tools/setup_tls.py --host 192.168.1.10 --mode 2
```

This creates private `firmware/AEGIS_Gate/config.h` and `runtime/` TLS files. Edit `WIFI_SSID` and `WIFI_PASSWORD` in `config.h` to your real credentials. The CA and API address are generated together. No old Wi-Fi credentials have been copied into this package. `AEGIS_REQUIRE_ATECC=1` checks that your connected chip is present even in software-demo mode; it does not make the signature hardware-backed.

Mode 0 is diagnostics only and always blocks handoff. Mode 2 explicitly uses the software key in ESP32 NVS. Mode 1 only uses an already provisioned ATECC key, with no fallback. The build without private config is mode 0.

The helper refuses to overwrite existing TLS/config files. If the PC's address changes, intentionally regenerate the certificate/config after preserving any settings, rebuild, and re-enroll the resulting gate hash. A LAN DHCP reservation avoids this. SNTP access is needed to obtain a valid clock for TLS; blocked time sync closes the gate.

## 4. Start the v2 backend

SQLite is the default; no external database setup is necessary. From this directory, in a terminal using the venv:

```text
python -m uvicorn backend.server:app --host 0.0.0.0 --port 8443 --workers 1 --ssl-keyfile runtime/server-key.pem --ssl-certfile runtime/server.pem
```

Leave it running. Allow inbound TCP 8443 on the PC's private/LAN firewall if necessary. Stop the old server first if it already occupies 8443. Use **one worker**: outstanding challenges are held in that process and are lost on restart (devices safely retry after reset).

Windows listener check:

```powershell
Get-NetTCPConnection -LocalPort 8443 -State Listen
curl.exe --cacert runtime/ca.pem https://192.168.1.10:8443/health
```

Linux health check:

```bash
curl --cacert runtime/ca.pem https://192.168.1.10:8443/health
```

Optional Supabase: apply `backend/schema.sql` in your own project, copy `.env.example` to `.env`, set `AEGIS_STORE=supabase`, `SUPABASE_URL` and a server-only service-role `SUPABASE_KEY`. Keep that key on the PC. V2 uses additive `aegis_v2_*` tables; it does not modify old tables. Restart the backend after environment changes. The local enrollment tool must use the same environment/store. Hosted Supabase integration was not exercised here.

## 5. Build both applications

In a second terminal, activate the same venv and run:

```text
python tools/build_flash.py build --payload-version 1
```

The helper stages both sketches with `partitions/aegis_dual.csv`, compiles them, checks table consistency and image sizes/checksums/hashes, and writes `build/manifest.json`. The manifest contains the exact gate hash, payload hash, version and flash offsets for **your** build. Compile paths/settings/timestamps and any config change can change hashes: approve the artifacts you actually flash.

**Do not use Arduino IDE Upload, generated `merged.bin`, or Arduino's `boot_app0.bin` for this layout.** The helper supplies erased OTA metadata so factory AEGIS runs first. There is no single preconfigured final binary because your Wi-Fi and CA are local.

## 6. Flash with NVS preservation

Close the serial monitor. Find the port with `arduino-cli board list` (examples: `COM5`, `/dev/ttyUSB0`). Preview first:

```text
python tools/build_flash.py flash --port COM5
```

Then execute the reviewed plan:

```text
python tools/build_flash.py flash --port COM5 --execute
```

Linux uses the same command with `--port /dev/ttyUSB0`. Hold BOOT during connection if your board requires manual download mode.

Before writing, the helper saves the old partition table and NVS into ignored `runtime/backups/`, and rejects incompatible existing NVS locations/sizes. It never mass-erases flash, writes NVS, programs eFuses or accesses the ATECC. The NVS backup contains secrets; keep it private. The old `aegis-demo/private` key is reused if intact. New gate state uses `aegis-chain`.

## 7. Read identity and enroll

Open the serial monitor at 115200 (Arduino IDE monitor is fine; do not click Upload), then press EN/reset. Expect these enrollment fields followed by a closed gate because the new v2 identity is not yet approved:

```text
HARDWARE_ID=...
ATECC_SERIAL=...
GATE_HASH=...
PAYLOAD_HASH=...
PAYLOAD_VERSION=1
MODE=software_demo
PUBLIC_KEY=...
[GATE] APPLICATION BLOCKED
```

Public key is printed after successful Wi-Fi/time initialization. If it is missing, fix the preceding error. Confirm both hashes match `build/manifest.json` (`images.aegis.sha256`, `images.payload.sha256`). The prior v1 full-partition hash is not valid for v2.

Run the following **one-line** command in a third terminal using the same venv/database, replacing the three uppercase placeholders with your trusted output:

```text
python tools/enroll.py --id D4E9F4A48E94 --atecc-serial 01238B9993793ACCEE --public-key YOUR_PUBLIC_KEY --gate-hash YOUR_GATE_HASH --payload-hash YOUR_PAYLOAD_HASH --mode software_demo --minimum-payload-version 1
```

Use the actual printed ID/serial if different. Enrollment is your local operator trust decision, not an unauthenticated HTTP endpoint. The database stores public keys, never device private keys.

When enabling sensors, additionally enroll with `--require-temperature --require-voltage` and appropriate `--temperature-min`, `--temperature-max`, `--voltage-min`, `--voltage-max`. These integer limits use the units above. Until then both sensor requirements remain false and readings explicitly say DISABLED.

## 8. First acceptance test

Reset. Expected sequence: gate → matching identity/images/version → sensor policy → fresh HTTPS challenge → signature verified → fully bound approval → final checks → launch → software reboot → separate payload restores factory selection → payload prints its success line. The exact success text is in the payload sketch. It should appear once per successful run.

Press EN again and then test a full power cycle: each must show AEGIS Gate and a fresh server exchange before payload success. Record the entire serial log, not just the final line.

Next, stop the server and reset: expect a clear gate failure, APPLICATION BLOCKED, and no payload success. Restart the server and reset to recover. Run the additional non-destructive negative cases in VALIDATION.md. Never short the power rail to demonstrate tamper.

On every changed build, inspect the new manifest and deliberately update enrollment. Raising payload version persists an NVS highest-seen floor; lowering the server floor alone will not undo it. Do not clear NVS as a routine fix: that destroys the demo identity and rollback history.

## 9. Host checks and simulation

```text
python -m pytest -q tests
python tools/demo_roundtrip.py --url https://192.168.1.10:8443 --ca runtime/ca.pem
```

The simulator enrolls only synthetic ID `DE0000000002` and tests HTTPS/signatures/replay; it does not authorize or boot the physical board. Native C++ tests require g++/clang++ and ArduinoJson headers, otherwise they are explicitly skipped. Linux's default header location is `~/Arduino/libraries/ArduinoJson/src`; set `ARDUINOJSON_INCLUDE` to your actual location (often `Documents/Arduino/libraries/ArduinoJson/src` on Windows). Do not treat a skipped native test suite as fully validated.
