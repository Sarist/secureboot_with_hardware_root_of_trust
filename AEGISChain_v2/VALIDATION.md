# Validation — 2026-09-23

## Completed in this workspace

- Original v1 backend suite: **18 passed**, unchanged.
- V2 suite: **131 passed**, zero skips. Two upstream FastAPI/Starlette deprecation warnings; no test failures.
- Actual shared C++ response, canonical encoding, image-length, gate policy and handoff policy headers compiled using g++ and exercised by pytest. This is native policy testing, not ESP32 emulation.
- Real loopback Uvicorn HTTPS: trusted certificate succeeds, untrusted certificate rejects, stopped server is unreachable, valid signature succeeds and replay rejects.
- Arduino CLI / ESP32 core **3.3.2**, ArduinoJson **7.4.2**, OneWire **2.3.8**, ESP32 Dev Module compiled successfully:

| Build variant | Program bytes reported | Global data bytes |
|---|---:|---:|
| Gate diagnostics, default config | 922323 | 44992 |
| Gate hardware signer, sensors disabled | 1077623 | 48144 |
| Gate software demo, sensors disabled | 1077775 | 48272 |
| Gate software demo, both sensors enabled | 1089167 | 48360 |
| Separate payload, version 1 | 288599 | 20784 |

Each app fits its 1572864-byte slot. Hardware/software compile checks used synthetic credentials only. A successfully compiled hardware-signing path is **not** a successful ATECC signing experiment.

The complete build helper ran on the diagnostic/payload pair; compiled partition tables matched the CSV and independent host image validation passed. Actual image lengths: diagnostic gate 922464 bytes, payload 288752 bytes. Flash helper dry run uses offsets 0x1000, 0x8000, 0xe000, 0x10000 and 0x190000. **No board was flashed here.** NVS backup/write behavior needs the board test.

## Fail-closed matrix

| Scenario | Automated evidence | Physical test |
|---|---|---|
| Unknown/disabled ESP identity | HTTP policy rejection | Pending |
| Wrong ATECC serial or signer mode | Policy + signature/response binding | Pending |
| Wrong public key / invalid ECDSA | Verification rejection, consumed challenge | Pending |
| Modified signed fields | Signature rejection | Pending |
| Wrong payload or gate hash | Server policy + C++ response binding | Pending |
| Payload downgrade | Server floor + shared native NVS-floor policy | Pending persistence on ESP |
| Expired/replayed/wrong-device challenge | Expiry, concurrent single-use, identity binding | Pending |
| Enrollment/key change during challenge | Snapshot/revision rejection | Pending |
| Malformed requests/responses | Strict Python schemas + actual C++ response validators | Pending transport on ESP |
| Server unavailable / TLS trust failure | Real host network failure + native gate decision remains BLOCK | Pending ESP TLS path |
| Wi-Fi failure / network timeout | Simulated incomplete stage flags in actual native gate policy | Pending ESP radio/timeouts |
| Temperature/voltage tamper or required sensor disabled | Server policy + native sensor decisions | Pending real readings/calibration |
| Payload missing / corrupted | Empty/truncated/corrupted image rejection; native bounded parser; source null-partition guard | Pending flash/partition API path |
| Incorrect/missing/reused handoff ticket, cold reset | Native handoff predicates require every condition | Pending NVS/reset behavior |
| Unsafe flash offset or modified artifact | Helper rejects edited manifests/artifacts; dry run opens no serial port | Pending actual flash |
| Successful enrolled report, fresh signature, bound approval | Backend HTTPS + C++ validation and all-stage ALLOW | Pending actual separate-image launch |

These tests do not claim that a simulated network failure exercised Wi-Fi hardware, that an image fixture called `esp_image_verify`, or that a native ALLOW result booted an ESP32.

## Required board acceptance checklist

Start with sensors explicitly disabled and software-demo mode, because your chip is unlocked. Capture logs and firmware manifest for each case.

1. First flash with preserved NVS: gate runs first; v2 unknown identity is rejected. Confirm the old software public key remains the same if the previous NVS key was intact.
2. Enroll trusted output; reset. Gate passes, selects the separately measured payload, restarts, and payload prints its sole success line. Confirm distinct reset/boot between gate and payload.
3. Repeat EN reset and full power-off/on at least five times. Every normal cycle must pass through the gate and fresh server exchange.
4. Stop the backend; reset. No payload success. Restart and reset to recover. Disable the identity with the enrollment command plus `--disabled`, reset, then restore enrollment and retest.
5. Use a deliberately wrong approved payload hash (e.g. 64 zeroes); reset and verify denial, then restore the real hash. Repeat for gate hash and serial policy. No flash corruption is necessary for these policy tests.
6. Set the server minimum version above the actual version; verify denial, then restore the previous server floor. Separately build/approve payload version 2 and boot once; a later version-1 image must fail local NVS policy even if server approval is lowered. Plan this monotonic test deliberately; normal setup must not clear NVS.
7. On a spare test configuration, use incorrect Wi-Fi credentials or an unrelated CA; rebuild and check clear timeout/TLS failure. Restore correct settings and approve the resulting gate hash afterward.
8. Enable a real temperature sensor with correct wiring; calibrate voltage measurements before requiring them. Enable each server requirement, then safely test out-of-range thresholds and disconnected sensors. A missing DS18B20 must produce ERROR. A disconnected ADC input can float into a plausible range, so record this limitation rather than asserting guaranteed disconnection detection.
9. On a recoverable bench setup, omit the payload image or corrupt a test image and confirm image rejection; use the normal helper to recover. Test interrupted handoff power cycles without shorting/glitching supply rails.
10. Re-read ATECC lock bytes: they must remain `0x55`/`0x55` for your existing unprovisioned device. Hardware-mode signing requires a separately authorized, already provisioned compatible device; this release does not create one.

Physical fault injection, boot-selection power-loss edge cases, Windows tool execution and Supabase connectivity are unverified. No secure boot, flash encryption, eFuse or ATECC provisioning action was performed. Passing this checklist establishes a functional PoC demonstration; it does not establish fault resistance or certification.

## Repeat tests

Run from this directory using the venv:

```text
python -m pytest -q tests
python tools/build_flash.py build --payload-version 1
python tools/build_flash.py flash --port COM5
```

The last command is intentionally a dry run. See START_HERE.md for actual flash and enrollment. Native tests skip explicitly if a C++ compiler or ArduinoJson headers are missing; verify the summary has no unexpected skips. Tests use temporary stores/certificates and do not contact your deployed backend or device.
