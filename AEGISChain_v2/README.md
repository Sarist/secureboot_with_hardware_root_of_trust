# AEGISChain v2

Advanced Embedded Guardian for Integrity and Security Chain.

This ESP32-WROOM proof of concept has **two separate applications**: a factory AEGIS Gate and an OTA payload. The gate authenticates an enrolled device and signed image/sensor report over HTTPS before selecting the payload. The payload restores the gate as the next boot target before doing application work.

**Start with [START_HERE.md](START_HERE.md)** for Windows/Linux installation, build, flash, server, enrollment and first hardware test. Read [AUDIT.md](AUDIT.md) for the original findings, [ARCHITECTURE.md](ARCHITECTURE.md) for the protocol/trust chain, and [VALIDATION.md](VALIDATION.md) for tested versus pending behavior.

The original working `../prototype/` and original archives are preserved. This directory is a deliberate v2 upgrade with a separate API and database; v1 enrollments do not automatically authorize v2.

## Status — updated 2026-09-24

- Implemented: separate gate/payload images, deterministic image measurement, version policy, one-use handoff record, HTTPS challenge-response, explicit software/ATECC signer selection, modular temperature/voltage checks, audit evidence, enrollment and build/flash tools.
- Verified here: host tests, actual shared C++ policy/response/encoding tests, loopback HTTPS tests and Arduino compilation. See validation details.
- Demonstrated on your board in the latest supplied serial log: v2 factory gate startup, gate/payload image measurement, payload version 1, temperature PASS, HTTPS challenge-response with the software demo key, final gate approval, software reset and execution of the separate payload. The payload printed `Booted successfully`.
- ATECC I2C communication and serial read succeeded. Both lock bytes remain `0x55` (unlocked). **ATECC is not the signer; hardware signing has not been demonstrated.**
- Temperature checking is enabled and reports PASS. Voltage checking remains explicitly DISABLED. A PASS reading is not evidence of calibration or resistance to tampering.
- Pending: repeated reset/power-cycle gate-first tests, server-off and other negative hardware tests, temperature calibration/out-of-range/disconnection tests, voltage monitoring validation, hardware-backed signing and physical fault injection.

This is an **application-controlled gate**, not ROM-enforced firmware authenticity. Replaced ESP32 firmware can bypass the gate and falsify measurements. The external secure element does not measure ESP32 code. There is no TrustZone, PUF protection, eFuse anti-rollback, protected debug or certification claim here. No provisioning, locking or eFuse programming is performed.

The success text is emitted only by the separate payload firmware, after its handoff checks. Gate failures prevent payload selection in the intended, unmodified execution path. The OTA selection window and unprotected NVS prevent an absolute physical-attack guarantee.

## Latest hardware demonstration

Evidence: user-supplied serial output, not a locally attached board test.

| Field | Observed value |
|---|---|
| ESP hardware ID | `D4E9F4A48E94` |
| ATECC serial | `01238B9993793ACCEE` |
| Data / configuration lock bytes | `0x55` / `0x55` (unlocked) |
| Signer | `software_demo` — private key in ESP32 NVS |
| Payload version | `1` |
| Gate image length | `1074752` bytes |
| Payload image length | `280656` bytes |
| Temperature / voltage | PASS / DISABLED |
| Result | Server accepted signature; gate launched separate payload successfully |

Observed gate SHA-256:

```text
a00dd375c474adc1aefb37788903ed938208a236726c804db9751fc075c51198
```

Observed payload SHA-256:

```text
82c3de672f9872e322528990e86ab32f4f577bc00b17ff9b623532d8c4395c77
```

These identify the demonstrated build, not universal approval values. Rebuilds or configuration changes can change the hashes; approve the actual artifacts using your build manifest and trusted serial output.

The observed sequence was:

```text
[TAMPER] Temperature: PASS, Voltage: DISABLED
[SERVER] Challenge received
[CRYPTO] Challenge signed
[SERVER] Signature accepted
[ATTEST] PASS (application-reported measurements)
[GATE] ALL CHECKS PASSED
[GATE] Launching application...
rst:0xc (SW_CPU_RESET)
Booted successfully
```

Temperature checks reported PASS at each logged sampling stage. The log confirms successful authentication with temperature checking enabled; it does not independently expose the database's required-sensor settings or prove rejection of bad readings. The recommended enrollment policy uses `--require-temperature --temperature-min 0 --temperature-max 70000` (0–70 °C).

## What to share with another AI

Send the clean `AEGISChain_v2_Setup.zip`, these documents, and a sanitized serial log. It includes both sketches, shared headers, driver, backend, schema, tools, tests and dependency versions. Do not send `config.h`, `.env`, `runtime/`, NVS dumps, private TLS keys or configured binaries. Build artifacts can contain the Wi-Fi password. Public keys/hashes are not private keys, but they identify your device.