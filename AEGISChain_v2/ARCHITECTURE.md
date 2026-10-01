# Architecture and trust boundaries

## Chain and handoff

```text
ROM → normal ESP32 second-stage bootloader → factory AEGIS Gate
  → restore factory as next boot; remove stale handoff record
  → read ESP MAC-derived ID and ATECC serial/config (read-only)
  → verify image format/checksum; measure gate and separate payload
  → read payload's embedded version; enforce local NVS floor
  → require configured sensor checks to pass
  → connect Wi-Fi, obtain time, validate server TLS certificate
  → server checks local operator enrollment and image/version/sensor policy
  → receive fresh nonce + challenge ID + exact report echo
  → explicit signer signs SHA-256(canonical report)
  → server verifies signature, consumes challenge, writes audit record
  → gate validates complete approval binding, version floor, freshness
  → repeat sensor/image/identity checks; require every stage to pass
  → persist/read back highest version and one-use payload ticket
  → select payload OTA partition; restart
  → payload immediately restores factory as next boot target
  → consume ticket, require software-reset reason and image/version match
  → payload application action
Next reset/power-on → factory AEGIS Gate again
```

A single boolean success response is insufficient. The gate validates the entire response schema and all bound values. Final stage flags all must be true (`GateChecks::passed`); there is no XOR of successful booleans. Random microsecond delays and redundant reads are experimental fault-hardening measures, not validated glitch immunity. ESP random generation is used after Wi-Fi is enabled for signer randomness and jitter; this is not evidence of physical attack resistance.

## Three trust levels

1. ESP hardware ID is a public enrollment identifier, not an authenticator.
2. ATECC mode proves use of an enrolled existing P-256 key inside a compatible secure element. The normal gate can read configuration, obtain the public key and sign; its driver rejects persistent Write, Lock and private-key generation operations. Software-demo mode stores an extractable P-256 private key in ESP NVS, prints that limitation, and never silently replaces hardware mode.
3. This build does not enable ROM-enforced secure boot or flash encryption. An attacker able to replace the gate can lie about measured code, manipulate NVS, or request ATECC signatures on chosen reports. ATECC key possession alone is not trusted ESP32 measured boot. The self-measurement and server allowlist are useful PoC policy, not an immutable measurement chain.

## Flash layout (4 MB)

| Region | Offset | Size | Purpose |
|---|---:|---:|---|
| Bootloader | `0x1000` | below `0x8000` | Stock core build |
| Partition table | `0x8000` | `0x1000` | Explicit CSV |
| nvs | `0x9000` | `0x5000` | Existing demo key, highest version, ticket |
| otadata | `0xe000` | `0x2000` | Initialized erased for factory boot |
| aegis / factory | `0x10000` | `0x180000` | AEGIS Gate |
| payload / ota_0 | `0x190000` | `0x180000` | Independent application |
| spiffs | `0x310000` | `0xe0000` | Reserved, not used by prototype |
| coredump | `0x3f0000` | `0x10000` | Reserved |

The CSV is authoritative. The build helper verifies compiled partition tables and generates the flash manifest from it. ESP-IDF selects factory with erased OTA data and supports app selection through `esp_ota_set_boot_partition`; see [Espressif OTA documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/system/ota.html).

## Deterministic measurements

Both images must have a valid ESP image structure with appended SHA-256. On the ESP, `esp_image_verify` validates the image, then the shared bounded parser determines the image length: header, all segments, checksum alignment/padding internal to the image, and appended 32-byte digest. SHA-256 covers exactly those bytes. Unused partition tail is excluded. This approval digest is distinct from the embedded digest and from an ELF hash.

The payload contains a 20-byte custom descriptor after `esp_app_desc_t`: a 16-byte magic field plus little-endian uint32 version. Version is measured as part of the payload, not supplied only by the gate's configuration. Host tooling checks the checksum and appended digest as well. Descriptor placement is checked against compiled images and covered by tests. Rebuilding can change image bytes and thus approval hashes.

## Signed protocol

Requests use strict JSON as transport; signatures use fixed-width canonical bytes, independent of JSON key order. Protocol is `AEGISChain-v2`. `POST /api/v2/device/challenge` takes exactly the 11 report fields in `backend/protocol.py`. It returns those fields, a challenge ID, nonce and `expires_in=30`. `POST /api/v2/device/verify` takes exactly hardware ID, challenge ID and signature. Approval returns the original signed report plus `authenticated=true`, minimum version and `scope=application_gate_poc`.

The signature is ECDSA P-256 over SHA-256 of this concatenation:

| Field | Encoding |
|---|---|
| Domain | ASCII `AEGISChain-v2` followed by NUL (13 bytes) |
| Hardware ID | 12 uppercase ASCII hex characters |
| ATECC serial | 9 decoded bytes |
| Challenge ID | 16 decoded bytes |
| Nonce | 32 decoded bytes |
| Gate SHA-256 | 32 decoded bytes |
| Payload SHA-256 | 32 decoded bytes |
| Payload version | uint32 big-endian |
| Mode | uint8: 1 ATECC, 2 software demo |
| Temperature state | uint8 |
| Temperature value | int32 big-endian, milli-degrees Celsius |
| Voltage state | uint8 |
| Voltage value | int32 big-endian, millivolts |

Total: 161 bytes. Sensor state: 0 DISABLED, 1 PASS, 2 TAMPER, 3 ERROR. Disabled value must be `-2147483648`; an enabled state cannot use that sentinel. Server rejects TAMPER/ERROR and readings outside its own policy, even if the client labels them PASS. Zero ATECC serial is allowed only outside hardware mode, for an explicitly configured chip-optional demo.

Signature transport is lowercase hex of 64 raw bytes `r || s`, each 32-byte big-endian. Public key is SEC1 uncompressed P-256 (`04` followed by X/Y, 65 bytes). Shared C++ encoding is tested against Python's digest implementation.

Challenges expire after 30 monotonic seconds, are atomically removed on verification attempt, and bind an entire enrollment snapshot. Changed enrollment rejects in-flight challenges. At most four pending challenges per identity and 1024 total are retained. Responses are bounded to 2048 bytes, require Content-Length, and are rejected for unexpected fields, types or values. TLS verifies CA/hostname, redirects are disabled, and connection/handshake/read deadlines are bounded. The gate checks the approval age again immediately before boot selection.

Approval is authenticated by the TLS connection, not by a separate server signature. Server floor/result/timestamp are not device-signed. The signature covers the reported sensor snapshot; additional final readings are local decisions and are not retroactively included in that snapshot.

## Rollback and audit

The backend allowlists both exact image hashes and a minimum payload version. The gate also preserves the highest authorized version in NVS and checks it on later boots. NVS protection is mutable PoC state, not OTP/eFuse protection; raw flash access can remove it. An approved higher version advances the floor before launching, even if a later launch fails.

Audit rows retain canonical-report fields, raw signature, verification public key, enrollment revision, server timestamp and result. `tools/verify_audit.py exported-row.json` checks the report signature. An embedded public key must itself be compared with a separately trusted enrollment record. Database timestamps/results and log completeness are not authenticated by that signature. Known-challenge verification attempts are logged; unknown/replayed IDs and initial policy rejections are not a complete forensic event stream. A database write failure prevents approval.

## Limits that remain

- Payload machine code must execute to restore factory selection and validate its ticket. Thus a selected payload can enter its guard code without a new gate run after an interrupted handoff. Cold resets do not pass the ticket's software-reset requirement and return to the gate without doing the demo action. This reduces accidental bypass; it cannot enforce a literal guarantee that no payload instruction ever executes before checks.
- The unprotected ticket is not a cryptographic boot authorization. OTA metadata corruption, power loss at selection boundaries, or malicious flash/NVS replacement require a real trusted bootloader to handle securely. Physical reset/power tests are still pending.
- Temperature conversion and sampled ADC checks are slow relative to voltage glitches. Sensors can be spoofed, a floating ADC input may look plausible, and no runtime tamper monitor is installed in the tiny payload. See [Espressif ADC API](https://docs.espressif.com/projects/arduino-esp32/en/latest/api/adc.html) and [DS18B20 datasheet](https://www.analog.com/media/en/technical-documentation/data-sheets/DS18B20.pdf).
- No authenticated OTA delivery/updater, tamper-protected audit storage, distributed challenge storage or production denial-of-service defense is provided.
- Wi-Fi credentials remain extractable from an unencrypted configured firmware image. Ignoring config prevents accidental source sharing; it does not encrypt flash. Software private keys are runtime NVS data and may not exist in a compile-produced app binary, but can be extracted from a full device flash dump.
- No ChipWhisperer evidence, secure debug, TrustZone, PUF, hardware rollback counters or certification. OTP is one-time programmable, not something this design can erase as a tamper response. Future EFR32 features must be verified against that part's supported hardware rather than inferred from this demo.
