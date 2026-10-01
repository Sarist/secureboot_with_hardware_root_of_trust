# Audit and upgrade record — 2026-09-23

The existing source, prototype firmware/driver, backend/protocol/storage, tests, enrollment/TLS tools, SQL and documentation were reviewed before implementation. Earlier binary-review reports and packaged artifacts were inspected as context. Build caches/dependency-generated files were not treated as authored security code. The original implementation and archives remain in place; the corrected dual-application implementation is isolated in `aegischain/`.

## What was already correct

The working v1 prototype already separated diagnostic, existing-ATECC and explicit software-demo modes; normal boot did not provision/lock the chip. It used CA-validated HTTPS, explicit enrollment, canonical P-256 signing, nonce/challenge binding, expiry, single-use challenges, strict schemas, bounded response handling, fail-closed application gating and audit evidence. The existing 18 passing tests still pass.

The user's physical logs prove software-mode authentication and ATECC communication, not ATECC signing. The most recent hardware report identifies chip `01238B9993793ACCEE` with both zones unlocked. Preserving that state is a requirement, not an error to auto-correct.

## Findings and resolution

| Finding | Resolution / remaining scope |
|---|---|
| Original heartbeat shared the gate image; no independent application boot | Separate factory gate and OTA payload, guarded one-use handoff and early factory restoration |
| Hash covered entire partition and depended on unused/padding bytes | Validate and hash exact image length; separate gate/payload approvals |
| No measured payload version or enforced rollback policy | Embedded payload descriptor, server minimum and persistent NVS high-water mark; NVS is not immutable |
| No modular implemented startup sensor policy | DS18B20 and ADC1 modules, compile flags, explicit DISABLED state, signed values and server requirements |
| Old signed protocol had no independent payload/version/sensor binding | Versioned canonical v2 encoding, strict full response matching, additive v2 schema/API |
| Arduino merged image initializes OTA selection incompatibly with gate-first layout | Flash helper supplies erased OTA data and explicit offsets, verifies artifacts, backs up/preserves NVS |
| Driver response handling could consume incompletely initialized response data; unnecessary APIs existed | Bounded count/CRC-checked initialized response buffer, wake/idle failures checked, bus set to 100 kHz, unused unsupported APIs removed; persistent commands remain prohibited |
| Source and old binary contained real Wi-Fi credentials | New package has placeholders and ignored private config only; original evidence untouched. Configured images still expose credentials without flash encryption |
| Hardware ID/ATECC/secure boot claims could be conflated | Three trust levels documented; no hardware signing or ROM secure boot claim from detection alone |
| Old conceptual XOR token example did not require all checks | Explicit all-stage policy, sequential fail-closed exits, redundant final checks and shared C++ tests |
| A plain server success can authorize the wrong exchange | Gate rejects wrong ID/serial/hash/version/mode/nonce/challenge/sensor response even with HTTP 200 |
| Enrollment changes during challenge could invalidate approval | Full enrollment snapshot/revision checked before and after signature verification |
| Existing project had no reproducible dual-image flash procedure | Pinned core/libraries, CSV, compiler helper, verified manifest and Windows/Linux guide |
| Irreversible operations were unsuitable for this board | No provisioning tool added, no ATECC changes or eFuse programming performed |

The upgrade cannot eliminate mutable boot/NVS and OTA handoff edge cases within an Arduino application gate. They remain explicit in ARCHITECTURE.md. The phrase “payload must never run on failure” applies to the intended gate decision and payload application action; enforcing it before any payload instruction requires a trusted bootloader.

## Preservation and migration

Original `prototype/`, old sketches, binary reviews and ZIPs are left intact. V2 does not trust old full-partition approvals automatically. Re-enroll using the new actual-image hashes and bound ATECC serial; the software key remains reusable because the existing NVS layout and namespace are preserved. No existing external service or physical board was changed during this work.

The fresh ZIP excludes all runtime databases, private keys/configuration, flash dumps and compiled images. Review `PACKAGE_SHA256SUMS.txt` inside it to check its source/document inventory. Do not redistribute the original repository wholesale without removing its old exposed credentials.
