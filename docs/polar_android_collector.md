# Polar Android Collector / Rust Bridge

## Status

K5-12 implements the software boundary for a Polar Verity Sense collector. The
Android build and host-side Rust tests are reproducible in CI. Real-device BLE,
Android hardware attestation, native-library packaging, latency, and sustained
wear tests remain `NOT_VERIFIED`; those measurements belong to K5-14 (#19).

## Fixed integration profile

| Item | Fixed value |
|---|---|
| Polar BLE SDK | `8.1.0` |
| Android minimum SDK | `33` |
| PPG candidate | `55 Hz`, only when offered by the connected device |
| ACC candidate | `52 Hz`, only when offered by the connected device |
| Source ceiling | `PairedCommercialSensor` |
| Sensor-signed source | Forbidden; this adapter does not create such a claim |
| Skin contact | Not used as a sole worn/not-worn detector |
| Batch bound | At most 512 samples, at most 8 PPG channels |

The SDK pin was checked against the official release page on 2026-08-14. The
official Android API requires querying `requestStreamSettings` before starting
`startPpgStreaming` or `startAccStreaming`. The current Verity Sense product
table includes online PPG 55 Hz and ACC 52 Hz. Device offers remain authoritative:
the collector refuses to invent or request an unsupported setting.

## Private path

```text
Polar BLE SDK
  -> typed PPG/ACC batch conversion
  -> bounded Kotlin bridge
  -> bounded Rust JNI copy
  -> private acquisition processing boundary
```

Both Kotlin and Rust temporary arrays are overwritten immediately after the JNI
call. A disconnect, cancellation, malformed batch, unsupported rate, poisoned
bridge lock, or unavailable native library fails closed and moves the public
surface to `FAULT`/cover behavior. The UI and notification expose only a small
public status enum. They expose no samples, feature values, baseline values,
device identifier, acceptance counts, or provenance evidence.

`PrivateBaselineStore` encrypts baseline material with a non-exportable Android
Keystore AES-GCM key. `AndroidKeyAttester` is only the platform evidence collection
boundary: K5-07 remains responsible for certificate-chain appraisal and NPL1
issuance. Merely generating an Android attestation chain does not establish AEPA
or authorize production ATv2 issuance.

## Build separation

Ordinary `debug` and `release` builds set `ALLOW_RAW_DEBUG=false`. The separate
`lab` application ID is the only build type with the flag enabled; no raw viewer
or raw logger is implemented even there. `preBuild` rejects common logging and
analytics APIs from `src/main`. The app declares no internet permission and has
no analytics or cloud dependency.

The JNI crate produces `libnoticer_android_bridge.so`. Packaging it for Android
ABIs is intentionally not represented as verified until K5-14 runs the pinned
NDK/cargo-ndk process on the target hardware. An APK that lacks the library fails
closed at collector start rather than falling back to a Kotlin raw-data path.

## Reproducible checks

```bash
cd android/collector
gradle :app:testDebugUnitTest :app:assembleDebug
cd ../..
cargo test --manifest-path android/collector/native/Cargo.toml
```

The repository CI runs both commands. The Kotlin tests cover setting negotiation,
state transitions, conversion, immediate buffer wiping, and the production-safe
debug variant. The Rust tests cover exact rates, batch bounds, monotonic time,
shape validation, and purge/revocation.

## Upstream and license record

- Polar BLE SDK release: <https://github.com/polarofficial/polar-ble-sdk/releases>
- Android API: <https://polarofficial.github.io/polar-ble-sdk/polar-sdk-android/com/polar/sdk/api/PolarOnlineStreamingApi.html>
- Verity Sense capabilities and skin-contact warning: <https://github.com/polarofficial/polar-ble-sdk/blob/master/documentation/products/PolarVeritySense.md>
- SDK license and notices: <https://github.com/polarofficial/polar-ble-sdk/blob/master/LICENSE>
- Third-party notices: <https://github.com/polarofficial/polar-ble-sdk/blob/master/ThirdPartySoftwareListing.txt>

The Polar SDK license and third-party notices must be included in any distributed
application as required by their terms. This repository records the dependency;
it does not relicense or imply endorsement by Polar Electro.
