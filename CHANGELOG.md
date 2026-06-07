## V2.3.4 — Deep Bug Fix Release

### Critical Fixes
- Fix AOSP attestation failure from hardcoded patch levels in Rust COSE
- Fix keystore crash on FLAG_ONEWAY (reply!! NPE in BinderInterceptor)
- Fix BouncyCastle provider race condition (concurrent key generation)
- Fix algorithm normalization NPE (ECDSA vs EC in rotationCounters)
- Fix inject binary ABI-unaware path in KeystoreInterceptor, DrmInterceptor, TelephonyInterceptor
- Fix RKP keyPairCounter thread safety + overflow (AtomicInteger)
- Fix updateJson URL (tryigitx → tryigit)

### DRM / IMEI Fixes
- Fix TelephonyInterceptor fallback IMEI generation: wrong Luhn checksum (left-to-right instead of right-to-left) produced invalid IMEIs
- Fix TelephonyInterceptor inject deadlock: stdout/stderr pipe blocking replaced with redirectErrorStream
- Fix DrmInterceptor inject path ABI resolution

### AOSP Compatibility Fixes
- Fix createExtension() null return NPE chain
- Fix rootOfTrust null dereference in hackCertificateChain
- Fix boot key/hash null in createExtension (random fallback)
- Fix device properties NPE (individual null guards)
- Fix missing ro.oem_unlock_supported in hide props

### Safety Improvements
- Fix KeyCache.values() ConcurrentModificationException

## Changelog

- Changelog and other stuff Github.

Github:
github.com/tryigit/CleveresTricky
