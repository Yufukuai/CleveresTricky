# CleveresTricky

[![Build](https://github.com/tryigit/CleveresTricky/actions/workflows/build.yml/badge.svg)](https://github.com/tryigit/CleveresTricky/actions/workflows/build.yml)

### The Intelligent Android Security Module

CleveresTricky is a self-managing spoof root module that uses automated decision-making to keep your device passing integrity checks, rotating identities, and healing itself without manual intervention. It monitors, adapts, and corrects problems on its own.

---

## How It Works

Unlike traditional modules that apply static patches, CleveresTricky runs an always-on daemon that makes real-time decisions:

- **Self-Healing:** If SELinux contexts are lost after an OTA, the daemon detects and repairs them before every launch. No user action needed.
- **Adaptive Key Rotation:** Cryptographic keys rotate automatically every 24 hours. If a key is revoked, the system detects it and switches to the next valid key without interruption.
- **Automated Patch Sync:** When your security patch level falls behind (6+ months), the module updates it automatically to keep attestation passing.
- **Crash Recovery:** If the daemon crashes, the service restarts it with exponential backoff, logging every event. After exhausting retries, it backs off to prevent boot storms.
- **Live Configuration:** Changes to config files are detected instantly via FileObserver. No reboot needed.
- **Stealth Execution:** Property hiding runs inside compiled daemon code, not scannable shell scripts. The process disguises itself to avoid detection by integrity frameworks.

---

## Minimum Requirements

| Requirement | Details |
|-------------|---------|
| **Root Manager** | KernelSU v0.7.0+ (Zygisk Next) or APatch |
| **Android** | 12 or newer (API 31+) |
| **Architecture** | arm64-v8a, x86_64 |
| **SELinux** | Enforcing (module manages its own policy) |

> **TEE features** (IMEI provisioning, hardware attestation) require Qualcomm or MediaTek hardware. All other features work on any SoC.

---

## Features

### Pass Every Integrity Check

| What it does | How |
|--------------|-----|
| **Play Integrity DEVICE/STRONG** | Intercepts keystore at the Binder level and injects valid attestation chains |
| **KeyMint 4.0 attestation** | Full support for the latest hardware attestation protocol |
| **RKP (Remote Key Provisioning)** | Built-in local proxy generates RFC-compliant COSE/CBOR proofs signed with rotating secrets |
| **Device Recall Protection** | Neutralizes Google's persistent 3-bit device recall by randomizing all device identity signals (see below) |
| **Multi-keybox rotation** | Maintains a pool of keyboxes and rotates through them automatically (round-robin) |
| **Encrypted keyboxes (.cbox)** | AES-256-GCM containers with hardware-backed key storage |
| **Remote key servers** | Auto-fetches and validates keyboxes from configured community servers |
| **Automated revocation check** | Verifies keys against Google's CRL every 24 hours; switches to valid keys if revoked |

### Complete Identity Control

| What it does | How |
|--------------|-----|
| **IMEI / Serial / IMSI / ICCID** | System-wide spoofing via Binder interception (Qualcomm and MediaTek) |
| **Randomize on boot** | Generates a fresh identity every reboot: IMEI (Luhn-valid), Serial, MAC, device template |
| **Contact spoofing** | Per-app blank permissions for contacts, media, and microphone |
| **DRM ID reset** | Regenerates Widevine device ID with one click |
| **Location spoofing** | Simulates GPS coordinates with optional random drift within a configurable radius |
| **MAC randomization** | WiFi and Bluetooth MAC addresses randomized per boot or on demand |

### WebUI Dashboard

Manage everything from your browser at `http://localhost:5623`:

| Capability | Details |
|------------|---------|
| **Settings backup/restore** | Encrypted backup (.ctsb format, AES-256-GCM) with password protection. Upload to restore. |
| **Keybox management** | Upload, delete, verify, and rotate keyboxes. Supports XML, .cbox encrypted containers |
| **One-click profiles** | GodProfile, DailyUse, Minimal, Default -- each configures all toggles at once |
| **Per-app rules** | Assign templates, keyboxes, and blank permissions per application |
| **Live toggles** | Enable/disable features instantly without reboot |
| **Multi-language** | Fully translatable UI via lang.json |

### Spoof Modes

| Mode | What happens |
|------|-------------|
| **Target Only** (default) | Only apps in `target.txt` see spoofed values |
| **Global Mode** | All apps are spoofed; `target.txt` becomes an exclusion list |
| **IMEI Global** | IMEI/modem spoofing applies system-wide, independent of Global Mode |
| **Network Global** | WiFi/BT MAC spoofing applies system-wide, independent of Global Mode |

### Device Templates

Built-in profiles that set all Build properties at once:

`pixel8pro` `pixel7pro` `pixel6` `xiaomi14` `s23ultra` `oneplus11` and more.

Assign templates globally or per-app. The module applies the correct fingerprint, model, brand, security patch, and attestation IDs automatically.

### Platform Auto-Detection

| Feature | Qualcomm | MediaTek |
|---------|----------|----------|
| **TEE Attestation** | `/dev/qseecom` or `/dev/smd` | `/dev/tee0` |
| **IMEI Provisioning** | `provision_device_ids` | `provision_device_ids_mtk` |
| **Hardware Keystore** | Supported | Supported |

The module detects your chipset and uses the correct provisioning binary automatically.

### Self-Managing Architecture

| Component | Description |
|-----------|-------------|
| **Adaptive Binder Interceptor** | Version-immune hook architecture that discovers kernel struct layouts at runtime (see below) |
| **Stealth Daemon** | Runs as a disguised process. All property hiding happens in compiled code, not shell scripts. |
| **Crash Recovery** | Automatic restart with exponential backoff (5 retries, 3 cycles, 5-minute cooldown) |
| **SELinux Auto-Repair** | Contexts are verified and repaired before every daemon launch |
| **Hot Reload** | FileObserver detects config changes and applies them instantly |
| **Detailed Logging** | Every decision, rotation, failure, and recovery is logged with context |
| **Atomic File Writes** | Config writes use temp-file + rename to prevent corruption on power loss |
| **Thread-Safe State** | All shared configuration uses volatile fields and concurrent data structures |

---

## Quick Start

1. **Install** -- Flash the module ZIP from KernelSU/APatch manager and reboot
2. **Open WebUI** -- Navigate to `http://localhost:5623` in any browser (Configuration changes take effect immediately. No reboot needed)
3. **Add Keybox** *(optional)* -- Upload via WebUI or place at `/data/adb/cleverestricky/keybox.xml`
4. **Enable RKP** *(for STRONG integrity)* -- Toggle in WebUI or `touch /data/adb/cleverestricky/rkp_bypass`
5. **Set Targets** *(optional)* -- Add package names in WebUI or edit `/data/adb/cleverestricky/target.txt`


---

## Documentation

| Document | Description |
|----------|-------------|
| [LOG.md](LOG.md) | Logcat filters and debugging guide |
| [DETECTION_ANALYSIS.md](DETECTION_ANALYSIS.md) | Security analysis: eBPF, DroidGuard, timing checks |
| [FFI_SAFETY_NOTES.md](FFI_SAFETY_NOTES.md) | Rust FFI safety audit and memory ownership model |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute to the project |
| [LANGUAGES.md](LANGUAGES.md) | WebUI translation guide |
| [THEME.md](THEME.md) | WebUI theme customization |
| [DONATE.md](DONATE.md) | Support development |

---

## Configuration Reference

### Keybox (keybox.xml)

```xml
<?xml version="1.0"?>
<AndroidAttestation>
    <NumberOfKeyboxes>1</NumberOfKeyboxes>
    <Keybox DeviceID="...">
        <Key algorithm="ecdsa|rsa">
            <PrivateKey format="pem">
-----BEGIN EC PRIVATE KEY-----
...
-----END EC PRIVATE KEY-----
            </PrivateKey>
            <CertificateChain>
                <NumberOfCertificates>...</NumberOfCertificates>
                <Certificate format="pem">
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
                </Certificate>
            </CertificateChain>
        </Key>
    </Keybox>
</AndroidAttestation>
```

### Build Properties Spoofing (`spoof_build_vars`)

```ini
MANUFACTURER=Google
MODEL=Pixel 8 Pro
FINGERPRINT=google/husky/husky:15/AP4A.250305.002/12737840:user/release-keys
BRAND=google
PRODUCT=husky
DEVICE=husky
RELEASE=15
ID=AP4A.250305.002
SECURITY_PATCH=2025-03-05
# Or use a built-in template:
# TEMPLATE=pixel8pro
```

<details>
<summary><b>All Supported Keys</b></summary>

| Key | Example |
|-----|---------|
| `MANUFACTURER` | `Google` |
| `MODEL` | `Pixel 8 Pro` |
| `FINGERPRINT` | `google/husky/husky:15/...` |
| `BRAND` | `google` |
| `PRODUCT` | `husky` |
| `DEVICE` | `husky` |
| `RELEASE` | `15` |
| `ID` | `AP4A.250305.002` |
| `DISPLAY` | `AP4A.250305.002` |
| `INCREMENTAL` | `12737840` |
| `TYPE` | `user` |
| `TAGS` | `release-keys` |
| `SECURITY_PATCH` | `2025-03-05` |
| `BOOTLOADER` | `...` |
| `BOARD` | `...` |
| `HARDWARE` | `...` |
| `SDK_INT` | `35` |
| `CODENAME` | `REL` |
| `TEMPLATE` | `pixel8pro` |
| `ATTESTATION_ID_BRAND` | `google` |
| `ATTESTATION_ID_DEVICE` | `husky` |
| `ATTESTATION_ID_MODEL` | `Pixel 8 Pro` |
| `ATTESTATION_ID_IMEI` | `35...` (Luhn-valid 15 digits) |
| `ATTESTATION_ID_SERIAL` | `ABC123...` |
| `ATTESTATION_ID_WIFI_MAC` | `00:11:22:33:44:55` |
| `ATTESTATION_ID_BT_MAC` | `00:11:22:33:44:55` |
| `SPOOF_LATITUDE` | `41.0082` |
| `SPOOF_LONGITUDE` | `28.9784` |
| `SPOOF_ALTITUDE` | `0` |
| `SPOOF_ACCURACY` | `1.0` |
| `SPOOF_LOCATION_RANDOM` | `true` / `false` |
| `SPOOF_LOCATION_RADIUS` | `500` (meters) |
| `SPOOF_LOCATION_INTERVAL` | `30` (seconds) |

</details>

### Target Packages for Attestation (`target.txt`)

```bash
# Standard mode (leaf certificate replacement)
io.github.vvb2060.keyattestation

# Generate mode for TEE-broken devices (append !)
com.google.android.gms!
```

### Per-App Configuration (`app_config`)

```bash
# Format: packageName [template] [keybox_filename] [permissions]
com.google.android.gms pixel8pro keybox_beta.xml
com.netflix.mediaclient xiaomi14 null
com.google.android.apps.walletnfcrel null keybox_wallet.xml
```

### Security Patch Spoofing (`security_patch.txt`)

```ini
# Simple (applied to all components)
20250305

# Advanced (per-component)
system=202503
boot=2025-03-05
vendor=2025-03-05

# Dynamic (auto-updates)
today
```

---

## Advanced

### RKP Spoofing (STRONG Integrity)

```bash
# Enable
touch /data/adb/cleverestricky/rkp_bypass

# Disable
rm /data/adb/cleverestricky/rkp_bypass
```

The module runs a **Local RKP Proxy** that generates valid COSE/CBOR structures signed by a rotating root secret. The cryptographic identity mutates every 24 hours to prevent fingerprint-based banning.

### AutoPIF - Automatic Fingerprint Updates

```bash
# Manual
sh /data/adb/modules/cleverestricky/autopif.sh

# Automatic (24h interval)
touch /data/adb/cleverestricky/auto_beta_fetch
```

### DRM / Netflix Fix

```bash
touch /data/adb/cleverestricky/drm_fix
```

### Randomize on Boot

```bash
touch /data/adb/cleverestricky/random_on_boot
```

### Location Spoofing via WebUI or File

```bash
touch /data/adb/cleverestricky/spoof_location
```

### Per-Feature Global Modes

```bash
touch /data/adb/cleverestricky/imei_global
touch /data/adb/cleverestricky/network_global
```

### Play Integrity API Protection

The module includes comprehensive countermeasures against **all** Play Integrity API verdict categories, as documented in Google's November 2025 update and the Device Recall beta (2026).

```bash
# Enable (also auto-enables when random_on_boot or random_drm_on_boot is active)
touch /data/adb/cleverestricky/device_recall_protection

# Disable
rm /data/adb/cleverestricky/device_recall_protection
```

**Verdict categories covered:**

| Verdict | Threat | Our Defense |
|---------|--------|-------------|
| **deviceIntegrity** | Detects rooted/uncertified/emulated devices | Spoofed build props, locked bootloader, verified boot state, security patch |
| **appIntegrity** | Detects modified/unsigned APKs | Keystore interception injects valid attestation chains |
| **accountDetails** | Checks Play Store license | Handled by legitimate Play Store installation |
| **recentDeviceActivity** | Flags anomalous token request volume | Built-in rate limiter caps requests to avoid anomaly detection |
| **deviceRecall** | 3 persistent bits per device surviving factory resets | All device identifiers (IMEI, serial, DRM ID, fingerprint) randomized to break association |
| **appAccessRiskVerdict** | Detects overlay/screen-capture apps | Module runs as native daemon, not as overlay |
| **playProtectVerdict** | Checks Play Protect malware scan status | Module is not flagged as malware (native process) |
| **deviceAttributes** | Attested SDK version | SDK version spoofed to match legitimate device |
| **Remediation dialogs** | GET_INTEGRITY, GET_STRONG_INTEGRITY, GET_LICENSED force re-verification | Dialog intent detection at Binder level |
| **Platform key rotation** | Google rotating root certificates (Feb 2026) | Adaptive key handling via rotating keybox pool |

**How identity randomization defeats Device Recall:**

Device Recall needs a stable device identifier to associate the 3 persistent bits. When all identifiers are randomized (IMEI, serial, DRM ID, fingerprint, security patch), the device appears as a completely new device to Google's servers. The 3-year retention period becomes irrelevant because previous bits cannot be matched to the new identity.

**Best practice:** Enable `random_on_boot` + `random_drm_on_boot` for maximum protection. This gives you a fresh device identity on every boot.

### Adaptive Binder Interceptor

The native Binder hook uses an **Adaptive Interception** architecture that is immune to Android version updates and kernel struct changes. Instead of hardcoding kernel struct layouts, it discovers them dynamically at runtime.

**Strategy priority (automatic fallback):**

| Priority | Strategy | When |
|----------|----------|------|
| 1 | **BTF Kernel Introspection** | Kernel 5.4+ with `CONFIG_DEBUG_INFO_BTF` -- reads `/sys/kernel/btf/vmlinux` for exact struct layouts |
| 2 | **Runtime Heuristic Probing** | Sends a dummy `PING_TRANSACTION` at startup and analyzes the response to discover struct field positions |
| 3 | **Static Fallback Database** | Known offset maps for Android 8 (API 26) through Android 16+ (API 36) across kernel 4.4 -- 6.6 |

**Safety guarantees:**

- All buffer accesses are **bounds-checked** before read/write
- A **state-machine stream parser** processes binder commands without assuming fixed struct sizes
- **SIGSEGV/SIGBUS-safe memory probing** prevents kernel panics on malformed data
- No raw C-style struct casts -- all field access uses dynamically discovered offsets
- Unknown/new fields are **skipped safely** instead of causing crashes

---

## AI Agent Engineering Policies

To ensure the long-term viability and unbreakability of this module, AI Agents contributing to this project must adhere to strict policies:
- **No Hardcoding:** Offsets, sizes, and struct layouts must be discovered dynamically (e.g., via BTF or heuristic probing). No blind reliance on fixed values.
- **Dynamic Adaptability:** The architecture must withstand kernel updates and Android version changes without crashing.
- **Deep Testing:** Tests must cover edge cases deeply. Write tests before writing code.
- **Robust Architectures:** No shortcuts or band-aid fixes. Provide serious, international-level engineering solutions.

## Roadmap

- [ ] AOSP Full Compatibility
- [ ] Zygisk-less standalone mode
- [ ] Enhanced KernelSU native integration
- [ ] Advanced detection evasion independent of Zygisk injection

## Acknowledgements

- [PlayIntegrityFix](https://github.com/chiteroman/PlayIntegrityFix) - Original inspiration
- [FrameworkPatch](https://github.com/chiteroman/FrameworkPatch) - Framework patching
- [BootloaderSpoofer](https://github.com/chiteroman/BootloaderSpoofer) - Bootloader state spoofing
- [KeystoreInjection](https://github.com/aviraxp/Zygisk-KeystoreInjection) - Zygisk-based injection
- [LSPosed](https://github.com/LSPosed/LSPosed) - Xposed framework

## Community

**Telegram:** [Cleverestech Group](https://t.me/cleverestech)

## Support

If you find this project useful, consider supporting its development: [DONATE.md](DONATE.md)
