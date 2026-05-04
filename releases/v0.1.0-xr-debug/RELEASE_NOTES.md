# OxleyXR v0.1.0 — debug build

Single-arch (arm64-v8a) debug APK of the React Native 0.85 + Jetpack XR Galaxy
XR client. Targets the Firebase project `inventory-setup-b3f20` and uses the
shared Google Maps API key.

| | |
|---|---|
| File | `oxley-xr-v0.1.0-debug-arm64-v8a.apk` |
| Package | `com.oxleyxr` |
| versionCode / versionName | `1` / `1.0` |
| minSdk / targetSdk | `34` / `36` |
| ABI | `arm64-v8a` only |
| Signed with | bundled Android debug keystore |
| Size | ~59 MB |
| SHA-256 | `750412418f360a164d022ae477497f015c22fcb81942bd05e418feddddbfedea` |

Direct download:

```
https://github.com/Oxleymatt87/mini-crm/raw/refs/tags/v0.1.0-xr-debug/releases/v0.1.0-xr-debug/oxley-xr-v0.1.0-debug-arm64-v8a.apk
```

---

## Sideloading via wireless ADB from an Android phone

You don't need a laptop. Any Android 11+ phone with the **"Shizuku"** or
**"Material Files"** apps that ship a userspace `adb` works, but the simplest
path uses **Termux** + `adb` because the Galaxy XR exposes the standard
Android wireless-debugging pairing flow.

### 1. On the Galaxy XR — turn on wireless debugging

1. Settings → About headset → tap **Build number** seven times to unlock
   developer options.
2. Settings → System → **Developer options** → **Wireless debugging** → On.
3. Tap **Pair device with pairing code**. Leave the screen up — it shows two
   things you'll need:
   - a **pairing IP:port** (e.g. `192.168.1.42:37145`) and a **6-digit code**
   - a separate, longer-lived **connection IP:port** (e.g. `192.168.1.42:5555`)
     listed at the top of the Wireless debugging screen.

Make sure the headset and the phone are on the **same Wi-Fi network**.

### 2. On the Android phone — install Termux + adb

```sh
# Install Termux from F-Droid (NOT Play Store — the Play build is stale).
# Then inside Termux:
pkg update && pkg install android-tools wget
```

### 3. Download the APK

```sh
cd ~/storage/downloads 2>/dev/null || cd ~
wget https://github.com/Oxleymatt87/mini-crm/raw/refs/tags/v0.1.0-xr-debug/releases/v0.1.0-xr-debug/oxley-xr-v0.1.0-debug-arm64-v8a.apk

# Verify integrity:
sha256sum oxley-xr-v0.1.0-debug-arm64-v8a.apk
# Expected: 750412418f360a164d022ae477497f015c22fcb81942bd05e418feddddbfedea
```

### 4. Pair, connect, install

```sh
# Use the "pairing IP:port" + 6-digit code from the headset's pair screen:
adb pair 192.168.1.42:37145
# (paste the 6-digit code when prompted)

# Now use the "connection IP:port" from the top of Wireless debugging:
adb connect 192.168.1.42:5555

adb devices
# expected:
#   192.168.1.42:5555    device

adb install -r oxley-xr-v0.1.0-debug-arm64-v8a.apk
```

If `adb install` reports `INSTALL_FAILED_UPDATE_INCOMPATIBLE`, the package is
already installed with a different signature (e.g. an older release-signed
build). Uninstall first:

```sh
adb uninstall com.oxleyxr
adb install -r oxley-xr-v0.1.0-debug-arm64-v8a.apk
```

### 5. Launch on the headset

In the headset's app drawer, find **OxleyXR** and launch it. It enters
immersive (full-space) XR mode automatically — no 2D launcher window.

---

## Known caveats

- This APK is signed with the **debug keystore** that ships in the repo. Do
  not distribute it as a release build; rebuild and sign with a real keystore
  before any production handoff.
- `google-services.json` uses a synthesized `mobilesdk_app_id` derived from
  the existing web Firebase app id (`map.html`). The plugin accepts it and
  the build succeeds, but Firebase Auth / Firestore on Android may reject
  the app at runtime. If they do, register an Android app for `com.oxleyxr`
  in the Firebase console and drop the real `google-services.json` over
  `oxley-xr/android/app/google-services.json`.
- The Maps API key (`AIzaSyDdxP9prJjiFFeJ1XGZewkzstgxf7Ciy4E`) must have the
  **Maps SDK for Android** enabled in Google Cloud Console and must not be
  restricted to HTTP referrers, or the in-app map tiles will fail to load.
- Galaxy XR runs arm64 only — this APK does not include `armeabi-v7a`,
  `x86`, or `x86_64`.
