# APK 1: Post-Rename Smoke Test Build

## Critical Issue Found

The native library files are still named `libbtcdid_core.so` but:
- Kotlin `NativeBridge` loads `System.loadLibrary("signedby_core")`
- JNI functions expect `Java_com_signedby_app_NativeBridge_*`

**The .so files MUST be rebuilt with the new name and JNI signatures.**

## Build Steps (on machine with Android Studio)

### 1. Rebuild Native Library

```bash
cd SignedByMe

# Install Android targets (if not already)
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

# Install cargo-ndk
cargo install cargo-ndk

# Set NDK path (adjust to your NDK location)
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/26.1.10909125  # or your version

# Build for all architectures
cd native/signedby_core
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o ../../app/src/main/jniLibs build --release
```

This creates:
- `app/src/main/jniLibs/arm64-v8a/libsignedby_core.so`
- `app/src/main/jniLibs/armeabi-v7a/libsignedby_core.so`
- `app/src/main/jniLibs/x86_64/libsignedby_core.so`

### 2. Remove Old .so Files

```bash
rm app/src/main/jniLibs/*/libbtcdid_core.so
```

### 3. Build Debug APK

```bash
./gradlew assembleDebug
```

APK location: `app/build/outputs/apk/debug/app-debug.apk`

### 4. Install on Device

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

Or drag the APK to your phone.

## Smoke Test Checklist

- [ ] App launches without crash
- [ ] Home screen loads
- [ ] QR scanner opens
- [ ] No `UnsatisfiedLinkError`

## Troubleshooting

### "Library not found" error
Check that the .so files are correctly named `libsignedby_core.so`

### UnsatisfiedLinkError on specific function
JNI signature mismatch. Verify:
- Kotlin package: `com.signedby.app`
- Rust exports: `Java_com_signedby_app_NativeBridge_*`

### Cargo-ndk not finding NDK
Set `ANDROID_NDK_HOME` explicitly or create `.cargo/config.toml`:
```toml
[target.aarch64-linux-android]
linker = "/path/to/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"

[target.armv7-linux-androideabi]
linker = "/path/to/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang"

[target.x86_64-linux-android]
linker = "/path/to/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android21-clang"
```
