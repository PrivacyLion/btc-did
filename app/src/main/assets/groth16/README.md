# Groth16 Proof Assets

## Required Files

### Bundled in assets/groth16/ (in APK):

| File | Size | Status | Description |
|------|------|--------|-------------|
| `membership.wasm` | 6.3MB | ✓ BUNDLED | WASM witness calculator |
| `membership.dat` | 4.5MB | ✓ BUNDLED | Circuit constraint data |
| `membership` | ~4MB | ✗ NEED BUILD | ARM64 witness calculator |

### Sideloaded to device (before first run):

| File | Size | Description |
|------|------|-------------|
| `membership_final.zkey` | 85MB | Proving key (too large for APK) |

```bash
adb push circuits/build/membership_final.zkey /storage/emulated/0/Download/
```

## Current Status

**Problem:** The WASM witness calculator (`membership.wasm`) cannot be executed directly 
on Android. The Rust code shells out via `Command::new()` which expects a native binary.

**Workaround:** Need ARM64 witness calculator binary. Two options:

### Option 1: Pure C++ Build (Recommended)

We've added `fr_generic.cpp` - a pure C++ implementation of field operations that 
doesn't require x86 assembly:

```bash
cd circuits/build/membership_cpp

# Prerequisites:
# 1. Android NDK (r25+)
# 2. GMP compiled for ARM64 (see instructions below)

# Build:
NDK=/path/to/android-ndk GMP=/path/to/gmp-arm64 make -f Makefile.android

# Copy to assets:
cp membership_arm64 ../../../app/src/main/assets/groth16/membership
```

#### Building GMP for ARM64

```bash
# Download GMP
wget https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz
tar xf gmp-6.3.0.tar.xz && cd gmp-6.3.0

# Configure for Android ARM64
export NDK=/path/to/android-ndk
export TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64
export CC=$TOOLCHAIN/bin/aarch64-linux-android21-clang
export CXX=$TOOLCHAIN/bin/aarch64-linux-android21-clang++

./configure \
  --host=aarch64-linux-android \
  --prefix=$HOME/gmp-arm64 \
  --disable-shared \
  --enable-static

make -j$(nproc) && make install
```

### Option 2: Native Binary from Scott's Machine

If you have access to a Linux ARM64 machine or can build locally:

```bash
cd circuits/build/membership_cpp
make clean && make
# Copy the 'membership' binary to assets
```

## Timing Logs

Monitor proof generation:
```bash
adb logcat -s SignedByMe | grep -E "TIMING|witness|generateProof"
```

Expected output:
```
[TIMING] generateGroth16Proof START at 1709402400000
[generateProof] Starting witness calculation...
[witness] Running: /data/.../membership input.json witness.wtns
[witness] Calculator completed in ~1.5s
[generateProof] Starting rapidsnark proof generation...
[generateProof] Rapidsnark proof generation completed in ~2.0s
[TIMING] NativeBridge.generateProof END (+3500ms PROOF TIME)
```

## File Locations at Runtime

After extraction by `Groth16AssetManager`:
- Calculator: `/data/data/com.signedby.app/files/groth16/membership`
- Data: `/data/data/com.signedby.app/files/groth16/membership.dat`
- Zkey: `/data/data/com.signedby.app/files/groth16/membership_final.zkey` 
  (copied from sideload location)

## Troubleshooting

### "Witness calculator not found"
The ARM64 `membership` binary is missing from assets. Build it using Option 1 above.

### "Proving key not found"
Sideload the zkey:
```bash
adb push circuits/build/membership_final.zkey /storage/emulated/0/Download/
```

### UnsatisfiedLinkError on proveMembership
The native library needs to be rebuilt with Groth16 JNI symbols. See 
`native/signedby_core/` and run:
```bash
cargo build --release --target aarch64-linux-android
```
Then copy `libsignedby_core.so` to `app/src/main/jniLibs/arm64-v8a/`.
