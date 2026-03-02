# Groth16 Proof Assets

## Required Files

### Bundled in assets/groth16/:

1. **membership.dat** (4.5MB) - Circuit constraint data ✓ BUNDLED
2. **membership** (~6MB) - ARM64 witness calculator ✗ NEEDS BUILD

### Sideloaded to device:

3. **membership_final.zkey** (85MB) - Proving key
   ```bash
   adb push circuits/build/membership_final.zkey /storage/emulated/0/Download/
   ```

## Building ARM64 Witness Calculator

The witness calculator needs to be cross-compiled for Android ARM64.

### Option 1: Using Android NDK

```bash
cd circuits/build/membership_cpp

# Set NDK path
export NDK=/path/to/android-ndk

# Note: fr.asm is x86 assembly, need pure C++ implementation
# The Makefile uses nasm for x86 - this won't work for ARM64

# For ARM64, you need to either:
# 1. Get the fr_asm implementations for ARM64
# 2. Use a pure C++ implementation of the field operations
```

### Option 2: Static linking with GMP

The witness calculator requires GMP (GNU Multiple Precision) library.
For static linking on Android:

```bash
# Cross-compile GMP for ARM64 first
# Then link statically:
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang++ \
  -O2 -o membership \
  membership.cpp calcwit.cpp fr.cpp \
  -I. -static-libstdc++ \
  /path/to/gmp_arm64/lib/libgmp.a

# Copy to assets
cp membership ../../../app/src/main/assets/groth16/
```

### Option 3: Use snarkjs Node.js (dev only)

For testing on device with node.js installed:
```bash
node circuits/build/membership_js/generate_witness.js \
  circuits/build/membership_js/membership.wasm \
  input.json \
  witness.wtns
```

## Timing Logs

```bash
adb logcat -s SignedByMe | grep -E "TIMING|witness|generateProof"
```

Expected:
```
[TIMING] generateGroth16Proof START at 1709402400000
[generateProof] Starting witness calculation...
[witness] Running: /data/.../membership input.json witness.wtns
[witness] Calculator completed in 1.5s
[generateProof] Starting rapidsnark proof generation...
[generateProof] Rapidsnark proof generation completed in 2.0s
[TIMING] NativeBridge.generateProof END (+3500ms PROOF TIME)
```
