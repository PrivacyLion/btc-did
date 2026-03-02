# Android Build Guide - SignedByMe APK 3 (Groth16)

## Prerequisites

1. **Android Studio** with NDK installed
2. **ANDROID_NDK** environment variable set:
   ```bash
   export ANDROID_NDK=$HOME/Android/Sdk/ndk/25.2.9519653  # adjust version
   ```
3. **Rust** with Android targets:
   ```bash
   rustup target add aarch64-linux-android
   ```

## Build Order

### 1. Build rapidsnark for Android (already done)
```bash
cd native/rapidsnark
./build_gmp.sh android
make android
```
Output: `package_android/lib/librapidsnark.so` (ARM64, 2.2MB)

### 2. Build witness calculator for Android
```bash
./scripts/build_witness_android.sh
```
Output: `app/src/main/jniLibs/arm64-v8a/membership` (ARM64, ~3MB)

### 3. Build Rust native library
```bash
cd native/signedby_core
cargo build --release --target aarch64-linux-android
```
Output: `target/aarch64-linux-android/release/libsignedby_core.so`

### 4. Copy native libraries to jniLibs
```bash
mkdir -p app/src/main/jniLibs/arm64-v8a

# Rust lib
cp native/signedby_core/target/aarch64-linux-android/release/libsignedby_core.so \
   app/src/main/jniLibs/arm64-v8a/

# rapidsnark
cp native/rapidsnark/package_android/lib/librapidsnark.so \
   app/src/main/jniLibs/arm64-v8a/
```

### 5. Prepare assets
```bash
mkdir -p app/src/main/assets/groth16

# Circuit data (4.6MB)
cp circuits/build/membership_cpp/membership.dat app/src/main/assets/groth16/

# Witness calculator binary (already in jniLibs, but also in assets for extraction)
cp app/src/main/jniLibs/arm64-v8a/membership app/src/main/assets/groth16/
```

### 6. Handle .zkey file (85MB)

**Option A: Sideload for testing**
```bash
adb push circuits/build/membership_final.zkey /sdcard/Download/
```
Then in app, copy from Download to app data dir.

**Option B: Bundle in APK (increases APK size significantly)**
```bash
cp circuits/build/membership_final.zkey app/src/main/assets/groth16/
```

**Option C: CDN download (production)**
Upload to CDN, download on first launch with progress indicator.

### 7. Build APK
```bash
./gradlew assembleDebug
# or
./gradlew assembleRelease
```

## Architecture

```
app/
├── src/main/
│   ├── jniLibs/arm64-v8a/
│   │   ├── libsignedby_core.so   # Rust JNI (secp256k1, proofs)
│   │   ├── librapidsnark.so      # Groth16 prover
│   │   └── membership            # Witness calculator executable
│   ├── assets/groth16/
│   │   ├── membership.dat        # Circuit data (4.6MB)
│   │   └── membership_final.zkey # Proving key (85MB) - or download
│   └── java/com/signedby/app/
│       ├── NativeBridge.kt       # JNI declarations
│       ├── Groth16AssetManager.kt # Asset extraction
│       └── MainActivity.kt       # UI with proof timer
```

## JNI Flow

1. App starts → `NativeBridge` loads `librapidsnark.so` then `libsignedby_core.so`
2. On first proof:
   - Extract `membership` binary to app data dir (executable)
   - Extract `membership.dat` to app data dir
   - Ensure `membership_final.zkey` is available
3. Call `NativeBridge.initProver(zkeyPath, datPath, calculatorPath)`
4. Call `NativeBridge.generateProof(inputJson)` → returns proof JSON

## Testing Proof Generation

```kotlin
// Initialize prover (once, at app startup or before first proof)
val dataDir = context.filesDir.absolutePath
val zkeyPath = "$dataDir/membership_final.zkey"
val datPath = "$dataDir/membership.dat"
val calcPath = "$dataDir/membership"

val initialized = NativeBridge.initProver(zkeyPath, datPath, calcPath)
if (!initialized) {
    Log.e("Groth16", "Failed to initialize prover")
}

// Generate proof (at login time)
val startTime = System.currentTimeMillis()
val inputJson = """
{
    "leaf_secret": "$leafSecretHex",
    "siblings": [${merkleWitness.siblings.joinToString(",") { "\"$it\"" }}],
    "path_bits": [${merkleWitness.pathBits.joinToString(",")}]
}
"""
val resultJson = NativeBridge.generateProof(inputJson)
val elapsed = System.currentTimeMillis() - startTime

Log.i("Groth16", "Proof generated in ${elapsed}ms")

val result = JSONObject(resultJson)
if (result.getBoolean("success")) {
    val proof = result.getJSONObject("proof")
    val publicInputs = result.getJSONArray("public_inputs")
    // Submit to server...
} else {
    Log.e("Groth16", "Proof failed: ${result.getString("error")}")
}
```

## Expected Performance

| Component | Time |
|-----------|------|
| Witness generation | ~1.4s |
| Proof generation | ~1.5s |
| **Total** | **~3s** |

Target devices: Pixel 7+, iPhone 13+ (ARM64 with good single-core performance)
