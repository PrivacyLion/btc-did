# Groth16 Proof Assets

This directory contains circuit data for Groth16 proof generation.

## Required Files

### In this directory (bundled in APK):

1. **membership.dat** (4.5MB) - Circuit constraint data
   - Source: `circuits/build/membership_cpp/membership.dat`
   - ✓ Already bundled

2. **membership** (optional, ~6MB) - ARM64 witness calculator
   - Source: Cross-compiled from `circuits/build/membership_cpp/membership`
   - Alternative: Bundle as `jniLibs/arm64-v8a/libmembership.so`
   - The app checks both locations

### Sideloaded to device (too big for APK):

3. **membership_final.zkey** (85MB) - Proving key
   - Source: `circuits/build/membership_final.zkey`
   - Sideload to one of:
     - `/storage/emulated/0/Android/data/com.signedby.app/files/membership_final.zkey` (preferred)
     - `/storage/emulated/0/Download/membership_final.zkey` (fallback)
   
   To sideload via adb:
   ```bash
   adb push circuits/build/membership_final.zkey /storage/emulated/0/Android/data/com.signedby.app/files/
   ```

## How It Works

1. App extracts `membership.dat` and `membership` from assets to `filesDir/groth16/` at startup
2. App looks for proving key in externalFilesDir, then Downloads
3. `NativeBridge.initProver()` loads all three files
4. `NativeBridge.generateProof()` runs the witness calculator + rapidsnark

## Logs

Check logcat for detailed initialization logs:
```bash
adb logcat -s SignedByMe | grep -E "Groth16|TIMING"
```
