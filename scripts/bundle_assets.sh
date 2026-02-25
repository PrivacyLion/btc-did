#!/bin/bash
# Bundle circuit assets for mobile apps
#
# Assets needed:
# 1. membership_final.zkey (85MB) - Prover key for Groth16
# 2. membership.dat (4.6MB) - Circuit data for witness calculator
# 3. membership (witness calculator binary) - Platform specific
#
# Strategy:
# - For beta: Download assets on first run from CDN
# - For production: Bundle .dat in app, download .zkey on demand
#
# Output:
# - Android: app/src/main/assets/groth16/
# - iOS: DID_BTC/DID_BTC/Resources/groth16/

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CIRCUITS_DIR="$PROJECT_ROOT/circuits/build"

# Android output
ANDROID_ASSETS="$PROJECT_ROOT/app/src/main/assets/groth16"

# iOS output  
IOS_ASSETS="$PROJECT_ROOT/DID_BTC/DID_BTC/Resources/groth16"

echo "=== Bundling Groth16 Assets ==="

# Check source files exist
if [ ! -f "$CIRCUITS_DIR/membership_final.zkey" ]; then
    echo "Warning: membership_final.zkey not found"
    echo "Generate with: cd circuits && ./scripts/setup.sh"
fi

if [ ! -f "$CIRCUITS_DIR/membership_cpp/membership.dat" ]; then
    echo "Warning: membership.dat not found"
    echo "Generate with: cd circuits/build/membership_cpp && make"
fi

# Create directories
mkdir -p "$ANDROID_ASSETS"
mkdir -p "$IOS_ASSETS"

# Copy verification key (small, always bundle)
echo "Copying verification key..."
if [ -f "$CIRCUITS_DIR/verification_key_final.json" ]; then
    cp "$CIRCUITS_DIR/verification_key_final.json" "$ANDROID_ASSETS/"
    cp "$CIRCUITS_DIR/verification_key_final.json" "$IOS_ASSETS/"
fi

# Copy .dat file (4.6MB, can bundle)
echo "Copying circuit data..."
if [ -f "$CIRCUITS_DIR/membership_cpp/membership.dat" ]; then
    cp "$CIRCUITS_DIR/membership_cpp/membership.dat" "$ANDROID_ASSETS/"
    cp "$CIRCUITS_DIR/membership_cpp/membership.dat" "$IOS_ASSETS/"
fi

# Create asset manifest (for download URLs)
echo "Creating asset manifest..."
cat > "$ANDROID_ASSETS/manifest.json" << 'EOF'
{
  "version": "1.0.0",
  "assets": {
    "zkey": {
      "url": "https://assets.signedby.me/groth16/membership_final.zkey",
      "sha256": "TODO",
      "size_bytes": 88552208,
      "required": true
    },
    "dat": {
      "bundled": true,
      "size_bytes": 4617752
    },
    "verification_key": {
      "bundled": true,
      "size_bytes": 4390
    }
  },
  "rapidsnark": {
    "android_arm64": {
      "url": "https://assets.signedby.me/rapidsnark/android-arm64/rapidsnark",
      "sha256": "TODO",
      "required": true
    },
    "ios_arm64": {
      "bundled": true
    }
  }
}
EOF

cp "$ANDROID_ASSETS/manifest.json" "$IOS_ASSETS/"

echo ""
echo "=== Bundle Summary ==="
echo "Android assets: $ANDROID_ASSETS"
ls -la "$ANDROID_ASSETS" 2>/dev/null || true
echo ""
echo "iOS assets: $IOS_ASSETS"
ls -la "$IOS_ASSETS" 2>/dev/null || true

echo ""
echo "=== Notes ==="
echo "1. The .zkey (85MB) is too large to bundle - download on first run"
echo "2. rapidsnark binary needs to be cross-compiled for each platform"
echo "3. For iOS, rapidsnark should be statically linked into xcframework"
echo ""
echo "To cross-compile rapidsnark for Android:"
echo "  git clone https://github.com/nicm/rapidsnark"
echo "  cd rapidsnark && ./build_android.sh"
