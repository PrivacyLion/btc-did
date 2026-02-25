#!/bin/bash
# Build signedby_core for iOS
#
# Prerequisites:
# - macOS with Xcode
# - Rust with iOS targets: rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#
# Output: DID_BTC/Frameworks/signedby_core.xcframework

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
NATIVE_DIR="$PROJECT_ROOT/native/signedby_core"
OUTPUT_DIR="$PROJECT_ROOT/DID_BTC/Frameworks"

echo "=== Building signedby_core for iOS ==="

# Check we're on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo "Error: iOS builds require macOS"
    exit 1
fi

# Ensure targets are installed
rustup target add aarch64-apple-ios 2>/dev/null || true
rustup target add aarch64-apple-ios-sim 2>/dev/null || true
rustup target add x86_64-apple-ios 2>/dev/null || true

cd "$NATIVE_DIR"

# Build for device (arm64)
echo ""
echo "Building for iOS device (arm64)..."
cargo build --release --target aarch64-apple-ios

# Build for simulator (arm64 - Apple Silicon)
echo ""
echo "Building for iOS simulator (arm64)..."
cargo build --release --target aarch64-apple-ios-sim

# Build for simulator (x86_64 - Intel)
echo ""
echo "Building for iOS simulator (x86_64)..."
cargo build --release --target x86_64-apple-ios

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Create fat library for simulator (arm64 + x86_64)
echo ""
echo "Creating fat library for simulator..."
mkdir -p "$OUTPUT_DIR/sim-fat"
lipo -create \
    "target/aarch64-apple-ios-sim/release/libsignedby_core.a" \
    "target/x86_64-apple-ios/release/libsignedby_core.a" \
    -output "$OUTPUT_DIR/sim-fat/libsignedby_core.a"

# Create xcframework
echo ""
echo "Creating xcframework..."
rm -rf "$OUTPUT_DIR/signedby_core.xcframework"
xcodebuild -create-xcframework \
    -library "target/aarch64-apple-ios/release/libsignedby_core.a" \
    -headers "$NATIVE_DIR/include" \
    -library "$OUTPUT_DIR/sim-fat/libsignedby_core.a" \
    -headers "$NATIVE_DIR/include" \
    -output "$OUTPUT_DIR/signedby_core.xcframework"

# Cleanup
rm -rf "$OUTPUT_DIR/sim-fat"

echo ""
echo "=== Build complete ==="
echo "XCFramework at: $OUTPUT_DIR/signedby_core.xcframework"
ls -la "$OUTPUT_DIR/signedby_core.xcframework" 2>/dev/null || echo "(framework not found)"
