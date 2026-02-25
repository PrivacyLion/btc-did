#!/bin/bash
# Build signedby_core for Android
#
# Prerequisites:
# - Rust with Android targets: rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
# - Android NDK (set ANDROID_NDK_HOME)
# - cargo-ndk: cargo install cargo-ndk
#
# Output: app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/libsignedby_core.so

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
NATIVE_DIR="$PROJECT_ROOT/native/signedby_core"
OUTPUT_DIR="$PROJECT_ROOT/app/src/main/jniLibs"

echo "=== Building signedby_core for Android ==="

# Check prerequisites
if ! command -v cargo-ndk &> /dev/null; then
    echo "Installing cargo-ndk..."
    cargo install cargo-ndk
fi

if [ -z "$ANDROID_NDK_HOME" ]; then
    # Try common locations
    if [ -d "$HOME/Android/Sdk/ndk" ]; then
        export ANDROID_NDK_HOME="$(ls -d $HOME/Android/Sdk/ndk/*/ 2>/dev/null | head -1)"
    elif [ -d "/opt/android-ndk" ]; then
        export ANDROID_NDK_HOME="/opt/android-ndk"
    fi
fi

if [ -z "$ANDROID_NDK_HOME" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "Error: ANDROID_NDK_HOME not set or NDK not found"
    echo "Set ANDROID_NDK_HOME to your NDK installation path"
    exit 1
fi

echo "Using NDK: $ANDROID_NDK_HOME"

# Ensure targets are installed
rustup target add aarch64-linux-android 2>/dev/null || true
rustup target add armv7-linux-androideabi 2>/dev/null || true
rustup target add x86_64-linux-android 2>/dev/null || true

cd "$NATIVE_DIR"

# Build for each architecture
echo ""
echo "Building for arm64-v8a..."
cargo ndk -t arm64-v8a -o "$OUTPUT_DIR" build --release

echo ""
echo "Building for armeabi-v7a..."
cargo ndk -t armeabi-v7a -o "$OUTPUT_DIR" build --release

echo ""
echo "Building for x86_64 (emulator)..."
cargo ndk -t x86_64 -o "$OUTPUT_DIR" build --release

echo ""
echo "=== Build complete ==="
echo "Libraries at: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"/*/libsignedby_core.so 2>/dev/null || echo "(no .so files found)"
