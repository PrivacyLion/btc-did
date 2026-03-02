#!/bin/bash
# Build witness calculator for Android ARM64
# Requires: Android NDK installed, ANDROID_NDK environment variable set
#
# Usage: ./scripts/build_witness_android.sh

set -e

# Check NDK
if [ -z "$ANDROID_NDK" ]; then
    echo "ERROR: ANDROID_NDK environment variable not set"
    echo "Example: export ANDROID_NDK=\$HOME/Android/Sdk/ndk/25.2.9519653"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WITNESS_DIR="$PROJECT_ROOT/circuits/build/membership_cpp"
OUTPUT_DIR="$PROJECT_ROOT/app/src/main/jniLibs/arm64-v8a"

# Pre-built GMP from rapidsnark
GMP_DIR="$PROJECT_ROOT/native/rapidsnark/depends/gmp/package_android_arm64"
GMP_INCLUDE="$GMP_DIR/include"
GMP_LIB="$GMP_DIR/lib"

if [ ! -f "$GMP_LIB/libgmp.a" ]; then
    echo "ERROR: Pre-built GMP not found at $GMP_LIB"
    echo "Run: cd native/rapidsnark && ./build_gmp.sh android"
    exit 1
fi

# NDK toolchain
TOOLCHAIN="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64"
if [ ! -d "$TOOLCHAIN" ]; then
    # macOS
    TOOLCHAIN="$ANDROID_NDK/toolchains/llvm/prebuilt/darwin-x86_64"
fi

if [ ! -d "$TOOLCHAIN" ]; then
    echo "ERROR: NDK toolchain not found at $TOOLCHAIN"
    exit 1
fi

CC="$TOOLCHAIN/bin/aarch64-linux-android24-clang"
CXX="$TOOLCHAIN/bin/aarch64-linux-android24-clang++"
AR="$TOOLCHAIN/bin/llvm-ar"
STRIP="$TOOLCHAIN/bin/llvm-strip"

echo "=== Building witness calculator for Android ARM64 ==="
echo "Source: $WITNESS_DIR"
echo "Output: $OUTPUT_DIR"
echo "Compiler: $CXX"
echo "GMP: $GMP_LIB"

mkdir -p "$OUTPUT_DIR"
cd "$WITNESS_DIR"

# Clean previous ARM64 objects
rm -f *.arm64.o membership_arm64

CXXFLAGS="-O2 -std=c++17 -fPIC -DANDROID -I$GMP_INCLUDE"
TARGET_FLAGS="-target aarch64-linux-android24"

# Compile each source file
echo "Compiling fr.cpp..."
$CXX -c $CXXFLAGS $TARGET_FLAGS fr.cpp -o fr.arm64.o

echo "Compiling calcwit.cpp..."
$CXX -c $CXXFLAGS $TARGET_FLAGS calcwit.cpp -o calcwit.arm64.o

echo "Compiling main.cpp..."
$CXX -c $CXXFLAGS $TARGET_FLAGS main.cpp -o main.arm64.o

echo "Compiling membership.cpp (this is large, may take a minute)..."
$CXX -c $CXXFLAGS $TARGET_FLAGS membership.cpp -o membership.arm64.o

# Note: fr.asm is x86_64 assembly - we use the C++ implementation in fr.cpp for ARM64
# The circom C++ witness generator falls back to GMP-based field operations

echo "Linking..."
$CXX $TARGET_FLAGS \
    -static-libstdc++ \
    fr.arm64.o calcwit.arm64.o main.arm64.o membership.arm64.o \
    "$GMP_LIB/libgmp.a" \
    -o membership_arm64 \
    -lm

echo "Stripping..."
$STRIP membership_arm64

# Copy to jniLibs
cp membership_arm64 "$OUTPUT_DIR/membership"
chmod +x "$OUTPUT_DIR/membership"

# Check output
ls -la "$OUTPUT_DIR/membership"
file "$OUTPUT_DIR/membership"

SIZE=$(ls -lh "$OUTPUT_DIR/membership" | awk '{print $5}')
echo ""
echo "=== SUCCESS ==="
echo "ARM64 witness calculator: $OUTPUT_DIR/membership ($SIZE)"
echo ""
echo "Next steps:"
echo "1. Copy to app assets: cp $OUTPUT_DIR/membership app/src/main/assets/"
echo "2. Copy circuit data: cp circuits/build/membership_cpp/membership.dat app/src/main/assets/"
echo "3. For .zkey: sideload to device or bundle in APK (85MB - consider CDN for production)"
echo "4. APK will extract membership binary to app data dir on first run"
