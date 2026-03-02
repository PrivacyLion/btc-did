#!/bin/bash
# Build witness calculator for Android ARM64
# Requires: Android NDK installed, ANDROID_NDK environment variable set
#
# Usage: ./scripts/build_witness_android.sh
#
# Key insight: circom's fr.asm is x86_64-only. We use rapidsnark's ARM64
# field arithmetic (libfr.a) which provides the same Fr_* symbols via
# fr_raw_arm64.s assembly.

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
RAPIDSNARK_DIR="$PROJECT_ROOT/native/rapidsnark"

# Pre-built libs from rapidsnark Android build
RAPIDSNARK_LIB="$RAPIDSNARK_DIR/package_android/lib"
RAPIDSNARK_BUILD="$RAPIDSNARK_DIR/build"

# GMP from rapidsnark
GMP_DIR="$RAPIDSNARK_DIR/depends/gmp/package_android_arm64"
GMP_INCLUDE="$GMP_DIR/include"
GMP_LIB="$GMP_DIR/lib"

# Check prerequisites
if [ ! -f "$GMP_LIB/libgmp.a" ]; then
    echo "ERROR: Pre-built GMP not found at $GMP_LIB"
    echo "Run: cd native/rapidsnark && ./build_gmp.sh android"
    exit 1
fi

if [ ! -f "$RAPIDSNARK_LIB/libfr.a" ]; then
    echo "ERROR: Pre-built libfr.a not found at $RAPIDSNARK_LIB"
    echo "Run: cd native/rapidsnark && make android"
    exit 1
fi

if [ ! -f "$RAPIDSNARK_BUILD/fr.hpp" ]; then
    echo "ERROR: rapidsnark fr.hpp not found at $RAPIDSNARK_BUILD"
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

CXX="$TOOLCHAIN/bin/aarch64-linux-android24-clang++"
STRIP="$TOOLCHAIN/bin/llvm-strip"

echo "=== Building witness calculator for Android ARM64 ==="
echo "Source: $WITNESS_DIR"
echo "Output: $OUTPUT_DIR"
echo "Compiler: $CXX"
echo "Using rapidsnark's libfr.a for ARM64 field arithmetic"

mkdir -p "$OUTPUT_DIR"

# Create temp build dir to avoid polluting circuit dir
BUILD_DIR=$(mktemp -d)
trap "rm -rf $BUILD_DIR" EXIT

cd "$BUILD_DIR"

# Copy circom sources (except fr.hpp/fr.cpp/fr.asm which we replace)
cp "$WITNESS_DIR/calcwit.cpp" "$WITNESS_DIR/calcwit.hpp" .
cp "$WITNESS_DIR/main.cpp" .
cp "$WITNESS_DIR/circom.hpp" .
cp "$WITNESS_DIR/membership.cpp" .
cp "$WITNESS_DIR/membership.dat" .

# Use rapidsnark's field implementation (ARM64-compatible)
cp "$RAPIDSNARK_BUILD/fr.hpp" .
cp "$RAPIDSNARK_BUILD/fr.cpp" .
cp "$RAPIDSNARK_BUILD/fr_element.hpp" .

# nlohmann/json header (used by main.cpp)
JSON_INCLUDE="$RAPIDSNARK_DIR/depends/json/single_include"

# Compiler flags
TARGET_FLAGS="-target aarch64-linux-android24"
CXXFLAGS="-O2 -std=c++17 -fPIC -DUSE_ASM -DARCH_ARM64"
INCLUDES="-I. -I$GMP_INCLUDE -I$JSON_INCLUDE"

# Compile each source file
echo "Compiling fr.cpp (rapidsnark's ARM64-compatible version)..."
$CXX -c $CXXFLAGS $TARGET_FLAGS $INCLUDES fr.cpp -o fr.o

echo "Compiling calcwit.cpp..."
$CXX -c $CXXFLAGS $TARGET_FLAGS $INCLUDES calcwit.cpp -o calcwit.o

echo "Compiling main.cpp..."
$CXX -c $CXXFLAGS $TARGET_FLAGS $INCLUDES main.cpp -o main.o

echo "Compiling membership.cpp (large file, may take a minute)..."
$CXX -c $CXXFLAGS $TARGET_FLAGS $INCLUDES membership.cpp -o membership.o

echo "Linking with libfr.a (ARM64 assembly) + libgmp.a..."
$CXX $TARGET_FLAGS \
    -static-libstdc++ \
    fr.o calcwit.o main.o membership.o \
    "$RAPIDSNARK_LIB/libfr.a" \
    "$GMP_LIB/libgmp.a" \
    -o membership_arm64 \
    -lm

echo "Stripping debug symbols..."
$STRIP membership_arm64

# Copy to jniLibs
cp membership_arm64 "$OUTPUT_DIR/membership"
chmod +x "$OUTPUT_DIR/membership"

# Also copy .dat file to assets
ASSETS_DIR="$PROJECT_ROOT/app/src/main/assets/groth16"
mkdir -p "$ASSETS_DIR"
cp "$WITNESS_DIR/membership.dat" "$ASSETS_DIR/"

# Check output
ls -la "$OUTPUT_DIR/membership"
file "$OUTPUT_DIR/membership"

SIZE=$(ls -lh "$OUTPUT_DIR/membership" | awk '{print $5}')
echo ""
echo "=== SUCCESS ==="
echo "ARM64 witness calculator: $OUTPUT_DIR/membership ($SIZE)"
echo "Circuit data: $ASSETS_DIR/membership.dat"
echo ""
echo "Next steps:"
echo "1. Sideload .zkey: adb push circuits/build/membership_final.zkey /sdcard/Download/"
echo "2. Build APK: ./gradlew assembleDebug"
