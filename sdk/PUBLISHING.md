# SDK Publishing Guide

This guide explains how to publish the SignedByMe SDKs to package registries.

## Prerequisites

### crates.io (Rust)
1. Create account at https://crates.io
2. Get API token from https://crates.io/settings/tokens
3. Login: `cargo login <token>`

### PyPI (Python)
1. Create account at https://pypi.org
2. Get API token from https://pypi.org/manage/account/token/
3. Install: `pip install maturin twine`

### npm (TypeScript/JavaScript)
1. Create account at https://www.npmjs.com
2. Login: `npm login`

---

## Publishing Rust SDK to crates.io

```bash
cd native/signedby_core

# Verify it builds
cargo build --release

# Dry run to check for issues
cargo publish --dry-run

# Publish!
cargo publish
```

---

## Publishing Python SDK to PyPI

```bash
cd sdk/python

# Build wheels for all platforms (requires maturin)
maturin build --release

# Or build for current platform only
maturin build --release --target x86_64-unknown-linux-gnu

# Upload to PyPI
twine upload target/wheels/*

# Or use maturin's built-in publish
maturin publish
```

### Building for Multiple Platforms

For production, build wheels on each target platform or use CI:

```bash
# Linux x86_64
maturin build --release --target x86_64-unknown-linux-gnu

# Linux ARM64
maturin build --release --target aarch64-unknown-linux-gnu

# macOS x86_64
maturin build --release --target x86_64-apple-darwin

# macOS ARM64 (Apple Silicon)
maturin build --release --target aarch64-apple-darwin

# Windows x86_64
maturin build --release --target x86_64-pc-windows-msvc
```

---

## Publishing TypeScript SDK to npm

```bash
cd sdk/typescript

# Build native bindings first
cd native
cargo build --release
cd ..

# Build TypeScript
npm run build

# Publish to npm
npm publish --access public
```

### Publishing Native Binaries

The TypeScript SDK uses platform-specific native binaries. Publish each as a separate package:

```bash
# Build and publish for each platform
# (Usually done via CI - see .github/workflows/release.yml)

# Package names:
# @signedby/core-linux-x64-gnu
# @signedby/core-linux-arm64-gnu  
# @signedby/core-darwin-x64
# @signedby/core-darwin-arm64
# @signedby/core-win32-x64-msvc
```

---

## Version Bumping

Before publishing, update versions in:

1. `native/signedby_core/Cargo.toml` - Rust SDK
2. `sdk/python/pyproject.toml` - Python SDK
3. `sdk/python/python/signedby/__init__.py` - Python `__version__`
4. `sdk/typescript/package.json` - TypeScript SDK

Keep versions in sync across all packages.

---

## GitHub Release

After publishing to registries, create a GitHub release:

```bash
# Tag the release
git tag v0.1.0
git push origin v0.1.0

# Then go to GitHub → Releases → Create new release
# - Select tag v0.1.0
# - Add release notes
# - Attach any binary artifacts
```

---

## CI/CD Automation

For automated releases, see `.github/workflows/release.yml` which:

1. Triggers on version tags (v*)
2. Builds for all platforms
3. Publishes to crates.io, PyPI, npm
4. Creates GitHub release with artifacts
