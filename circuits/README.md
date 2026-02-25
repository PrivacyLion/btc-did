# SignedByMe Circuits

Groth16 circuits for ZK membership proofs with real secp256k1 NOSTR identity binding.

## Directory Structure

```
circuits/
├── membership.circom      # Main membership circuit (101K constraints)
├── circom-ecdsa/          # Vendored circom-ecdsa library for secp256k1
├── build/                 # Compiled artifacts
│   ├── membership.r1cs    # Compiled circuit (28MB)
│   ├── membership_js/     # WASM witness generator
│   ├── membership_cpp/    # C++ witness generator (faster)
│   ├── pot20.ptau         # Powers of Tau (1.2GB)
│   ├── membership_*.zkey  # Prover keys (~85MB)
│   └── verification_key.json  # Verifier key (4KB)
└── README.md
```

## Circuit Overview

The `membership.circom` circuit proves:
1. Knowledge of a `leaf_secret[5]` that hashes to a leaf in the Merkle tree
2. The leaf is at a valid path to the claimed `merkle_root`
3. **Real secp256k1 public key (npub)** derived from the secret

### Constraint Count

| Component | Constraints |
|-----------|-------------|
| Leaf commitment (Poseidon-5) | ~1,200 |
| Merkle path (20 × Poseidon-2) | ~4,000 |
| **secp256k1 key derivation** (ECDSAPrivToPub) | ~95,000 |
| Path bit enforcement | 20 |
| **TOTAL** | **~101,206** |

## Public Outputs (9 values) — FOR PHASE 23

The circuit outputs 9 field elements in `public.json`:

```
Index   Name          Description
─────   ────────────  ──────────────────────────────────────────────────
[0]     merkle_root   BN254 field element (Poseidon hash of tree root)
[1]     npub_x[0]     secp256k1 X coordinate, limb 0 (64-bit)
[2]     npub_x[1]     secp256k1 X coordinate, limb 1 (64-bit)
[3]     npub_x[2]     secp256k1 X coordinate, limb 2 (64-bit)
[4]     npub_x[3]     secp256k1 X coordinate, limb 3 (64-bit)
[5]     npub_y[0]     secp256k1 Y coordinate, limb 0 (64-bit)
[6]     npub_y[1]     secp256k1 Y coordinate, limb 1 (64-bit)
[7]     npub_y[2]     secp256k1 Y coordinate, limb 2 (64-bit)
[8]     npub_y[3]     secp256k1 Y coordinate, limb 3 (64-bit)
```

### Reconstructing the secp256k1 Public Key (npub)

The X and Y coordinates are split into 4 × 64-bit limbs (little-endian):

```python
# Python example for server-side verifier (Phase 23)
def limbs_to_256bit(limbs):
    """Reconstruct 256-bit integer from 4 × 64-bit limbs (little-endian)"""
    result = 0
    for i, limb in enumerate(limbs):
        result |= int(limb) << (64 * i)
    return result

# From public.json outputs:
merkle_root = int(public[0])
npub_x = limbs_to_256bit(public[1:5])  # indices 1,2,3,4
npub_y = limbs_to_256bit(public[5:9])  # indices 5,6,7,8

# Convert to 33-byte compressed pubkey (NOSTR format)
prefix = 0x02 if (npub_y % 2 == 0) else 0x03
compressed_npub = bytes([prefix]) + npub_x.to_bytes(32, 'big')

# Convert to bech32 npub for OIDC `sub` claim
npub_bech32 = bech32_encode("npub", npub_x.to_bytes(32, 'big'))
```

### Rust Reconstruction (for Phase 23 verifier)

```rust
fn limbs_to_u256(limbs: &[u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[i*8..(i+1)*8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

// Parse from proof public inputs
let merkle_root = parse_field_element(&public[0]);
let npub_x_limbs: [u64; 4] = [
    public[1].parse().unwrap(),
    public[2].parse().unwrap(),
    public[3].parse().unwrap(),
    public[4].parse().unwrap(),
];
let npub_x = limbs_to_u256(&npub_x_limbs);
// ... same for npub_y
```

### Private Inputs (45 values)

| Input | Count | Description |
|-------|-------|-------------|
| `leaf_secret` | 5 | User's identity secret (BN254 field elements) |
| `siblings` | 20 | Merkle path sibling hashes |
| `path_bits` | 20 | Binary path from leaf to root (0=left, 1=right) |

## Building

### Prerequisites

```bash
# Circom (must be 2.1.6+ for --c flag)
cargo install circom

# Node dependencies
npm install -g snarkjs
```

### Compile Circuit

```bash
# WASM witness generator (slower, ~7.5s)
~/.cargo/bin/circom circuits/membership.circom --r1cs --wasm --sym -o circuits/build/

# C++ witness generator (faster, ~1-2s expected)
~/.cargo/bin/circom circuits/membership.circom --r1cs --c -o circuits/build/
cd circuits/build/membership_cpp
make  # Requires: libgmp-dev, nlohmann-json3-dev
```

### Trusted Setup (Phase 5)

```bash
cd circuits/build

# Download Powers of Tau (1.2GB, one-time)
wget https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_20.ptau -O pot20.ptau

# Phase 1: Generate initial zkey
snarkjs groth16 setup membership.r1cs pot20.ptau membership_0.zkey

# Phase 2: Contribute entropy (repeat for multi-party ceremony)
snarkjs zkey contribute membership_0.zkey membership_1.zkey --name="Contributor 1" -e="random entropy"

# Export verification key
snarkjs zkey export verificationkey membership_1.zkey verification_key.json
```

## Testing

```bash
cd circuits/build

# Create test input
cat > test_input.json << 'EOF'
{
  "leaf_secret": ["123...", "456...", "789...", "abc...", "def..."],
  "siblings": ["0", "0", ... (20 zeros)],
  "path_bits": ["0", "0", ... (20 zeros)]
}
EOF

# Generate witness
node membership_js/generate_witness.js membership_js/membership.wasm test_input.json witness.wtns

# Generate proof
snarkjs groth16 prove membership_final.zkey witness.wtns proof.json public.json

# Verify proof
snarkjs groth16 verify verification_key.json public.json proof.json
```

## Benchmark Results (VPS, 2-core x86_64)

| Metric | Time | Notes |
|--------|------|-------|
| Witness generation (WASM) | 7.5s | Bottleneck for mobile |
| Witness generation (C++) | ~1-2s | **Use this for mobile** |
| Proof generation (snarkjs JS) | 8.5s | Not for production |
| Proof generation (rapidsnark) | ~1.5s est. | **Use for mobile** |
| Verification (snarkjs JS) | 500ms | |
| Verification (ark-groth16) | <10ms | **Use for server** |
| Peak RAM | 735MB | |

## Files Shipped to Mobile App

| File | Size | Purpose |
|------|------|---------|
| `membership_final.zkey` | ~85MB | Prover key |
| `membership.dat` | ~50MB | C++ witness data |
| `membership` (binary) | ~2MB | C++ witness executable |

Total app size increase: ~140MB (consider on-demand download + caching)

## Security Notes

1. **Real secp256k1**: npub is a real NOSTR public key derived inside the circuit. Proof theft is impossible — attacker would need to know the private key to sign events.

2. **Merkle depth 20**: Supports up to 2^20 = 1,048,576 users per tree.

3. **Poseidon hash**: BN254-native, ~200 constraints per hash.
