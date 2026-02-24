# SignedByMe Circuits

Groth16 circuits for ZK membership proofs with NOSTR identity binding.

## Directory Structure

```
circuits/
├── membership.circom      # Main membership circuit
├── secp256k1/             # (TODO) secp256k1 templates if needed
├── test/                  # (TODO) Test inputs and expected outputs
└── README.md
```

## Circuit Overview

The `membership.circom` circuit proves:
1. Knowledge of a `leaf_secret[5]` that hashes to a leaf in the Merkle tree
2. The leaf is at a valid path to the claimed `merkle_root`
3. A deterministic `npub` derived from `leaf_secret[0..2]`

### Public Outputs
- `merkle_root` - The Merkle root being proven against
- `npub` - Derived identity commitment

### Private Inputs
- `leaf_secret[5]` - The 5-element secret that defines the user's identity
- `siblings[20]` - Merkle path siblings (20-level tree = 2^20 = ~1M leaves)
- `path_bits[20]` - Binary path from leaf to root

## ⚠️ DESIGN DECISION: npub Derivation

The Bible specifies: `npub = secp256k1_pubkey(nsec)` where `nsec = Poseidon(leaf_secret[0..2])`.

**Problem**: secp256k1 scalar multiplication inside a BN254 Groth16 circuit is extremely expensive because secp256k1 is a different curve than the proving curve. Estimates:
- Basic scalar mult: ~15,000-20,000 constraints
- Full ECDSA verification: ~1.5M constraints (circom-ecdsa)

This would blow our <10,000 constraint budget.

**Current Implementation**: Poseidon-based commitment
```
nsec = Poseidon(leaf_secret[0..2])
npub = Poseidon(nsec, DOMAIN_SEP)  // NOT a real secp256k1 point
```

This gives us ~200 constraints for npub derivation.

**Tradeoff**:
- ✅ Stays under constraint budget
- ✅ npub is deterministic from leaf_secret
- ✅ nsec remains private
- ❌ npub is NOT a valid secp256k1 public key
- ❌ Cannot directly use npub to verify NOSTR signatures

**How binding works with Poseidon-based npub**:
1. Phone computes real secp256k1 keypair: `real_nsec = Poseidon(leaf_secret[0..2])`, `real_npub = secp256k1(real_nsec)`
2. Phone also computes circuit npub: `circuit_npub = Poseidon(real_nsec, DOMAIN_SEP)`
3. Phone generates proof with `circuit_npub` as public output
4. Phone signs NOSTR event (containing proof) with `real_nsec`
5. Verifier receives event signed by `real_npub`, extracts proof, sees `circuit_npub`
6. Binding check: Verifier computes `expected_circuit_npub = Poseidon(?, DOMAIN_SEP)` - **PROBLEM: verifier doesn't have nsec**

**Alternative architectures if real secp256k1 is required**:
1. **EdDSA on Baby Jubjub**: ~2,000 constraints. Use a different curve that's efficient inside BN254.
2. **Lookup tables / Plookup**: Newer proof systems like Halo2 handle non-native arithmetic better.
3. **Two-proof system**: One Groth16 proof for membership, separate STARK proof for secp256k1.
4. **Off-circuit binding**: Prove membership only, bind npub through NOSTR event signature (no npub in circuit).

**Recommendation**: Discuss with Scott. If real secp256k1 npub is required:
- Option 4 (off-circuit binding) may work: circuit proves membership only, npub binding via event signature
- This requires the verifier to trust that the signer of the NOSTR event is the one who generated the proof

## Building

Prerequisites:
```bash
sudo apt-get install -y build-essential nodejs npm
cargo install --path /tmp/circom
npm install -g snarkjs
npm install circomlib
```

Compile:
```bash
cd circuits
circom membership.circom --r1cs --wasm --sym -o build/
```

## Testing

```bash
# Generate witness from test input
node build/membership_js/generate_witness.js build/membership.wasm test/input.json witness.wtns

# Prove (after trusted setup)
snarkjs groth16 prove membership.zkey witness.wtns proof.json public.json

# Verify
snarkjs groth16 verify verification_key.json public.json proof.json
```

## Constraint Count Target

| Sub-circuit | Estimated Constraints |
|-------------|----------------------|
| Leaf commitment (Poseidon-5) | ~200 |
| Merkle path (20 × Poseidon-2) | ~4,000 |
| Path bit booleans | 20 |
| npub derivation (Poseidon) | ~200 |
| **TOTAL** | **~4,500** |

If using real secp256k1: add ~15,000+ constraints → ~20,000 total (over budget).
