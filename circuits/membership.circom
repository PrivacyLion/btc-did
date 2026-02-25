/**
 * SignedByMe Membership Circuit
 * 
 * Proves membership in a Merkle tree and derives a NOSTR npub from the leaf secret
 * using real secp256k1 scalar multiplication.
 * 
 * 4 Sub-circuits:
 *   1. Leaf Commitment: leaf = Poseidon(leaf_secret[0..5])
 *   2. Merkle Path (20 levels): parent = Poseidon(left, right)
 *   3. Path Bit Boolean: path_bits[i] * (path_bits[i] - 1) === 0
 *   4. npub Derivation: nsec = Poseidon(leaf_secret[0..2]) → npub = secp256k1(nsec * G)
 * 
 * Public Outputs: merkle_root, npub_x[4], npub_y[4]  (secp256k1 point in 4x64-bit limbs)
 * Private Inputs: leaf_secret[5], siblings[20], path_bits[20]
 * 
 * Estimated constraints: ~100,000 (95K for secp256k1 + ~5K for Merkle/Poseidon)
 * Target: <3s proof on iPhone 13+ / Pixel 7+
 * 
 * See: SignedByMe Bible Section 12, Phase 4
 */

pragma circom 2.1.0;

// Use circomlib from circom-ecdsa's node_modules
include "circom-ecdsa/node_modules/circomlib/circuits/poseidon.circom";
include "circom-ecdsa/node_modules/circomlib/circuits/mux1.circom";
include "circom-ecdsa/node_modules/circomlib/circuits/bitify.circom";

// Use the optimized ECDSAPrivToPub from circom-ecdsa (uses precomputed tables)
include "circom-ecdsa/circuits/ecdsa.circom";

/**
 * Leaf Commitment: hash 5 leaf_secret elements
 * leaf = Poseidon(leaf_secret[0..5])
 */
template LeafCommitment() {
    signal input leaf_secret[5];
    signal output leaf;
    
    component hasher = Poseidon(5);
    for (var i = 0; i < 5; i++) {
        hasher.inputs[i] <== leaf_secret[i];
    }
    leaf <== hasher.out;
}

/**
 * Merkle path verification with 20 levels
 * Uses Poseidon(2) for internal nodes
 */
template MerklePath(levels) {
    signal input leaf;
    signal input siblings[levels];
    signal input path_bits[levels];
    signal output root;
    
    component hashers[levels];
    component mux[levels];
    signal hashes[levels + 1];
    
    hashes[0] <== leaf;
    
    for (var i = 0; i < levels; i++) {
        // Ensure path_bits[i] is binary (Sub-circuit 3)
        path_bits[i] * (path_bits[i] - 1) === 0;
        
        // Select order based on path bit
        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== hashes[i];
        mux[i].c[0][1] <== siblings[i];
        mux[i].c[1][0] <== siblings[i];
        mux[i].c[1][1] <== hashes[i];
        mux[i].s <== path_bits[i];
        
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];
        
        hashes[i + 1] <== hashers[i].out;
    }
    
    root <== hashes[levels];
}

/**
 * Derive nsec from leaf_secret[0..2]
 * nsec = Poseidon(leaf_secret[0], leaf_secret[1], leaf_secret[2])
 * 
 * The nsec is a 254-bit BN254 scalar that gets converted to a 256-bit
 * secp256k1 scalar for the EC multiplication.
 */
template DeriveNsec() {
    signal input leaf_secret_0;
    signal input leaf_secret_1;
    signal input leaf_secret_2;
    signal output nsec;
    
    component hasher = Poseidon(3);
    hasher.inputs[0] <== leaf_secret_0;
    hasher.inputs[1] <== leaf_secret_1;
    hasher.inputs[2] <== leaf_secret_2;
    
    nsec <== hasher.out;
}

/**
 * Convert a BN254 field element to 4x64-bit limbs for secp256k1 operations
 * 
 * The Poseidon output is a BN254 scalar (254 bits).
 * secp256k1 operations expect 4 limbs of 64 bits each.
 */
template ScalarToLimbs() {
    signal input scalar;
    signal output limbs[4];
    
    // Decompose to bits (254 bits for BN254)
    component n2b = Num2Bits(254);
    n2b.in <== scalar;
    
    // Recompose into 4 limbs of 64 bits each
    component b2n[4];
    for (var i = 0; i < 4; i++) {
        b2n[i] = Bits2Num(64);
        for (var j = 0; j < 64; j++) {
            var bit_idx = i * 64 + j;
            if (bit_idx < 254) {
                b2n[i].in[j] <== n2b.out[bit_idx];
            } else {
                b2n[i].in[j] <== 0;
            }
        }
        limbs[i] <== b2n[i].out;
    }
}

/**
 * Derive npub from nsec via secp256k1 scalar multiplication
 * npub = nsec * G
 * 
 * Uses ECDSAPrivToPub which has precomputed tables for G and is much more
 * efficient than naive scalar multiplication (~95K constraints vs 1.4M).
 */
template DeriveNpub() {
    signal input nsec_limbs[4];
    signal output npub_x[4];
    signal output npub_y[4];
    
    // Use the optimized ECDSAPrivToPub template
    // n=64 bits per limb, k=4 limbs = 256 bits
    component privToPub = ECDSAPrivToPub(64, 4);
    
    for (var i = 0; i < 4; i++) {
        privToPub.privkey[i] <== nsec_limbs[i];
    }
    
    for (var i = 0; i < 4; i++) {
        npub_x[i] <== privToPub.pubkey[0][i];
        npub_y[i] <== privToPub.pubkey[1][i];
    }
}

/**
 * Main membership circuit
 * 
 * Proves: "I know a leaf_secret such that:
 *   1. Poseidon(leaf_secret[0..5]) is a leaf in the Merkle tree with the given root
 *   2. My npub = secp256k1(Poseidon(leaf_secret[0..3]) * G)"
 * 
 * The nsec (private key) never leaves the circuit. Only the npub (public key) is output.
 */
template Membership() {
    // === Private Inputs ===
    signal input leaf_secret[5];      // 5-element leaf secret
    signal input siblings[20];        // Merkle path siblings
    signal input path_bits[20];       // Merkle path direction bits
    
    // === Public Outputs ===
    signal output merkle_root;        // The Merkle root being proven against
    signal output npub_x[4];          // secp256k1 public key X (4x64-bit limbs)
    signal output npub_y[4];          // secp256k1 public key Y (4x64-bit limbs)
    
    // === Sub-circuit 1: Leaf Commitment ===
    component leafCommit = LeafCommitment();
    for (var i = 0; i < 5; i++) {
        leafCommit.leaf_secret[i] <== leaf_secret[i];
    }
    
    // === Sub-circuit 2 & 3: Merkle Path (includes boolean checks) ===
    component merkle = MerklePath(20);
    merkle.leaf <== leafCommit.leaf;
    for (var i = 0; i < 20; i++) {
        merkle.siblings[i] <== siblings[i];
        merkle.path_bits[i] <== path_bits[i];
    }
    merkle_root <== merkle.root;
    
    // === Sub-circuit 4: npub Derivation ===
    // Step 4a: Derive nsec from leaf_secret[0..2]
    component deriveNsec = DeriveNsec();
    deriveNsec.leaf_secret_0 <== leaf_secret[0];
    deriveNsec.leaf_secret_1 <== leaf_secret[1];
    deriveNsec.leaf_secret_2 <== leaf_secret[2];
    
    // Step 4b: Convert nsec to 4x64-bit limbs
    component toLimbs = ScalarToLimbs();
    toLimbs.scalar <== deriveNsec.nsec;
    
    // Step 4c: secp256k1 scalar multiplication: npub = nsec * G
    // Using ECDSAPrivToPub with precomputed tables (~95K constraints)
    component deriveNpub = DeriveNpub();
    for (var i = 0; i < 4; i++) {
        deriveNpub.nsec_limbs[i] <== toLimbs.limbs[i];
    }
    
    for (var i = 0; i < 4; i++) {
        npub_x[i] <== deriveNpub.npub_x[i];
        npub_y[i] <== deriveNpub.npub_y[i];
    }
}

component main = Membership();
