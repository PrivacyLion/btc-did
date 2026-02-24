/**
 * SignedByMe Membership Circuit
 * 
 * Proves membership in a Merkle tree and derives a NOSTR npub from the leaf secret.
 * 
 * 4 Sub-circuits:
 *   1. Leaf Commitment: leaf = Poseidon2(leaf_secret[0..5])
 *   2. Merkle Path (20 levels): parent = Poseidon2(left, right)
 *   3. Path Bit Boolean: path_bits[i] * (path_bits[i] - 1) === 0
 *   4. npub Derivation: nsec = Poseidon2(leaf_secret[0..2]) → npub = secp256k1_derive(nsec)
 * 
 * Public Outputs: merkle_root, npub_x, npub_y
 * Private Inputs: leaf_secret[5], siblings[20], path_bits[20]
 * 
 * Target: <10,000 constraints, <1s proof on phone
 * 
 * See: SignedByMe Bible Section 12, Phase 4
 */

pragma circom 2.1.0;

// Include Poseidon hash from circomlib
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// SECP256K1 scalar multiplication (from circom-ecdsa or custom implementation)
// NOTE: This is expensive (~15,000+ constraints). May need optimization.
// For MVP, we can use a Poseidon-based npub derivation instead of actual secp256k1.
include "./secp256k1/scalar_mult.circom";

/**
 * Poseidon2 hash with 5 inputs (for leaf commitment)
 * Using standard Poseidon since Poseidon2 templates may not be available in circomlib
 * Poseidon with 5 inputs uses t=6 (inputs + 1 for capacity)
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
        // Ensure path_bits[i] is binary
        path_bits[i] * (path_bits[i] - 1) === 0;
        
        // Select order based on path bit
        // If path_bit = 0: hash(current, sibling)
        // If path_bit = 1: hash(sibling, current)
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
 * NOTE: The nsec is PRIVATE - it never leaves the circuit.
 * Only the derived npub is public.
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
 * Derive npub from nsec via secp256k1 scalar multiplication
 * npub = nsec * G (where G is the secp256k1 generator point)
 * 
 * WARNING: secp256k1 inside BN254 circuit is expensive (~15K+ constraints).
 * Alternative: Use a commitment scheme where npub = Poseidon(nsec, salt)
 * and the verifier checks this commitment matches a registered npub.
 * 
 * For v1, we use the Poseidon-based approach to stay under 10K constraints.
 */
template DeriveNpubPoseidon() {
    signal input nsec;
    signal output npub;
    
    // Domain separator to distinguish npub derivation from other hashes
    // npub = Poseidon(nsec, DOMAIN_SEP) where DOMAIN_SEP is a constant
    var DOMAIN_SEP = 0x6e707562; // "npub" in hex
    
    component hasher = Poseidon(2);
    hasher.inputs[0] <== nsec;
    hasher.inputs[1] <== DOMAIN_SEP;
    
    npub <== hasher.out;
}

/**
 * Main membership circuit
 * 
 * Proves: "I know a leaf_secret such that:
 *   1. Poseidon(leaf_secret[0..5]) is a leaf in the Merkle tree with the given root
 *   2. My npub is derived from Poseidon(leaf_secret[0..3])"
 */
template Membership() {
    // === Private Inputs ===
    signal input leaf_secret[5];      // 5-element leaf secret
    signal input siblings[20];        // Merkle path siblings
    signal input path_bits[20];       // Merkle path direction bits
    
    // === Public Outputs ===
    signal output merkle_root;        // The Merkle root being proven against
    signal output npub;               // Derived NOSTR public key (Poseidon-based)
    
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
    component deriveNsec = DeriveNsec();
    deriveNsec.leaf_secret_0 <== leaf_secret[0];
    deriveNsec.leaf_secret_1 <== leaf_secret[1];
    deriveNsec.leaf_secret_2 <== leaf_secret[2];
    
    component deriveNpub = DeriveNpubPoseidon();
    deriveNpub.nsec <== deriveNsec.nsec;
    
    npub <== deriveNpub.npub;
}

component main {public []} = Membership();
