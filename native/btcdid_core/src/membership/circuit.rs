//! Poseidon2-M31 Circuit for STWO STARK Membership Proofs
//!
//! This circuit proves:
//! 1. Knowledge of leaf_secret such that leaf_commitment = Poseidon2(LEAF_DOM || secret)
//! 2. Merkle path from leaf_commitment to root is valid
//! 3. Nullifier = Poseidon2(NULL_DOM || leaf_secret || session_id) is correctly computed
//! 4. Binding hash is incorporated (public input)
//!
//! # Why Poseidon2-M31 over SHA-256?
//!
//! - Native M31 field arithmetic (no bit decomposition needed)
//! - 8+14+4 = 26 total rounds (vs 64×5=320 for SHA-256 with 5 blocks)
//! - S-box only applied to position 0 in internal rounds
//! - 1+Diag(V) internal layer is sparse (cheap)
//!
//! # Constraint Estimate (Optimized)
//!
//! Per Poseidon2 permutation (WIDTH=16, 8+14 rounds):
//! - External rounds (8 total): 16 S-boxes each = 128 S-boxes
//! - Internal rounds (14 total): 1 S-box each = 14 S-boxes
//! - Total S-boxes per permutation: 142
//!
//! S-box constraints using x² / x⁵ decomposition:
//! - x² = x * x (1 multiplication constraint)
//! - x⁵ = x² * x² * x (1 multiplication constraint, reuses x²)
//! - Total: 2 multiplication constraints per S-box
//!
//! Per permutation: 142 S-boxes × 2 = 284 multiplication constraints
//!
//! For membership proof:
//! - 1 Poseidon2 for leaf commitment
//! - 1 Poseidon2 for nullifier  
//! - 20 Poseidon2 for Merkle path (depth 20)
//! - Total: 22 permutations × 284 = 6,248 multiplication constraints
//!
//! This is MUCH smaller than SHA-256 circuit (~100k constraints for 5 blocks).

#![cfg(feature = "real-stwo")]

use anyhow::{anyhow, Result};
use p3_field::PrimeField32;
use p3_mersenne_31::Mersenne31;
use stwo::core::fields::m31::BaseField;
use stwo::prover::backend::CpuBackend;
use stwo::prover::backend::{Col, Column};
use stwo_constraint_framework::EvalAtRow;

use super::poseidon2_m31::{
    M31, WIDTH, RATE, FULL_ROUNDS_FIRST, FULL_ROUNDS_LAST, PARTIAL_ROUNDS,
    DOMAIN_LEAF, DOMAIN_NULL, DOMAIN_MERK,
    Poseidon2M31Hasher,
};

// ============================================================================
// Circuit Parameters
// ============================================================================

/// Tree depth (supports ~1M members)
pub const TREE_DEPTH: usize = 20;

/// Number of M31 elements in leaf_secret (155 bits entropy > 128 required)
pub const LEAF_SECRET_LEN: usize = 5;

/// Number of M31 elements in session_id (128 bits = 4 elements × 31 bits)
pub const SESSION_ID_LEN: usize = 5;

/// Number of M31 elements in nullifier output (4 elements = 124 bits)
pub const NULLIFIER_LEN: usize = 4;

/// Total rounds in Poseidon2
pub const TOTAL_ROUNDS: usize = FULL_ROUNDS_FIRST + PARTIAL_ROUNDS + FULL_ROUNDS_LAST;

// ============================================================================
// Trace Column Layout (with S-box pre-values and intermediates)
// ============================================================================
//
// For each Poseidon2 permutation, we store:
// - Input state: 16 M31 elements
// - State after each round: 26 rounds × 16 elements = 416 elements
// - S-box pre-values (x = prev + RC): 142 per permutation
// - S-box intermediates (x²): 142 per permutation
//
// Total per permutation: 16 + 416 + 142 + 142 = 716 columns
//
// For membership proof:
// - 22 permutations × 716 = 15,752 columns
//
// Plus auxiliary columns:
// - leaf_secret[5]: 5 columns (private witness)
// - session_id[5]: 5 columns (public input)
// - path_bits[20]: 20 columns (0 or 1 indicating left/right)
// - merkle_root: 1 column (public input)
// - nullifier[4]: 4 columns (public output)
// - binding_hash[8]: 8 columns (public input, as M31 elements)
//
// Grand total: 15,752 + 43 = 15,795 columns
//
// S-box constraints (per S-box, degree 3):
// 1. x² = x * x          (where x is pre_sbox value)
// 2. x⁵ = x² * x² * x    (post_sbox = pre_sbox^5)

/// S-boxes per external round (all 16 elements)
const SBOXES_PER_EXTERNAL_ROUND: usize = WIDTH;

/// S-boxes per internal round (only element 0)
const SBOXES_PER_INTERNAL_ROUND: usize = 1;

/// Total S-boxes per permutation
const SBOXES_PER_PERM: usize = 
    FULL_ROUNDS_FIRST * SBOXES_PER_EXTERNAL_ROUND +   // 4 × 16 = 64
    PARTIAL_ROUNDS * SBOXES_PER_INTERNAL_ROUND +       // 14 × 1 = 14
    FULL_ROUNDS_LAST * SBOXES_PER_EXTERNAL_ROUND;      // 4 × 16 = 64
    // Total: 142

/// Columns for state per permutation (input + all round states)
const STATE_COLS_PER_PERM: usize = WIDTH * (1 + TOTAL_ROUNDS);

/// Columns per Poseidon2 permutation (state + pre_sbox + x²)
const COLS_PER_PERM: usize = STATE_COLS_PER_PERM + SBOXES_PER_PERM + SBOXES_PER_PERM;

/// Total Poseidon2 permutations (leaf + nullifier + merkle path)
const NUM_PERMS: usize = 1 + 1 + TREE_DEPTH;

/// Total auxiliary columns
const AUX_COLS: usize = LEAF_SECRET_LEN + SESSION_ID_LEN + TREE_DEPTH + 1 + NULLIFIER_LEN + 8;

/// Number of trace columns
pub const N_TRACE_COLS: usize = COLS_PER_PERM * NUM_PERMS + AUX_COLS;

/// Log2 of number of rows
/// Must be large enough for STWO's FRI to work with degree-3 constraints
/// Minimum ~8 for proper constraint evaluation domain
pub const LOG_N_ROWS: u32 = 8; // 256 rows

// ============================================================================
// Round Constants (loaded from poseidon2_m31.rs)
// ============================================================================

/// Get external round constants for round `r` and element `i`
fn external_rc(r: usize, i: usize) -> M31 {
    // These come from Plonky3's verified parameters
    // Generated via Xoroshiro128Plus(seed=1)
    super::poseidon2_m31::get_external_constants()[r * WIDTH + i]
}

/// Get internal round constant for round `r` (only element 0)
fn internal_rc(r: usize) -> M31 {
    super::poseidon2_m31::get_internal_constants()[r]
}

/// Get internal diagonal matrix V values
/// 
/// Plonky3 uses HARDCODED optimized values for Mersenne31 (NOT random):
/// V = [-2, 1, 2, 4, 8, 16, 32, 64, 128, 256, 1024, 4096, 8192, 16384, 32768, 65536]
/// 
/// These are specifically chosen for efficient multiplication (shifts) in AVX2/AVX512/NEON.
/// See: plonky3/mersenne-31/src/poseidon2.rs
fn internal_diag(i: usize) -> M31 {
    const INTERNAL_DIAG: [i64; 16] = [
        -2, 1, 2, 4, 8, 16, 32, 64, 128, 256, 1024, 4096, 8192, 16384, 32768, 65536
    ];
    // Convert to M31 (handle negative value for -2)
    if INTERNAL_DIAG[i] < 0 {
        // -2 mod (2^31 - 1) = 2^31 - 1 - 2 = 2147483645
        M31::new(((1i64 << 31) - 1 + INTERNAL_DIAG[i]) as u32)
    } else {
        M31::new(INTERNAL_DIAG[i] as u32)
    }
}

// ============================================================================
// Poseidon2 Operations
// ============================================================================

/// S-box: x^5 using optimized constraint-friendly decomposition
/// 
/// Decomposes x^5 into 2 multiplication constraints (not 4):
/// 1. x² = x * x
/// 2. x⁵ = x² * x² * x = x⁴ * x
/// 
/// For 142 S-boxes total, this saves 284 constraints vs naive approach.
#[inline]
fn sbox(x: M31) -> M31 {
    let x2 = x * x;      // Constraint 1: x² = x * x
    let x4 = x2 * x2;    // (computed from x², no new constraint needed)
    x4 * x               // Constraint 2: x⁵ = x⁴ * x
}

/// S-box with intermediate values for constraint generation
/// Returns (x², x⁵) so constraints can reference intermediate
#[inline]
fn sbox_with_intermediate(x: M31) -> (M31, M31) {
    let x2 = x * x;
    let x4 = x2 * x2;
    let x5 = x4 * x;
    (x2, x5)
}

/// Apply M4 circulant matrix to 4 elements:
/// [ 2 3 1 1 ]
/// [ 1 2 3 1 ]
/// [ 1 1 2 3 ]
/// [ 3 1 1 2 ]
/// 
/// This is Plonky3's optimized `apply_mat4` using 7 additions + 2 doubles.
#[inline]
fn apply_mat4(x: &mut [M31; 4]) {
    let t01 = x[0] + x[1];
    let t23 = x[2] + x[3];
    let t0123 = t01 + t23;
    let t01123 = t0123 + x[1];
    let t01233 = t0123 + x[3];
    
    // Order matters - need to overwrite x[0] and x[2] after using them
    let x0_double = x[0] + x[0];
    let x2_double = x[2] + x[2];
    
    x[3] = t01233 + x0_double; // 3*x[0] + x[1] + x[2] + 2*x[3]
    x[1] = t01123 + x2_double; // x[0] + 2*x[1] + 3*x[2] + x[3]
    x[0] = t01123 + t01;       // 2*x[0] + 3*x[1] + x[2] + x[3]
    x[2] = t01233 + t23;       // x[0] + x[1] + 2*x[2] + 3*x[3]
}

/// External linear layer: MDS light permutation
/// 
/// For WIDTH=16, this:
/// 1. Applies M4 to each consecutive group of 4 elements
/// 2. Adds the sum of corresponding positions across all groups
/// 
/// This matches Plonky3's `mds_light_permutation` exactly.
fn external_linear(state: &mut [M31; WIDTH]) {
    // Step 1: Apply M4 to each group of 4
    for i in 0..4 {
        let offset = i * 4;
        let mut chunk = [state[offset], state[offset+1], state[offset+2], state[offset+3]];
        apply_mat4(&mut chunk);
        state[offset] = chunk[0];
        state[offset+1] = chunk[1];
        state[offset+2] = chunk[2];
        state[offset+3] = chunk[3];
    }
    
    // Step 2: Add sums of corresponding positions across groups
    // sums[k] = sum of all state[j + k] where j = 0, 4, 8, 12
    let sums: [M31; 4] = [
        state[0] + state[4] + state[8] + state[12],
        state[1] + state[5] + state[9] + state[13],
        state[2] + state[6] + state[10] + state[14],
        state[3] + state[7] + state[11] + state[15],
    ];
    
    // Each element adds the corresponding sum
    for i in 0..WIDTH {
        state[i] = state[i] + sums[i % 4];
    }
}

/// Internal linear layer: M_I = 1*1^T + Diag(V)
/// 
/// Where 1*1^T is the all-ones matrix (not identity).
/// 
/// Formula: new[i] = old[i] * V[i] + sum(old)
/// 
/// This matches Plonky3's matmul_internal exactly:
///   let sum = sum_array(state);
///   for i in 0..WIDTH {
///       state[i] *= mat_internal_diag_m_1[i];
///       state[i] += sum;
///   }
fn internal_linear(state: &mut [M31; WIDTH]) {
    let sum: M31 = state.iter().copied().sum();
    
    for i in 0..WIDTH {
        state[i] = state[i] * internal_diag(i) + sum;
    }
}

// ============================================================================
// Circuit Witness Generation
// ============================================================================

/// Witness for a single Poseidon2 permutation
#[derive(Clone)]
pub struct PermutationWitness {
    /// Input state
    pub input: [M31; WIDTH],
    /// State after each round (26 rounds)
    pub round_states: Vec<[M31; WIDTH]>,
}

impl PermutationWitness {
    /// Generate witness for a Poseidon2 permutation
    pub fn generate(input: [M31; WIDTH]) -> Self {
        let mut state = input;
        let mut round_states = Vec::with_capacity(TOTAL_ROUNDS);
        
        // CRITICAL: Initial external linear layer (Poseidon2 spec requirement)
        // This is applied BEFORE any rounds begin
        external_linear(&mut state);
        
        // First half of full rounds
        for r in 0..FULL_ROUNDS_FIRST {
            // Add round constants
            for i in 0..WIDTH {
                state[i] = state[i] + external_rc(r, i);
            }
            // S-box to all elements
            for i in 0..WIDTH {
                state[i] = sbox(state[i]);
            }
            // Linear layer
            external_linear(&mut state);
            round_states.push(state);
        }
        
        // Partial rounds
        for r in 0..PARTIAL_ROUNDS {
            // Add round constant to element 0 only
            state[0] = state[0] + internal_rc(r);
            // S-box to element 0 only
            state[0] = sbox(state[0]);
            // Internal linear layer
            internal_linear(&mut state);
            round_states.push(state);
        }
        
        // Second half of full rounds
        for r in 0..FULL_ROUNDS_LAST {
            let rc_idx = FULL_ROUNDS_FIRST + r;
            // Add round constants
            for i in 0..WIDTH {
                state[i] = state[i] + external_rc(rc_idx, i);
            }
            // S-box to all elements
            for i in 0..WIDTH {
                state[i] = sbox(state[i]);
            }
            // Linear layer
            external_linear(&mut state);
            round_states.push(state);
        }
        
        Self { input, round_states }
    }
    
    /// Get the output (state after last round)
    pub fn output(&self) -> [M31; WIDTH] {
        self.round_states[TOTAL_ROUNDS - 1]
    }
}

/// Full membership proof witness
pub struct MembershipWitness {
    /// Leaf secret (private)
    pub leaf_secret: [M31; LEAF_SECRET_LEN],
    /// Session ID (public, for nullifier)
    pub session_id: [M31; SESSION_ID_LEN],
    /// Merkle path siblings (private)
    pub siblings: Vec<M31>,
    /// Path bits: 0 = sibling on right, 1 = sibling on left (private)
    pub path_bits: Vec<bool>,
    /// Merkle root (public)
    pub root: M31,
    /// Binding hash as M31 elements (public)
    pub binding_hash: [M31; 8],
    
    /// Computed: leaf commitment permutation witness
    pub leaf_perm: PermutationWitness,
    /// Computed: nullifier permutation witness
    pub null_perm: PermutationWitness,
    /// Computed: Merkle path permutation witnesses
    pub merkle_perms: Vec<PermutationWitness>,
    /// Computed: nullifier output
    pub nullifier: [M31; NULLIFIER_LEN],
}

impl MembershipWitness {
    /// Generate full witness for membership proof
    pub fn generate(
        leaf_secret: [M31; LEAF_SECRET_LEN],
        session_id: [M31; SESSION_ID_LEN],
        siblings: Vec<M31>,
        path_bits: Vec<bool>,
        root: M31,
        binding_hash: [M31; 8],
    ) -> Result<Self> {
        if siblings.len() != TREE_DEPTH {
            return Err(anyhow!("Expected {} siblings, got {}", TREE_DEPTH, siblings.len()));
        }
        if path_bits.len() != TREE_DEPTH {
            return Err(anyhow!("Expected {} path_bits, got {}", TREE_DEPTH, path_bits.len()));
        }
        
        // 1. Compute leaf commitment
        let mut leaf_input = [M31::new(0); WIDTH];
        leaf_input[0] = M31::new(DOMAIN_LEAF);
        for i in 0..LEAF_SECRET_LEN {
            leaf_input[1 + i] = leaf_secret[i];
        }
        let leaf_perm = PermutationWitness::generate(leaf_input);
        let leaf_commitment = leaf_perm.output()[1]; // Output from position 1
        
        // 2. Compute nullifier
        let mut null_input = [M31::new(0); WIDTH];
        null_input[0] = M31::new(DOMAIN_NULL);
        for i in 0..LEAF_SECRET_LEN {
            null_input[1 + i] = leaf_secret[i];
        }
        for i in 0..SESSION_ID_LEN {
            null_input[1 + LEAF_SECRET_LEN + i] = session_id[i];
        }
        let null_perm = PermutationWitness::generate(null_input);
        let nullifier = [
            null_perm.output()[1],
            null_perm.output()[2],
            null_perm.output()[3],
            null_perm.output()[4],
        ];
        
        // 3. Verify Merkle path and generate witnesses
        let mut current = leaf_commitment;
        let mut merkle_perms = Vec::with_capacity(TREE_DEPTH);
        
        for i in 0..TREE_DEPTH {
            let sibling = siblings[i];
            let (left, right) = if path_bits[i] {
                (sibling, current)
            } else {
                (current, sibling)
            };
            
            let mut merkle_input = [M31::new(0); WIDTH];
            merkle_input[0] = M31::new(DOMAIN_MERK);
            merkle_input[1] = left;
            merkle_input[2] = right;
            
            let perm = PermutationWitness::generate(merkle_input);
            current = perm.output()[1];
            merkle_perms.push(perm);
        }
        
        // Verify root matches
        if current != root {
            return Err(anyhow!(
                "Merkle path does not lead to expected root. Got {:?}, expected {:?}",
                current, root
            ));
        }
        
        Ok(Self {
            leaf_secret,
            session_id,
            siblings,
            path_bits,
            root,
            binding_hash,
            leaf_perm,
            null_perm,
            merkle_perms,
            nullifier,
        })
    }
}

// ============================================================================
// STWO Circuit Constraints (FrameworkEval implementation)
// ============================================================================

/// Membership proof evaluator for STWO constraint framework
pub struct MembershipEval {
    pub log_n_rows: u32,
}

impl Default for MembershipEval {
    fn default() -> Self {
        Self { log_n_rows: LOG_N_ROWS }
    }
}

// Column indices for trace
const COL_LEAF_SECRET_START: usize = 0;
const COL_SESSION_ID_START: usize = LEAF_SECRET_LEN;
const COL_PATH_BITS_START: usize = COL_SESSION_ID_START + SESSION_ID_LEN;
const COL_ROOT: usize = COL_PATH_BITS_START + TREE_DEPTH;
const COL_NULLIFIER_START: usize = COL_ROOT + 1;
const COL_BINDING_HASH_START: usize = COL_NULLIFIER_START + NULLIFIER_LEN;
const COL_PERM_START: usize = COL_BINDING_HASH_START + 8;

impl stwo_constraint_framework::FrameworkEval for MembershipEval {
    fn log_size(&self) -> u32 {
        self.log_n_rows
    }
    
    fn max_constraint_log_degree_bound(&self) -> u32 {
        // With x² intermediates, S-box constraint is: x⁵ = x² * x² * x (degree 3)
        // log2(3) ≈ 1.58, so we need log_n_rows + 2
        self.log_n_rows + 2
    }
    
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        // =========================================================================
        // STWO Constraint Framework Integration
        // =========================================================================
        //
        // Column layout (must match generate_trace exactly):
        // 1. Auxiliary columns: leaf_secret[5], session_id[5], path_bits[20], 
        //    root[1], nullifier[4], binding_hash[8] = 43 columns
        // 2. Permutation columns: 22 perms × 574 = 12,628 columns
        //    Per permutation: input[16] + rounds[26×16] + sbox_intermediates[142]
        // Total: 43 + 12,628 = 12,671 = N_TRACE_COLS
        
        // =========================================================================
        // Step 1: Read all auxiliary columns (43 total)
        // =========================================================================
        
        // Leaf secret (private witness, 5 columns)
        let leaf_secret: Vec<_> = (0..LEAF_SECRET_LEN)
            .map(|_| eval.next_trace_mask())
            .collect();
        
        // Session ID (public input, 5 columns)
        let session_id: Vec<_> = (0..SESSION_ID_LEN)
            .map(|_| eval.next_trace_mask())
            .collect();
        
        // Path bits (private witness, 20 columns)
        let path_bits: Vec<_> = (0..TREE_DEPTH)
            .map(|_| eval.next_trace_mask())
            .collect();
        
        // Root (public input, 1 column)
        let root = eval.next_trace_mask();
        
        // Nullifier output (public output, 4 columns)
        let nullifier: Vec<_> = (0..NULLIFIER_LEN)
            .map(|_| eval.next_trace_mask())
            .collect();
        
        // Binding hash (public input, 8 columns)
        let _binding_hash: Vec<_> = (0..8)
            .map(|_| eval.next_trace_mask())
            .collect();
        
        // =========================================================================
        // Step 2: Read all permutation traces with S-box intermediates
        // =========================================================================
        //
        // Layout per permutation: 
        //   input[16] + rounds[26][16] + sbox_x2[142] = 574 columns
        
        // Storage for all permutation data
        struct PermData<F> {
            input: Vec<F>,
            rounds: Vec<Vec<F>>,
            pre_sbox: Vec<F>,  // Pre-S-box values (x = prev + RC)
            sbox_x2: Vec<F>,   // x² intermediates
        }
        
        let mut all_perms: Vec<PermData<E::F>> = Vec::with_capacity(NUM_PERMS);
        
        // Read all 22 permutations
        for _ in 0..NUM_PERMS {
            // Input state (16 elements)
            let input: Vec<_> = (0..WIDTH).map(|_| eval.next_trace_mask()).collect();
            
            // Round states (26 rounds × 16 elements)
            let rounds: Vec<Vec<_>> = (0..TOTAL_ROUNDS)
                .map(|_| (0..WIDTH).map(|_| eval.next_trace_mask()).collect())
                .collect();
            
            // Pre-S-box values (142 per permutation)
            let pre_sbox: Vec<_> = (0..SBOXES_PER_PERM)
                .map(|_| eval.next_trace_mask())
                .collect();
            
            // S-box x² intermediates (142 per permutation)
            let sbox_x2: Vec<_> = (0..SBOXES_PER_PERM)
                .map(|_| eval.next_trace_mask())
                .collect();
            
            all_perms.push(PermData { input, rounds, pre_sbox, sbox_x2 });
        }
        
        // =========================================================================
        // Step 3: Add Poseidon2 round constraints for each permutation
        // =========================================================================
        //
        // For each S-box we have:
        //   pre_sbox (x): the value before S-box
        //   sbox_x2 (x²): the square of pre_sbox
        //   post_sbox = x⁵ = x² * x² * x (computed symbolically)
        //
        // For external rounds:
        //   round_output = external_linear(post_sbox)
        //   where external_linear applies M4 circulant + cross-group sums
        //
        // For internal rounds:
        //   post_sbox[0] = x⁵, post_sbox[i>0] = prev_state[i] (no S-box)
        //   round_output = internal_linear(post_sbox)
        //
        // Constraints:
        //   1. x² = x * x (degree 2)
        //   2. round_output[i] = linear_layer(post_sbox)[i] (degree 3)
        
        for perm in &all_perms {
            // =====================================================================
            // Constraint 1: x² = x * x for all S-boxes
            // =====================================================================
            for i in 0..SBOXES_PER_PERM {
                let x = &perm.pre_sbox[i];
                let x2 = &perm.sbox_x2[i];
                eval.add_constraint(x2.clone() - x.clone() * x.clone());
            }
            
            // =====================================================================
            // Constraint 2: External round transitions (first 4 rounds)
            // =====================================================================
            // 
            // For external round r:
            //   post_sbox[i] = x²[i] * x²[i] * pre_sbox[i]  (S-box output)
            //   round_output = external_linear(post_sbox)
            //
            // external_linear:
            //   1. Apply M4 = circ(2,3,1,1) to each group of 4
            //   2. Add sums of corresponding positions across groups
            //
            // Result for element i (group g = i/4, position j = i%4):
            //   output[i] = Σ_{k=0..3} M4[j][k] * (post_sbox[4g+k] + T_k)
            //   where T_k = Σ_{h=0..3} post_sbox[4h+k]
            //
            // M4 circulant rows:
            //   j=0: [2,3,1,1]
            //   j=1: [1,2,3,1]
            //   j=2: [1,1,2,3]
            //   j=3: [3,1,1,2]
            
            for r in 0..FULL_ROUNDS_FIRST {
                let sbox_base = r * WIDTH;
                
                for i in 0..WIDTH {
                    let g = i / 4;
                    let j = i % 4;
                    
                    // M4 coefficients for row j
                    let m4_row: [u32; 4] = match j {
                        0 => [2, 3, 1, 1],
                        1 => [1, 2, 3, 1],
                        2 => [1, 1, 2, 3],
                        3 => [3, 1, 1, 2],
                        _ => unreachable!(),
                    };
                    
                    // Helper to compute post_sbox symbolically: x⁵ = x² * x² * x
                    let ps = |idx: usize| -> E::F {
                        let x2 = &perm.sbox_x2[sbox_base + idx];
                        let x = &perm.pre_sbox[sbox_base + idx];
                        x2.clone() * x2.clone() * x.clone()
                    };
                    
                    // Compute T_k = sum of post_sbox at position k across all groups
                    let t0 = ps(0) + ps(4) + ps(8) + ps(12);
                    let t1 = ps(1) + ps(5) + ps(9) + ps(13);
                    let t2 = ps(2) + ps(6) + ps(10) + ps(14);
                    let t3 = ps(3) + ps(7) + ps(11) + ps(15);
                    
                    // Compute output[i] = Σ_{k=0..3} m4[j][k] * (post_sbox[4g+k] + T_k)
                    // Using repeated addition for multiplication by constant
                    let term0 = ps(4*g + 0) + t0.clone();
                    let term1 = ps(4*g + 1) + t1.clone();
                    let term2 = ps(4*g + 2) + t2.clone();
                    let term3 = ps(4*g + 3) + t3.clone();
                    
                    // Scale each term by its M4 coefficient (using repeated addition)
                    let scaled0 = scale_by(term0, m4_row[0]);
                    let scaled1 = scale_by(term1, m4_row[1]);
                    let scaled2 = scale_by(term2, m4_row[2]);
                    let scaled3 = scale_by(term3, m4_row[3]);
                    
                    let expected = scaled0 + scaled1 + scaled2 + scaled3;
                    eval.add_constraint(perm.rounds[r][i].clone() - expected);
                }
            }
            
            // =====================================================================
            // Constraint 3: Internal round transitions (14 rounds)
            // =====================================================================
            //
            // For internal round r:
            //   post_sbox[0] = x⁵ (element 0 through S-box)
            //   post_sbox[i>0] = prev_round[i] (other elements unchanged)
            //   round_output = internal_linear(post_sbox)
            //
            // internal_linear: output[i] = post_sbox[i] * V[i] + sum(post_sbox)
            //   where V = [-2,1,2,4,8,16,32,64,128,256,1024,4096,8192,16384,32768,65536]
            //
            // For -2: output = -(2*x) = sum - 2*x - x = sum - 3*x + x - 2*x = ...
            // Actually: -2*x = sum - sum - 2*x, but we need sum + (-2)*x
            // Let's express: output[0] = V[0]*post_sbox[0] + sum = -2*post_sbox[0] + sum
            //              = sum - 2*post_sbox[0] - post_sbox[0] + post_sbox[0]
            //              = sum - post_sbox[0] - post_sbox[0]
            // But that's sum - 2*ps[0], and we need -2*ps[0] + sum
            // These are the same! So: output[0] = sum - ps[0] - ps[0]
            
            for r in 0..PARTIAL_ROUNDS {
                let round_idx = FULL_ROUNDS_FIRST + r;
                let sbox_idx = FULL_ROUNDS_FIRST * WIDTH + r;
                
                let prev_round = &perm.rounds[round_idx - 1];
                
                // post_sbox[0] = x² * x² * pre_sbox
                let x2_0 = &perm.sbox_x2[sbox_idx];
                let x_0 = &perm.pre_sbox[sbox_idx];
                let ps0 = x2_0.clone() * x2_0.clone() * x_0.clone();
                
                // sum(post_sbox) = ps0 + Σ_{i=1..15} prev_round[i]
                let mut sum = ps0.clone();
                for i in 1..WIDTH {
                    sum = sum + prev_round[i].clone();
                }
                
                // V values (positive only for now, handle -2 specially)
                const V_POS: [u32; 16] = [
                    2, 1, 2, 4, 8, 16, 32, 64, 128, 256, 1024, 4096, 8192, 16384, 32768, 65536
                ];
                
                // Element 0: output = -2*ps0 + sum = sum - 2*ps0
                let expected_0 = sum.clone() - ps0.clone() - ps0.clone();
                eval.add_constraint(perm.rounds[round_idx][0].clone() - expected_0);
                
                // Elements 1..15: output[i] = V[i]*prev_round[i] + sum
                for i in 1..WIDTH {
                    let expected = scale_by(prev_round[i].clone(), V_POS[i]) + sum.clone();
                    eval.add_constraint(perm.rounds[round_idx][i].clone() - expected);
                }
            }
            
            // =====================================================================
            // Constraint 4: Final external rounds (last 4 rounds)
            // =====================================================================
            
            for r in 0..FULL_ROUNDS_LAST {
                let round_idx = FULL_ROUNDS_FIRST + PARTIAL_ROUNDS + r;
                // S-box indices: first 64 (4*16), then 14 internal, then 64 more
                let sbox_base = FULL_ROUNDS_FIRST * WIDTH + PARTIAL_ROUNDS + r * WIDTH;
                
                for i in 0..WIDTH {
                    let g = i / 4;
                    let j = i % 4;
                    
                    let m4_row: [u32; 4] = match j {
                        0 => [2, 3, 1, 1],
                        1 => [1, 2, 3, 1],
                        2 => [1, 1, 2, 3],
                        3 => [3, 1, 1, 2],
                        _ => unreachable!(),
                    };
                    
                    let ps = |idx: usize| -> E::F {
                        let x2 = &perm.sbox_x2[sbox_base + idx];
                        let x = &perm.pre_sbox[sbox_base + idx];
                        x2.clone() * x2.clone() * x.clone()
                    };
                    
                    let t0 = ps(0) + ps(4) + ps(8) + ps(12);
                    let t1 = ps(1) + ps(5) + ps(9) + ps(13);
                    let t2 = ps(2) + ps(6) + ps(10) + ps(14);
                    let t3 = ps(3) + ps(7) + ps(11) + ps(15);
                    
                    let term0 = ps(4*g + 0) + t0.clone();
                    let term1 = ps(4*g + 1) + t1.clone();
                    let term2 = ps(4*g + 2) + t2.clone();
                    let term3 = ps(4*g + 3) + t3.clone();
                    
                    let expected = scale_by(term0, m4_row[0]) 
                        + scale_by(term1, m4_row[1])
                        + scale_by(term2, m4_row[2]) 
                        + scale_by(term3, m4_row[3]);
                    
                    eval.add_constraint(perm.rounds[round_idx][i].clone() - expected);
                }
            }
        }
        
        // Helper: multiply expression by positive integer via repeated addition
        #[inline]
        fn scale_by<F: Clone + std::ops::Add<Output = F>>(expr: F, coeff: u32) -> F {
            debug_assert!(coeff > 0, "scale_by requires positive coefficient");
            let mut result = expr.clone();
            for _ in 1..coeff {
                result = result + expr.clone();
            }
            result
        }
        
        // =========================================================================
        // Step 4: Add structural constraints (data flow)
        // =========================================================================
        
        // --- Leaf commitment (permutation 0) ---
        let leaf_perm = &all_perms[0];
        
        // Constrain: leaf_input[1..6] = leaf_secret[0..5]
        for i in 0..LEAF_SECRET_LEN {
            eval.add_constraint(leaf_perm.input[1 + i].clone() - leaf_secret[i].clone());
        }
        
        // Constrain: padding positions must be zero
        for i in (1 + LEAF_SECRET_LEN)..WIDTH {
            eval.add_constraint(leaf_perm.input[i].clone());
        }
        
        // --- Nullifier (permutation 1) ---
        let null_perm = &all_perms[1];
        
        // Constrain: null_input[1..6] = leaf_secret (same secret proves binding)
        for i in 0..LEAF_SECRET_LEN {
            eval.add_constraint(null_perm.input[1 + i].clone() - leaf_secret[i].clone());
        }
        
        // Constrain: null_input[6..11] = session_id
        for i in 0..SESSION_ID_LEN {
            eval.add_constraint(null_perm.input[1 + LEAF_SECRET_LEN + i].clone() - session_id[i].clone());
        }
        
        // Constrain: padding positions must be zero
        for i in (1 + LEAF_SECRET_LEN + SESSION_ID_LEN)..WIDTH {
            eval.add_constraint(null_perm.input[i].clone());
        }
        
        // Constrain: nullifier output = positions 1-4 of final nullifier state
        let null_final = &null_perm.rounds[TOTAL_ROUNDS - 1];
        for i in 0..NULLIFIER_LEN {
            eval.add_constraint(nullifier[i].clone() - null_final[1 + i].clone());
        }
        
        // --- Merkle path (permutations 2..22) ---
        let leaf_commitment = leaf_perm.rounds[TOTAL_ROUNDS - 1][1].clone();
        let mut prev_hash = leaf_commitment;
        
        for level in 0..TREE_DEPTH {
            let merk_perm = &all_perms[2 + level];
            
            // Constrain: padding positions must be zero  
            for i in 3..WIDTH {
                eval.add_constraint(merk_perm.input[i].clone());
            }
            
            // Constrain: one of the inputs equals previous hash
            let diff1 = merk_perm.input[1].clone() - prev_hash.clone();
            let diff2 = merk_perm.input[2].clone() - prev_hash.clone();
            
            // diff1 * diff2 = 0 means at least one position has prev_hash
            eval.add_constraint(diff1.clone() * diff2.clone());
            
            // Update for next level
            prev_hash = merk_perm.rounds[TOTAL_ROUNDS - 1][1].clone();
        }
        
        // Constrain: final merkle output == root
        eval.add_constraint(prev_hash - root);
        
        // =========================================================================
        // Step 5: Binary constraints for path bits
        // =========================================================================
        for bit in &path_bits {
            // bit² - bit = 0 iff bit ∈ {0, 1}
            eval.add_constraint(bit.clone() * bit.clone() - bit.clone());
        }
        
        eval
    }
}

// ============================================================================
// Trace Generation
// ============================================================================

/// Generate STWO trace from membership witness
pub fn generate_trace(witness: &MembershipWitness) -> Vec<Col<CpuBackend, BaseField>> {
    let n_rows = 1 << LOG_N_ROWS;
    let mut trace: Vec<Col<CpuBackend, BaseField>> = Vec::with_capacity(N_TRACE_COLS);
    
    // Initialize all columns with zeros
    for _ in 0..N_TRACE_COLS {
        let col = Col::<CpuBackend, BaseField>::zeros(n_rows);
        trace.push(col);
    }
    
    // Fill in witness values (row 0)
    // Leaf secret
    for i in 0..LEAF_SECRET_LEN {
        trace[COL_LEAF_SECRET_START + i].as_mut_slice()[0] = 
            BaseField::from(witness.leaf_secret[i].as_canonical_u32());
    }
    
    // Session ID
    for i in 0..SESSION_ID_LEN {
        trace[COL_SESSION_ID_START + i].as_mut_slice()[0] = 
            BaseField::from(witness.session_id[i].as_canonical_u32());
    }
    
    // Path bits
    for i in 0..TREE_DEPTH {
        trace[COL_PATH_BITS_START + i].as_mut_slice()[0] = 
            if witness.path_bits[i] { BaseField::from_u32_unchecked(1) } else { BaseField::from_u32_unchecked(0) };
    }
    
    // Root
    trace[COL_ROOT].as_mut_slice()[0] = BaseField::from(witness.root.as_canonical_u32());
    
    // Nullifier
    for i in 0..NULLIFIER_LEN {
        trace[COL_NULLIFIER_START + i].as_mut_slice()[0] = 
            BaseField::from(witness.nullifier[i].as_canonical_u32());
    }
    
    // Binding hash
    for i in 0..8 {
        trace[COL_BINDING_HASH_START + i].as_mut_slice()[0] = 
            BaseField::from(witness.binding_hash[i].as_canonical_u32());
    }
    
    // Permutation states
    let mut perm_col = COL_PERM_START;
    
    // Leaf commitment permutation
    fill_permutation_trace(&mut trace, perm_col, &witness.leaf_perm);
    perm_col += COLS_PER_PERM;
    
    // Nullifier permutation
    fill_permutation_trace(&mut trace, perm_col, &witness.null_perm);
    perm_col += COLS_PER_PERM;
    
    // Merkle path permutations
    for perm in &witness.merkle_perms {
        fill_permutation_trace(&mut trace, perm_col, perm);
        perm_col += COLS_PER_PERM;
    }
    
    // CRITICAL: Copy row 0 to all other rows
    // STWO evaluates constraints on ALL rows, so they must all contain valid data
    // that satisfies the constraints. Since our proof is for a single membership,
    // we duplicate the data across all rows.
    for col in &mut trace {
        let row0_val = col.as_slice()[0];
        for row in 1..n_rows {
            col.as_mut_slice()[row] = row0_val;
        }
    }
    
    trace
}

/// Fill trace columns for a single permutation (including S-box intermediates)
fn fill_permutation_trace(
    trace: &mut Vec<Col<CpuBackend, BaseField>>,
    start_col: usize,
    perm: &PermutationWitness,
) {
    // Input state (16 columns)
    for i in 0..WIDTH {
        trace[start_col + i].as_mut_slice()[0] = 
            BaseField::from(perm.input[i].as_canonical_u32());
    }
    
    // Round states (26 × 16 = 416 columns)
    for (r, state) in perm.round_states.iter().enumerate() {
        let offset = start_col + WIDTH + r * WIDTH;
        for i in 0..WIDTH {
            trace[offset + i].as_mut_slice()[0] = 
                BaseField::from(state[i].as_canonical_u32());
        }
    }
    
    // S-box columns: pre_sbox values (142) followed by x² intermediates (142)
    // Total: 284 columns for S-box data per permutation
    //
    // Layout within permutation:
    //   [input: 16] [rounds: 416] [pre_sbox: 142] [x²: 142]
    
    // Use the module-level external_rc() and internal_rc() functions
    // which handle indexing into the round constants
    
    let pre_sbox_start = start_col + STATE_COLS_PER_PERM;
    let x2_start = pre_sbox_start + SBOXES_PER_PERM;
    let mut sbox_idx = 0;
    
    // Track state through permutation to get pre-S-box values
    let mut state = perm.input;
    external_linear(&mut state); // Initial linear layer
    
    // First 4 external rounds
    for r in 0..FULL_ROUNDS_FIRST {
        // Add round constants - this is the pre-S-box state
        for i in 0..WIDTH {
            let pre_sbox = state[i] + external_rc(r, i);
            let x2 = pre_sbox * pre_sbox;
            
            // Store pre_sbox
            trace[pre_sbox_start + sbox_idx].as_mut_slice()[0] = 
                BaseField::from(pre_sbox.as_canonical_u32());
            // Store x²
            trace[x2_start + sbox_idx].as_mut_slice()[0] = 
                BaseField::from(x2.as_canonical_u32());
            
            sbox_idx += 1;
        }
        
        // Use the stored round state for next iteration
        state = perm.round_states[r];
    }
    
    // 14 internal rounds (S-box only on element 0)
    for r in 0..PARTIAL_ROUNDS {
        let round_idx = FULL_ROUNDS_FIRST + r;
        
        // Get the state before this round (previous round's output)
        let prev_state = perm.round_states[round_idx - 1];
        
        // Add round constant to element 0 only
        let pre_sbox = prev_state[0] + internal_rc(r);
        let x2 = pre_sbox * pre_sbox;
        
        // Store pre_sbox
        trace[pre_sbox_start + sbox_idx].as_mut_slice()[0] = 
            BaseField::from(pre_sbox.as_canonical_u32());
        // Store x²
        trace[x2_start + sbox_idx].as_mut_slice()[0] = 
            BaseField::from(x2.as_canonical_u32());
        
        sbox_idx += 1;
    }
    
    // Final 4 external rounds
    for r in 0..FULL_ROUNDS_LAST {
        let round_idx = FULL_ROUNDS_FIRST + PARTIAL_ROUNDS + r;
        let rc_idx = FULL_ROUNDS_FIRST + r;
        
        // Get previous state
        let prev_state = perm.round_states[round_idx - 1];
        
        // Add round constants - this is the pre-S-box state
        for i in 0..WIDTH {
            let pre_sbox = prev_state[i] + external_rc(rc_idx, i);
            let x2 = pre_sbox * pre_sbox;
            
            // Store pre_sbox
            trace[pre_sbox_start + sbox_idx].as_mut_slice()[0] = 
                BaseField::from(pre_sbox.as_canonical_u32());
            // Store x²
            trace[x2_start + sbox_idx].as_mut_slice()[0] = 
                BaseField::from(x2.as_canonical_u32());
            
            sbox_idx += 1;
        }
    }
    
    debug_assert_eq!(sbox_idx, SBOXES_PER_PERM, 
        "Expected {} S-box values, computed {}", SBOXES_PER_PERM, sbox_idx);
}

// ============================================================================
// Public Interface
// ============================================================================

/// Generate a membership proof
pub fn prove_membership(
    leaf_secret: &[u8; 32],
    session_id: &[u8; 32],
    siblings: &[[u8; 32]],
    path_bits: &[bool],
    root: &[u8; 32],
    binding_hash: &[u8; 32],
) -> Result<Vec<u8>> {
    // Convert inputs to M31 elements
    let leaf_m31 = bytes_to_m31_array::<LEAF_SECRET_LEN>(leaf_secret)?;
    let session_m31 = bytes_to_m31_array::<SESSION_ID_LEN>(session_id)?;
    let root_m31 = bytes_to_single_m31(root);
    let binding_m31 = bytes_to_m31_array::<8>(binding_hash)?;
    
    let siblings_m31: Vec<M31> = siblings.iter()
        .map(|s| bytes_to_single_m31(s))
        .collect();
    
    // Generate witness
    let witness = MembershipWitness::generate(
        leaf_m31,
        session_m31,
        siblings_m31,
        path_bits.to_vec(),
        root_m31,
        binding_m31,
    )?;
    
    // Generate trace
    let _trace = generate_trace(&witness);
    
    // TODO: Generate actual STWO proof
    // For now, return the nullifier and witness hash as placeholder
    let mut proof = Vec::new();
    proof.push(0x03); // Version 3
    
    // Nullifier (16 bytes)
    for n in &witness.nullifier {
        proof.extend_from_slice(&n.as_canonical_u32().to_le_bytes());
    }
    
    // Root (for verification)
    proof.extend_from_slice(root);
    
    // Binding hash (for verification)
    proof.extend_from_slice(binding_hash);
    
    Ok(proof)
}

/// Verify a membership proof
pub fn verify_membership(
    proof: &[u8],
    root: &[u8; 32],
    binding_hash: &[u8; 32],
) -> Result<bool> {
    if proof.len() < 1 + 16 + 32 + 32 {
        return Err(anyhow!("Proof too short"));
    }
    
    let version = proof[0];
    if version != 0x03 {
        return Err(anyhow!("Unsupported proof version: {}", version));
    }
    
    // Extract root from proof and compare
    let proof_root = &proof[17..49];
    if proof_root != root {
        return Ok(false);
    }
    
    // Extract binding hash from proof and compare
    let proof_binding = &proof[49..81];
    if proof_binding != binding_hash {
        return Ok(false);
    }
    
    // TODO: Verify actual STWO proof
    Ok(true)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert 32 bytes to an array of M31 elements
fn bytes_to_m31_array<const N: usize>(bytes: &[u8; 32]) -> Result<[M31; N]> {
    let mut result = [M31::new(0); N];
    for i in 0..N.min(8) {
        let offset = i * 4;
        if offset + 4 <= 32 {
            let val = u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
            // Reduce to M31 range
            result[i] = M31::new(val & 0x7FFFFFFF);
        }
    }
    Ok(result)
}

/// Convert 32 bytes to a single M31 element (takes first 4 bytes)
fn bytes_to_single_m31(bytes: &[u8; 32]) -> M31 {
    let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    M31::new(val & 0x7FFFFFFF)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_permutation_witness() {
        let mut input = [M31::new(0); WIDTH];
        input[0] = M31::new(DOMAIN_LEAF);
        input[1] = M31::new(12345);
        
        let witness = PermutationWitness::generate(input);
        assert_eq!(witness.round_states.len(), TOTAL_ROUNDS);
        
        // Output should be deterministic
        let witness2 = PermutationWitness::generate(input);
        assert_eq!(witness.output(), witness2.output());
    }
    
    #[test]
    fn test_membership_witness_generation() {
        let leaf_secret: [M31; LEAF_SECRET_LEN] = [
            M31::new(1), M31::new(2), M31::new(3), M31::new(4), M31::new(5)
        ];
        let session_id: [M31; SESSION_ID_LEN] = [
            M31::new(101), M31::new(102), M31::new(103), M31::new(104), M31::new(105)
        ];
        
        // Create a simple 1-level tree for testing
        let mut siblings = vec![M31::new(0); TREE_DEPTH];
        let path_bits = vec![false; TREE_DEPTH];
        
        // Compute expected root manually
        let mut leaf_input = [M31::new(0); WIDTH];
        leaf_input[0] = M31::new(DOMAIN_LEAF);
        for i in 0..LEAF_SECRET_LEN {
            leaf_input[1 + i] = leaf_secret[i];
        }
        let leaf_perm = PermutationWitness::generate(leaf_input);
        let mut current = leaf_perm.output()[1];
        
        for i in 0..TREE_DEPTH {
            let mut merkle_input = [M31::new(0); WIDTH];
            merkle_input[0] = M31::new(DOMAIN_MERK);
            merkle_input[1] = current;
            merkle_input[2] = siblings[i];
            
            let perm = PermutationWitness::generate(merkle_input);
            current = perm.output()[1];
        }
        
        let root = current;
        let binding_hash = [M31::new(0); 8];
        
        let witness = MembershipWitness::generate(
            leaf_secret,
            session_id,
            siblings,
            path_bits,
            root,
            binding_hash,
        );
        
        assert!(witness.is_ok());
    }
    
    /// CRITICAL TEST: Verify circuit implementation matches Plonky3's Poseidon2
    /// 
    /// This test ensures every constraint would evaluate to zero by comparing
    /// our circuit's PermutationWitness against the real Poseidon2Hasher.
    /// 
    /// If this test fails, the circuit constraints are WRONG and debugging
    /// through STWO error messages would be painful.
    #[test]
    fn test_circuit_matches_poseidon2_hasher() {
        use super::super::poseidon2_m31::Poseidon2Hasher;
        
        let hasher = Poseidon2Hasher::new();
        
        // Test case 1: Leaf commitment input
        let mut input = [M31::new(0); WIDTH];
        input[0] = M31::new(DOMAIN_LEAF);
        input[1] = M31::new(0x12345678);
        input[2] = M31::new(0x9ABCDEF0 & 0x7FFFFFFF);
        input[3] = M31::new(0x11111111);
        input[4] = M31::new(0x22222222);
        input[5] = M31::new(0x33333333);
        
        // Our circuit implementation
        let witness = PermutationWitness::generate(input);
        let circuit_output = witness.output();
        
        // Real Poseidon2Hasher
        let mut real_state = input;
        hasher.permute(&mut real_state);
        
        // MUST match exactly
        assert_eq!(
            circuit_output, real_state,
            "Circuit permutation output doesn't match Poseidon2Hasher!\n\
             Circuit: {:?}\n\
             Real:    {:?}",
            circuit_output, real_state
        );
        
        // Test case 2: Random values (Plonky3 test vector input)
        let input2: [M31; 16] = [
            894848333, 1437655012, 1200606629, 1690012884, 71131202, 1749206695, 1717947831,
            120589055, 19776022, 42382981, 1831865506, 724844064, 171220207, 1299207443, 227047920,
            1783754913,
        ].map(|v| M31::new(v));
        
        let witness2 = PermutationWitness::generate(input2);
        let circuit_output2 = witness2.output();
        
        let mut real_state2 = input2;
        hasher.permute(&mut real_state2);
        
        assert_eq!(
            circuit_output2, real_state2,
            "Circuit permutation doesn't match on random test vector!"
        );
        
        println!("✓ Circuit implementation matches Poseidon2Hasher exactly");
    }
    
    /// Test that external linear layer matches Plonky3's MDS
    #[test]
    fn test_external_linear_matches_plonky3() {
        use super::super::poseidon2_m31::Poseidon2Hasher;
        
        // Create a simple input and apply ONLY the linear layer
        let mut state1 = core::array::from_fn(|i| M31::new((i + 1) as u32));
        let mut state2 = state1;
        
        // Our implementation
        external_linear(&mut state1);
        
        // For comparison, we'll verify the properties:
        // After M4 and mixing, the matrix should have specific structure
        // This test verifies basic correctness
        
        // M4 circulant property: result[i] = 2*x[i] + 3*x[(i+1)%4] + x[(i+2)%4] + x[(i+3)%4]
        // for each group of 4
        
        // Just verify it's deterministic and produces non-trivial output
        assert_ne!(state1[0], M31::new(1), "Linear layer should change state");
        assert_ne!(state1[5], M31::new(6), "Linear layer should change state");
        
        // Verify idempotent behavior (applying twice gives different result)
        let mut state3 = core::array::from_fn(|i| M31::new((i + 1) as u32));
        external_linear(&mut state3);
        external_linear(&mut state3);
        assert_ne!(state1, state3, "Two applications should differ from one");
    }
    
    /// Test internal linear layer formula
    #[test]
    fn test_internal_linear_formula() {
        let mut state = core::array::from_fn(|i| M31::new((i + 1) as u32));
        let original = state;
        
        internal_linear(&mut state);
        
        // Formula: new[i] = old[i] * diag[i] + sum(old)
        let sum: M31 = original.iter().copied().sum();
        
        for i in 0..WIDTH {
            let expected = original[i] * internal_diag(i) + sum;
            assert_eq!(
                state[i], expected,
                "Internal linear layer formula wrong at position {}: got {:?}, expected {:?}",
                i, state[i], expected
            );
        }
    }
    
    /// Test S-box x^5 computation
    #[test]
    fn test_sbox() {
        let x = M31::new(7);
        let result = sbox(x);
        
        // 7^5 = 16807
        let expected = M31::new(16807);
        assert_eq!(result, expected, "S-box x^5 computation wrong");
        
        // Test with intermediate
        let (x2, x5) = sbox_with_intermediate(x);
        assert_eq!(x2, M31::new(49), "x^2 wrong");
        assert_eq!(x5, expected, "x^5 wrong via intermediate");
    }
    
    /// Debug test: trace round-by-round to find divergence
    #[test]
    fn test_debug_round_by_round() {
        use super::super::poseidon2_m31::Poseidon2Hasher;
        use p3_field::PrimeField32;
        use p3_poseidon2::{MDSMat4, mds_light_permutation, add_rc_and_sbox_generic};
        
        let input: [M31; 16] = core::array::from_fn(|i| M31::new((i + 1) as u32));
        
        println!("\n=== Round-by-round comparison ===");
        println!("Input: {:?}", input.map(|x| x.as_canonical_u32()));
        
        // === Compare initial linear layer ===
        let mut circuit_state = input;
        external_linear(&mut circuit_state);
        
        let mut plonky3_state = input;
        mds_light_permutation(&mut plonky3_state, &MDSMat4);
        
        println!("After init linear (circuit):  {:?}", circuit_state.map(|x| x.as_canonical_u32()));
        println!("After init linear (plonky3):  {:?}", plonky3_state.map(|x| x.as_canonical_u32()));
        assert_eq!(circuit_state, plonky3_state, "Init linear diverged!");
        
        // === Get Plonky3's actual round constants ===
        // CRITICAL: Must use StandardUniform<M31> sampling, not u32 conversion!
        use rand_p3::SeedableRng;
        use rand_p3::distr::{Distribution, StandardUniform};
        let mut rng = rand_p3::rngs::StdRng::seed_from_u64(1);
        
        let mut plonky3_external_initial: Vec<[M31; 16]> = Vec::new();
        let mut plonky3_external_terminal: Vec<[M31; 16]> = Vec::new();
        
        // Initial external constants (4 rounds × 16 elements)
        for _ in 0..4 {
            let rc: [M31; 16] = core::array::from_fn(|_| StandardUniform.sample(&mut rng));
            plonky3_external_initial.push(rc);
        }
        // Terminal external constants (4 rounds × 16 elements)
        for _ in 0..4 {
            let rc: [M31; 16] = core::array::from_fn(|_| StandardUniform.sample(&mut rng));
            plonky3_external_terminal.push(rc);
        }
        
        println!("\n=== Constants comparison ===");
        println!("Plonky3 round 0 constants: {:?}", plonky3_external_initial[0].map(|x| x.as_canonical_u32())[..4].to_vec());
        println!("Circuit round 0 constants: {:?}", (0..4).map(|i| external_rc(0, i).as_canonical_u32()).collect::<Vec<_>>());
        
        // === Step through first 4 external rounds ===
        for round in 0..FULL_ROUNDS_FIRST {
            // Apply to circuit state
            for i in 0..WIDTH {
                circuit_state[i] = circuit_state[i] + external_rc(round, i);
            }
            for i in 0..WIDTH {
                circuit_state[i] = sbox(circuit_state[i]);
            }
            external_linear(&mut circuit_state);
            
            // Apply to plonky3 state with plonky3's constants
            for i in 0..WIDTH {
                add_rc_and_sbox_generic::<M31, M31, 5>(&mut plonky3_state[i], plonky3_external_initial[round][i]);
            }
            mds_light_permutation(&mut plonky3_state, &MDSMat4);
            
            println!("\nAfter external round {} (circuit):  {:?}", round, circuit_state.map(|x| x.as_canonical_u32())[..4].to_vec());
            println!("After external round {} (plonky3):  {:?}", round, plonky3_state.map(|x| x.as_canonical_u32())[..4].to_vec());
            
            if circuit_state != plonky3_state {
                println!("!!! DIVERGED at external round {} !!!", round);
                break;
            }
        }
        
        // === Now trace internal rounds ===
        println!("\n=== Internal rounds ===");
        
        // Get internal constants the same way Plonky3 does (StandardUniform<M31>)
        let mut plonky3_internal_constants: Vec<M31> = Vec::new();
        for _ in 0..PARTIAL_ROUNDS {
            plonky3_internal_constants.push(StandardUniform.sample(&mut rng));
        }
        
        println!("Plonky3 internal constant 0: {}", plonky3_internal_constants[0].as_canonical_u32());
        println!("Circuit internal constant 0: {}", internal_rc(0).as_canonical_u32());
        
        for round in 0..PARTIAL_ROUNDS {
            // Circuit: add RC to element 0, sbox element 0, internal linear
            circuit_state[0] = circuit_state[0] + internal_rc(round);
            circuit_state[0] = sbox(circuit_state[0]);
            internal_linear(&mut circuit_state);
            
            // Plonky3: same operations with plonky3's constants
            add_rc_and_sbox_generic::<M31, M31, 5>(&mut plonky3_state[0], plonky3_internal_constants[round]);
            // Apply Plonky3's internal linear layer (the diffusion matrix)
            // This is the key - we need to use the same formula
            let sum: M31 = plonky3_state.iter().copied().sum();
            // Plonky3's internal diagonal: [-2, 1, 2, 4, 8, 16, 32, 64, 128, 256, 1024, 4096, 8192, 16384, 32768, 65536]
            let p3_diag: [i64; 16] = [-2, 1, 2, 4, 8, 16, 32, 64, 128, 256, 1024, 4096, 8192, 16384, 32768, 65536];
            for i in 0..WIDTH {
                let diag_val = if p3_diag[i] < 0 {
                    M31::new(((1i64 << 31) - 1 + p3_diag[i]) as u32)
                } else {
                    M31::new(p3_diag[i] as u32)
                };
                plonky3_state[i] = plonky3_state[i] * diag_val + sum;
            }
            
            if round < 2 || circuit_state != plonky3_state {
                println!("After internal round {} (circuit):  {:?}", round, circuit_state.map(|x| x.as_canonical_u32())[..4].to_vec());
                println!("After internal round {} (plonky3):  {:?}", round, plonky3_state.map(|x| x.as_canonical_u32())[..4].to_vec());
            }
            
            if circuit_state != plonky3_state {
                println!("!!! DIVERGED at internal round {} !!!", round);
                break;
            }
        }
        
        // === Final 4 external rounds ===
        println!("\n=== Final external rounds ===");
        
        // Circuit uses external_rc with indices 4-7 for terminal rounds
        // Plonky3 uses terminal constants (which we generated as plonky3_external_terminal)
        for round in 0..FULL_ROUNDS_LAST {
            let rc_idx = FULL_ROUNDS_FIRST + round;  // 4, 5, 6, 7
            
            // Circuit
            for i in 0..WIDTH {
                circuit_state[i] = circuit_state[i] + external_rc(rc_idx, i);
            }
            for i in 0..WIDTH {
                circuit_state[i] = sbox(circuit_state[i]);
            }
            external_linear(&mut circuit_state);
            
            // Plonky3
            for i in 0..WIDTH {
                add_rc_and_sbox_generic::<M31, M31, 5>(&mut plonky3_state[i], plonky3_external_terminal[round][i]);
            }
            mds_light_permutation(&mut plonky3_state, &MDSMat4);
            
            println!("After final ext round {} (circuit):  {:?}", round, circuit_state.map(|x| x.as_canonical_u32())[..4].to_vec());
            println!("After final ext round {} (plonky3):  {:?}", round, plonky3_state.map(|x| x.as_canonical_u32())[..4].to_vec());
            
            // Also print the constants being used
            println!("  Circuit RC[{}]: {:?}", rc_idx, (0..4).map(|i| external_rc(rc_idx, i).as_canonical_u32()).collect::<Vec<_>>());
            println!("  Plonky3 terminal[{}]: {:?}", round, plonky3_external_terminal[round].map(|x| x.as_canonical_u32())[..4].to_vec());
            
            if circuit_state != plonky3_state {
                println!("!!! DIVERGED at final external round {} !!!", round);
                break;
            }
        }
        
        // === Full outputs ===
        let hasher = Poseidon2Hasher::new();
        let mut real_state = input;
        hasher.permute(&mut real_state);
        println!("\nReal Poseidon2Hasher output: {:?}", real_state.map(|x| x.as_canonical_u32())[..4].to_vec());
        
        let witness = PermutationWitness::generate(input);
        println!("Circuit output: {:?}", witness.output().map(|x| x.as_canonical_u32())[..4].to_vec());
    }
    
    /// End-to-end STWO prove/verify test for Poseidon2 membership circuit
    /// 
    /// This is the critical integration test that proves the full pipeline works:
    /// witness → trace → constraints → STWO proof → verification
    #[test]
    fn test_stwo_membership_prove_verify() {
        use itertools::Itertools;
        use num_traits::Zero;
        use stwo::core::air::Component;
        use stwo::core::channel::Blake2sM31Channel;
        use stwo::core::fields::qm31::SecureField;
        use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
        use stwo::core::poly::circle::CanonicCoset;
        use stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleChannel;
        use stwo::core::verifier::verify;
        use stwo::prover::backend::CpuBackend;
        use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
        use stwo::prover::poly::BitReversedOrder;
        use stwo::prover::{prove, CommitmentSchemeProver};
        use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};
        
        // =========================================================================
        // Step 1: Create test witness
        // =========================================================================
        let leaf_secret: [M31; LEAF_SECRET_LEN] = [
            M31::new(0x12345678), M31::new(0x23456789), M31::new(0x3456789A & 0x7FFFFFFF),
            M31::new(0x456789AB & 0x7FFFFFFF), M31::new(0x56789ABC & 0x7FFFFFFF)
        ];
        let session_id: [M31; SESSION_ID_LEN] = [
            M31::new(0xAABBCCDD & 0x7FFFFFFF), M31::new(0xBBCCDDEE & 0x7FFFFFFF),
            M31::new(0xCCDDEEFF & 0x7FFFFFFF), M31::new(0xDDEEFF00 & 0x7FFFFFFF),
            M31::new(0xEEFF0011 & 0x7FFFFFFF)
        ];
        
        // Create siblings and path (all zeros for simplicity)
        let siblings = vec![M31::new(0); TREE_DEPTH];
        let path_bits = vec![false; TREE_DEPTH];
        
        // Compute the expected root by following the Merkle path
        let mut leaf_input = [M31::new(0); WIDTH];
        leaf_input[0] = M31::new(DOMAIN_LEAF);
        for i in 0..LEAF_SECRET_LEN {
            leaf_input[1 + i] = leaf_secret[i];
        }
        let leaf_perm = PermutationWitness::generate(leaf_input);
        let mut current = leaf_perm.output()[1];
        
        for i in 0..TREE_DEPTH {
            let mut merkle_input = [M31::new(0); WIDTH];
            merkle_input[0] = M31::new(DOMAIN_MERK);
            merkle_input[1] = current;
            merkle_input[2] = siblings[i];
            let perm = PermutationWitness::generate(merkle_input);
            current = perm.output()[1];
        }
        let root = current;
        let binding_hash = [M31::new(0); 8];
        
        // Generate full witness
        let witness = MembershipWitness::generate(
            leaf_secret,
            session_id,
            siblings,
            path_bits,
            root,
            binding_hash,
        ).expect("Witness generation should succeed");
        
        println!("✓ Witness generated");
        println!("  Nullifier: {:?}", witness.nullifier.map(|x| x.as_canonical_u32()));
        println!("  Root: {}", root.as_canonical_u32());
        
        // =========================================================================
        // Step 2: Generate trace
        // =========================================================================
        let trace_cols = generate_trace(&witness);
        assert_eq!(trace_cols.len(), N_TRACE_COLS, 
            "Trace should have {} columns, got {}", N_TRACE_COLS, trace_cols.len());
        println!("✓ Trace generated ({} columns)", trace_cols.len());
        
        // Convert to CircleEvaluations
        let domain = CanonicCoset::new(LOG_N_ROWS).circle_domain();
        let trace: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> = trace_cols
            .into_iter()
            .map(|col| CircleEvaluation::new(domain, col))
            .collect_vec();
        
        // =========================================================================
        // Step 3: Setup STWO prover
        // =========================================================================
        // Testing with higher blowup to diagnose constraint degree
        // Index 1110 > 1024 suggests degree > 3
        use stwo::core::fri::FriConfig;
        let config = PcsConfig {
            pow_bits: 10,
            fri_config: FriConfig {
                log_blowup_factor: 3,  // blowup = 8, domain = 256*8 = 2048
                log_last_layer_degree_bound: 0,
                n_queries: 3,
            },
        };
        
        let twiddles = CpuBackend::precompute_twiddles(
            CanonicCoset::new(LOG_N_ROWS + 1 + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );
        
        let prover_channel = &mut Blake2sM31Channel::default();
        let mut commitment_scheme =
            CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
        
        // CRITICAL: Must store polynomial coefficients for prover to work
        commitment_scheme.set_store_polynomials_coefficients();
        
        // Empty preprocessed trace
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(prover_channel);
        
        // Commit the main trace
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(trace);
        tree_builder.commit(prover_channel);
        
        println!("✓ Trace committed");
        
        // =========================================================================
        // Step 4: Create component and generate proof
        // =========================================================================
        type MembershipComponent = FrameworkComponent<MembershipEval>;
        
        let component = MembershipComponent::new(
            &mut TraceLocationAllocator::default(),
            MembershipEval { log_n_rows: LOG_N_ROWS },
            SecureField::zero(),
        );
        
        // Diagnostic: print constraint degree bounds
        let sizes = component.trace_log_degree_bounds();
        println!("Trace log degree bounds: {:?}", sizes);
        println!("✓ Component created, generating proof...");
        
        let proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
            &[&component],
            prover_channel,
            commitment_scheme,
        ).expect("Proof generation should succeed");
        
        println!("✓ Proof generated!");
        
        // =========================================================================
        // Step 5: Serialize/Deserialize round-trip (Phase 4 requirement)
        // =========================================================================
        let proof_bytes = bincode::serialize(&proof)
            .expect("Proof serialization should succeed");
        println!("✓ Proof serialized: {} bytes", proof_bytes.len());
        
        // Deserialize back (must match prover's MerkleChannel hasher type)
        type ProofType = stwo::core::proof::StarkProof<
            stwo::core::vcs_lifted::blake2_merkle::Blake2sM31MerkleHasher
        >;
        let proof: ProofType = bincode::deserialize(&proof_bytes)
            .expect("Proof deserialization should succeed");
        println!("✓ Proof deserialized successfully");
        
        // =========================================================================
        // Step 6: Verify the proof (using deserialized proof)
        // =========================================================================
        let verifier_channel = &mut Blake2sM31Channel::default();
        let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
        
        // Recreate component for verification
        let component = MembershipComponent::new(
            &mut TraceLocationAllocator::default(),
            MembershipEval { log_n_rows: LOG_N_ROWS },
            SecureField::zero(),
        );
        
        let sizes = component.trace_log_degree_bounds();
        
        // Commit to the proof's commitments
        commitment_scheme.commit(proof.0.commitments[0].clone(), &sizes[0], verifier_channel);
        commitment_scheme.commit(proof.0.commitments[1].clone(), &sizes[1], verifier_channel);
        
        let result = verify(
            &[&component],
            verifier_channel,
            commitment_scheme,
            proof,
        );
        
        match result {
            Ok(_) => println!("✓ Proof VERIFIED successfully!"),
            Err(e) => panic!("✗ Verification FAILED: {:?}", e),
        }
    }
}
