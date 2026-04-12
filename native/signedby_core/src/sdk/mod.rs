// sdk/mod.rs - SignedByMe Agent SDK Core (Phase 9A)
//
// Per Bible Section 9A.1:
// - DID and identity chain in TEE/encrypted storage
// - Initial SDK setup includes one-time human nsec import
// - Human grants explicit consent for agent to hold and sign NOSTR events
// - Human nsec stored in same TEE/encrypted storage as DID private key and leaf_secret
//
// Per Bible Section 9A.2:
// - Groth16 proof generation wired into SDK
// - Uses ark-circom with CircomReduction (NOT LibsnarkReduction)
// - Proof generation happens entirely on agent's machine

pub mod identity;
pub mod storage;
pub mod prover;

pub use identity::AgentIdentity;
pub use storage::{SecureStorage, StorageError};
pub use prover::{MembershipProver, ProverConfig, ProofResult, MerkleWitness};
