// sdk/mod.rs - SignedByMe Agent SDK Core (Phase 9A)
//
// Per Bible Section 9A.1:
// - DID and identity chain in TEE/encrypted storage
// - Secure storage holds ONLY: DID private key and leaf_secret
//
// Per Bible Section 9A.2:
// - Groth16 proof generation wired into SDK
// - Uses ark-circom with CircomReduction (NOT LibsnarkReduction)
// - Proof generation happens entirely on agent's machine
//
// Per Bible Section 9A.3:
// - Agent NOSTR client with NIP-42 authentication
// - Event publishing (agent signs with agent nsec)
// - Event polling for enrollment/delegation/revocation
//
// Per Bible Section 15 Decision 941 (Apr 14, 2026):
// - Agent never holds human nsec
// - Human signs kind 28250 and kind 28251 with their own NOSTR client

pub mod identity;
pub mod storage;
pub mod prover;
pub mod nostr_client;
pub mod enrollment;
pub mod delegation;
pub mod wallet;

pub use identity::AgentIdentity;
pub use storage::{SecureStorage, StorageError};
pub use prover::{MembershipProver, ProverConfig, ProofResult, MerkleWitness};
pub use nostr_client::NostrClient;
pub use enrollment::{EnrollmentBootstrap, EnrollmentResult};
pub use delegation::{DelegationValidator, DelegationValidation};
pub use wallet::NwcWallet;
