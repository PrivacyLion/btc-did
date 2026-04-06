// sdk/mod.rs - SignedByMe Agent SDK Core (Phase 9A)
//
// Per Bible Section 9A.1:
// - DID and identity chain in TEE/encrypted storage
// - Initial SDK setup includes one-time human nsec import
// - Human grants explicit consent for agent to hold and sign NOSTR events
// - Human nsec stored in same TEE/encrypted storage as DID private key and leaf_secret

pub mod identity;
pub mod storage;

pub use identity::AgentIdentity;
pub use storage::{SecureStorage, StorageError};
