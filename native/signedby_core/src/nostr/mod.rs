// nostr/mod.rs - NOSTR Mobile Client for SignedByMe (Phase 9)
//
// Key architectural decisions (binding, from Bible):
// - DECISION 1: Global npub. nsec = Poseidon2(leaf_secret[0..2]), NO client_id
// - DECISION 2: Ephemeral NWC keypair per login session. Proof npub NEVER touches Strike.
// - Server has ZERO NOSTR involvement. Phone publishes all events.
// - NOSTR is invisible to user. No npub displayed, no relay settings.

pub mod client;
pub mod events;
pub mod nwc;
pub mod nsec_derivation;
pub mod jni;

pub use client::NostrClient;
pub use events::{ProofEvent, PaymentReceiptEvent, LoginCompleteEvent};
pub use nwc::NwcClient;
pub use nsec_derivation::derive_nsec_from_leaf_secret;

// Event kinds for SignedByMe audit trail
pub const KIND_PROOF_EVENT: u16 = 28101;
pub const KIND_PAYMENT_RECEIPT: u16 = 28102;
pub const KIND_LOGIN_COMPLETE: u16 = 28103;

// Default relay list (SignedByMe audit relay is always first)
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.privacy-lion.com",  // SignedByMe audit relay (primary)
    "wss://relay.damus.io",           // Public relay (redundancy)
    "wss://nos.lol",                  // Public relay (redundancy)
];
