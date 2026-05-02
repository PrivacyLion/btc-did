// nostr/mod.rs - NOSTR Mobile Client for SignedByMe (Phase 9)
//
// Key architectural decisions (binding, from Bible):
// - DECISION 1: Global npub. nsec = Poseidon2(leaf_secret[0..2]), NO client_id
// - Server has ZERO NOSTR involvement. Phone publishes all events.
// - NOSTR is invisible to user. No npub displayed, no relay settings.

pub mod client;
pub mod events;
pub mod nsec_derivation;

// NOTE: JNI module removed per Bible Section 16 (Mar 30, 2026).
// Mobile Android bridge superseded. This is an SDK, not an Android app.

pub use client::NostrClient;
pub use events::{ProofEvent, PaymentReceiptEvent, LoginCompleteEvent};
pub use nsec_derivation::derive_nsec_from_leaf_secret;

// Event kinds for SignedByMe audit trail
pub const KIND_PROOF_EVENT: u16 = 28101;
pub const KIND_PAYMENT_RECEIPT: u16 = 28102;
pub const KIND_LOGIN_COMPLETE: u16 = 28103;

// Default relay list (SignedByMe audit relay is always first)
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.signedbyme.com",  // SignedByMe audit relay (primary)
    "wss://relay.damus.io",           // Public relay (redundancy)
    "wss://nos.lol",                  // Public relay (redundancy)
];
