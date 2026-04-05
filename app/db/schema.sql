-- SignedByMe SQLite Schema
-- Phase 26: Simplified architecture with NOSTR-native authorization

-- Version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO schema_version (version) VALUES (26);

-- ============================================================================
-- MERKLE LEAVES
-- Phase 26: Stores leaf commitments (enrollment_id eliminated)
-- Authorization is via kind 28200 NOSTR event signature
-- ============================================================================
CREATE TABLE IF NOT EXISTS merkle_leaves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tree_id TEXT NOT NULL,
    leaf_index INTEGER NOT NULL,
    leaf_commitment TEXT NOT NULL,          -- 32-byte hex
    
    -- Authorization event (kind 28200)
    authorization_event_id TEXT NOT NULL,   -- NOSTR event ID
    authorization_pubkey TEXT NOT NULL,     -- Enterprise pubkey (hex)
    
    -- Timestamps
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    
    UNIQUE(tree_id, leaf_index),
    UNIQUE(tree_id, leaf_commitment)
);
CREATE INDEX IF NOT EXISTS idx_leaves_tree ON merkle_leaves(tree_id);
CREATE INDEX IF NOT EXISTS idx_leaves_commitment ON merkle_leaves(leaf_commitment);
CREATE INDEX IF NOT EXISTS idx_leaves_auth_event ON merkle_leaves(authorization_event_id);

-- ============================================================================
-- MERKLE ROOTS
-- Published roots per tree (last 30 valid)
-- ============================================================================
CREATE TABLE IF NOT EXISTS merkle_roots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tree_id TEXT NOT NULL,
    root_hash TEXT NOT NULL,
    leaf_index INTEGER NOT NULL,            -- Index when this root was computed
    
    -- Timestamps
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_roots_tree ON merkle_roots(tree_id);
CREATE INDEX IF NOT EXISTS idx_roots_hash ON merkle_roots(root_hash);
CREATE INDEX IF NOT EXISTS idx_roots_created ON merkle_roots(tree_id, created_at DESC);

-- ============================================================================
-- LOGIN VERIFICATIONS
-- Log of successful logins (receipts for audit)
-- ============================================================================
CREATE TABLE IF NOT EXISTS login_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    npub TEXT NOT NULL,                     -- bech32 npub
    client_id TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    
    -- NOSTR event (Phase 26)
    login_event_id TEXT,                    -- NOSTR event ID containing proof
    
    -- Payment verification
    payment_hash_user TEXT,
    payment_hash_operator TEXT,
    
    -- Timestamps
    verified_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verifications_client ON login_verifications(client_id);
CREATE INDEX IF NOT EXISTS idx_verifications_npub ON login_verifications(npub);
CREATE INDEX IF NOT EXISTS idx_verifications_time ON login_verifications(verified_at);
CREATE INDEX IF NOT EXISTS idx_verifications_event ON login_verifications(login_event_id);

-- ============================================================================
-- MERKLE TREES (state tracking)
-- Stores incremental tree state for O(log n) updates
-- ============================================================================
CREATE TABLE IF NOT EXISTS merkle_trees (
    id TEXT PRIMARY KEY,                    -- tree_id (e.g., "acme-allowlist")
    client_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    
    -- Tree state
    depth INTEGER NOT NULL DEFAULT 20,
    next_leaf_index INTEGER NOT NULL DEFAULT 0,
    
    -- Current state: JSON array of hashes at each level (right-most path)
    state_json TEXT NOT NULL DEFAULT '[]',
    
    -- Timestamps
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_trees_client ON merkle_trees(client_id);

-- ============================================================================
-- MERKLE WITNESSES
-- Per-leaf witnesses for proving membership
-- ============================================================================
CREATE TABLE IF NOT EXISTS merkle_witnesses (
    leaf_id INTEGER PRIMARY KEY,
    tree_id TEXT NOT NULL,
    
    -- Witness data
    siblings_json TEXT NOT NULL,            -- JSON array of sibling hashes
    path_bits_json TEXT NOT NULL,           -- JSON array of path bits
    leaf_index INTEGER NOT NULL,
    root_hash TEXT NOT NULL,                -- Root at time of insertion
    
    FOREIGN KEY (leaf_id) REFERENCES merkle_leaves(id)
);
CREATE INDEX IF NOT EXISTS idx_witnesses_tree ON merkle_witnesses(tree_id);

-- ============================================================================
-- AUDIT LOG (optional - for debugging)
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    client_id TEXT,
    session_id TEXT,
    details_json TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

-- ============================================================================
-- USED EVENT IDS
-- Replay protection for enterprise-generated kind 28200 events
-- ============================================================================
CREATE TABLE IF NOT EXISTS used_event_ids (
    event_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    used_at INTEGER DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_used_events_client ON used_event_ids(client_id);

-- ============================================================================
-- PAYOUT LOG
-- Append-only log of monthly revenue share payouts (Section 7.2)
-- ============================================================================
CREATE TABLE IF NOT EXISTS payout_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    month TEXT NOT NULL,                    -- YYYY-MM format
    recipient_type TEXT NOT NULL,           -- 'enterprise' or 'agent'
    recipient_id TEXT NOT NULL,             -- client_id (enterprise) or npub (agent)
    amount_sats INTEGER NOT NULL,
    lightning_address TEXT,                 -- lud16 used for payment
    status TEXT NOT NULL,                   -- 'paid', 'failed', 'carried_forward'
    failure_count INTEGER DEFAULT 0,        -- Consecutive failures
    paid_at INTEGER,                        -- Unix timestamp when paid (NULL if not paid)
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_payout_month ON payout_log(month);
CREATE INDEX IF NOT EXISTS idx_payout_recipient ON payout_log(recipient_id);
CREATE INDEX IF NOT EXISTS idx_payout_status ON payout_log(status);

-- ============================================================================
-- MIGRATION: Phase 26
-- If upgrading from Phase 10, run these to migrate data:
-- 
-- 1. Create new tables (merkle_leaves from enrollments)
-- 2. Drop deprecated tables (enrollments, enrollment_sessions, enrollment_tokens)
--
-- Note: Fresh installs don't need migration.
-- ============================================================================
