-- SignedByMe SQLite Schema
-- Phase 13: Persistent storage migration

-- Version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO schema_version (version) VALUES (1);

-- ============================================================================
-- SESSIONS
-- Login sessions created by /v1/login/start, consumed by /v1/login/verify
-- ============================================================================
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    enterprise TEXT,
    amount_sats INTEGER DEFAULT 500,
    expires_at INTEGER NOT NULL,
    
    -- Membership requirements
    required_root_id TEXT,
    required_purpose_id INTEGER DEFAULT 0,
    
    -- Proof verification state
    verified INTEGER DEFAULT 0,
    npub TEXT,
    merkle_root TEXT,
    
    -- Payment state
    paid INTEGER DEFAULT 0,
    paid_at INTEGER,
    preimage_hex TEXT,
    
    -- Timestamps
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_client ON sessions(client_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- ============================================================================
-- OIDC CODES
-- Short-lived auth codes for OIDC token exchange
-- ============================================================================
CREATE TABLE IF NOT EXISTS oidc_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT,
    nonce TEXT,
    code_challenge TEXT,
    code_challenge_method TEXT DEFAULT 'S256',
    
    -- Session binding
    session_id TEXT,
    npub TEXT,
    
    -- Timestamps
    iat INTEGER NOT NULL,
    exp INTEGER NOT NULL,
    used INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_oidc_codes_exp ON oidc_codes(exp);

-- ============================================================================
-- ENROLLMENTS
-- User membership enrollment with status tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS enrollments (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    
    -- Enrollment data
    leaf_commitment TEXT NOT NULL,  -- Never changes
    email_hash TEXT,                -- For verification
    
    -- Status: pending, approved, rejected, in_tree
    status TEXT DEFAULT 'pending',
    
    -- Tree position (set when status = in_tree)
    tree_id TEXT,
    leaf_index INTEGER,
    
    -- Timestamps
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    approved_at INTEGER,
    rejected_at INTEGER,
    tree_built_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_enrollments_client ON enrollments(client_id);
CREATE INDEX IF NOT EXISTS idx_enrollments_status ON enrollments(status);
CREATE INDEX IF NOT EXISTS idx_enrollments_purpose ON enrollments(client_id, purpose);

-- ============================================================================
-- MERKLE ROOTS
-- Published roots per client/purpose
-- ============================================================================
CREATE TABLE IF NOT EXISTS merkle_roots (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    root_hash TEXT NOT NULL,
    
    -- Tree metadata
    leaf_count INTEGER NOT NULL,
    tree_depth INTEGER NOT NULL,
    
    -- Active flag (only one active per client+purpose)
    active INTEGER DEFAULT 1,
    
    -- Timestamps
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    superseded_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_roots_client ON merkle_roots(client_id);
CREATE INDEX IF NOT EXISTS idx_roots_active ON merkle_roots(client_id, purpose, active);

-- ============================================================================
-- MERKLE WITNESSES
-- Per-user witnesses for proving membership
-- ============================================================================
CREATE TABLE IF NOT EXISTS merkle_witnesses (
    enrollment_id TEXT PRIMARY KEY,
    root_id TEXT NOT NULL,
    
    -- Witness data (JSON array of siblings)
    siblings_json TEXT NOT NULL,
    path_bits_json TEXT NOT NULL,
    leaf_index INTEGER NOT NULL,
    
    FOREIGN KEY (enrollment_id) REFERENCES enrollments(id),
    FOREIGN KEY (root_id) REFERENCES merkle_roots(id)
);

-- ============================================================================
-- INCREMENTAL MERKLE TREES
-- Stores tree state for incremental updates (new root on each insert)
-- ============================================================================
CREATE TABLE IF NOT EXISTS merkle_trees (
    id TEXT PRIMARY KEY,  -- tree_id (e.g., "acme-allowlist")
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
-- ROOT HISTORY
-- Track last N roots for validity window (last 30 roots valid)
-- ============================================================================
CREATE TABLE IF NOT EXISTS root_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tree_id TEXT NOT NULL,
    root_hash TEXT NOT NULL,
    leaf_index INTEGER NOT NULL,  -- Index when this root was computed
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    
    FOREIGN KEY (tree_id) REFERENCES merkle_trees(id)
);
CREATE INDEX IF NOT EXISTS idx_root_history_tree ON root_history(tree_id);
CREATE INDEX IF NOT EXISTS idx_root_history_hash ON root_history(root_hash);

-- ============================================================================
-- NULLIFIERS
-- Used nullifiers for replay protection
-- ============================================================================
CREATE TABLE IF NOT EXISTS nullifiers (
    nullifier TEXT PRIMARY KEY,
    session_id TEXT,
    npub TEXT,
    used_at INTEGER DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_nullifiers_session ON nullifiers(session_id);

-- ============================================================================
-- PAYMENT CONFIRMATIONS
-- Preimage confirmations for payment verification
-- ============================================================================
CREATE TABLE IF NOT EXISTS payment_confirmations (
    payment_hash TEXT PRIMARY KEY,
    preimage_hex TEXT NOT NULL,
    session_id TEXT,
    amount_sats INTEGER,
    confirmed_at INTEGER DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_payments_session ON payment_confirmations(session_id);

-- ============================================================================
-- CLIENTS (optional - can stay in JSON for admin edits)
-- ============================================================================
-- Keeping clients.json for now - easier to edit manually
-- Could migrate later if needed

-- ============================================================================
-- ENROLLMENT TOKENS
-- Short-lived tokens for enrollment/witness retrieval
-- ============================================================================
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token TEXT PRIMARY KEY,
    enrollment_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    did TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_tokens_exp ON enrollment_tokens(expires_at);

-- ============================================================================
-- DID CHALLENGES
-- Challenges for DID signature verification
-- ============================================================================
CREATE TABLE IF NOT EXISTS did_challenges (
    challenge TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    did TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_challenges_exp ON did_challenges(expires_at);

-- ============================================================================
-- AUDIT LOG (optional - for debugging)
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    session_id TEXT,
    client_id TEXT,
    details_json TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
