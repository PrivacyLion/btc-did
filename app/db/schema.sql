-- SignedByMe SQLite Schema
-- Phase 8: Stateless architecture (no sessions, no DIDs on server)

-- Version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO schema_version (version) VALUES (2);

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
-- LOGIN VERIFICATIONS
-- Phase 8: Log of successful Groth16 verifications (receipts only, no preimages)
-- ============================================================================
CREATE TABLE IF NOT EXISTS login_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    npub TEXT NOT NULL,
    client_id TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    payment_hash_user TEXT NOT NULL,
    payment_hash_operator TEXT NOT NULL,
    verified_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verifications_client ON login_verifications(client_id);
CREATE INDEX IF NOT EXISTS idx_verifications_npub ON login_verifications(npub);
CREATE INDEX IF NOT EXISTS idx_verifications_time ON login_verifications(verified_at);

-- ============================================================================
-- AUDIT LOG (optional - for debugging)
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    client_id TEXT,
    details_json TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
