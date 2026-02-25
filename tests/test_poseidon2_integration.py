#!/usr/bin/env python3
"""
Integration tests for Poseidon2-M31 hashing consistency.

Verifies that ALL four components produce identical results:
1. Rust library (poseidon2_m31.rs via merkle_hash.rs)
2. Rust CLI (poseidon_hash binary)
3. Python API (membership.py)
4. Python tree builder (sbm_tree.py)

This test requires the poseidon_hash binary to be built:
    cd native/signedby_core && cargo build --release

Run with:
    pytest tests/test_poseidon2_integration.py -v
    
Or standalone:
    python tests/test_poseidon2_integration.py
"""

import os
import sys
import subprocess
import tempfile
import json
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "app"))
sys.path.insert(0, str(PROJECT_ROOT / "tools" / "sbm-tree"))

# Poseidon hash binary path
POSEIDON_HASH_BIN = os.getenv(
    "POSEIDON_HASH_BIN",
    str(PROJECT_ROOT / "native" / "signedby_core" / "target" / "release" / "poseidon_hash")
)


def check_binary_available():
    """Check if poseidon_hash binary is available."""
    try:
        result = subprocess.run(
            [POSEIDON_HASH_BIN, "help"],
            capture_output=True,
            timeout=5,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def call_cli(args: list) -> bytes:
    """Call poseidon_hash CLI and return output bytes."""
    result = subprocess.run(
        [POSEIDON_HASH_BIN] + args,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        raise RuntimeError(f"CLI failed: {result.stderr}")
    return bytes.fromhex(result.stdout.strip())


class TestPoseidon2Integration:
    """Integration tests for Poseidon2 consistency across all components."""
    
    @classmethod
    def setup_class(cls):
        """Check prerequisites."""
        if not check_binary_available():
            import pytest
            pytest.skip(
                f"poseidon_hash binary not found at {POSEIDON_HASH_BIN}. "
                "Build with: cd native/signedby_core && cargo build --release"
            )
    
    def test_cli_pair_deterministic(self):
        """Test that CLI hash_pair is deterministic."""
        left = "12345678"  # 4 bytes hex
        right = "abcdef01"
        
        result1 = call_cli(["pair", left, right])
        result2 = call_cli(["pair", left, right])
        
        assert result1 == result2, "CLI pair should be deterministic"
        assert len(result1) == 4, "M31 output should be 4 bytes"
    
    def test_cli_pair_order_matters(self):
        """Test that hash(a,b) != hash(b,a)."""
        a = "12345678"
        b = "abcdef01"
        
        result_ab = call_cli(["pair", a, b])
        result_ba = call_cli(["pair", b, a])
        
        assert result_ab != result_ba, "Hash should depend on order"
    
    def test_cli_leaf_commit(self):
        """Test CLI leaf_commit produces consistent output."""
        secret = "00" * 32  # 32 zero bytes
        
        result1 = call_cli(["leaf_commit", secret])
        result2 = call_cli(["leaf_commit", secret])
        
        assert result1 == result2, "leaf_commit should be deterministic"
        assert len(result1) == 4, "M31 output should be 4 bytes"
    
    def test_cli_nullifier(self):
        """Test CLI nullifier with different sessions."""
        secret = "42" * 32
        session1 = "01" * 32
        session2 = "02" * 32
        
        null1 = call_cli(["nullifier", secret, session1])
        null2 = call_cli(["nullifier", secret, session2])
        null1_again = call_cli(["nullifier", secret, session1])
        
        # Nullifier is now 16 bytes (4 M31 elements)
        assert len(null1) == 16, "Nullifier should be 16 bytes"
        assert null1 != null2, "Different sessions should give different nullifiers"
        assert null1 == null1_again, "Same session should give same nullifier"
    
    def test_cli_merkle_root(self):
        """Test CLI merkle_root produces expected root."""
        # 4 leaves (M31 values as 4-byte hex)
        leaves = ["00000001", "00000002", "00000003", "00000004"]
        
        root = call_cli(["merkle_root"] + leaves)
        assert len(root) == 4, "Root should be 4 bytes (M31)"
        
        # Verify against manual tree construction
        h01 = call_cli(["pair", leaves[0], leaves[1]])
        h23 = call_cli(["pair", leaves[2], leaves[3]])
        expected_root = call_cli(["pair", h01.hex(), h23.hex()])
        
        assert root == expected_root, "merkle_root should match manual construction"
    
    def test_python_api_matches_cli(self):
        """Test Python API produces same results as CLI."""
        # Import Python module
        from routes.membership import (
            merkle_hash_pair,
            compute_leaf_commitment,
            compute_nullifier,
        )
        
        # Test hash_pair
        left = bytes.fromhex("12345678" + "00" * 28)  # Padded to 32 bytes
        right = bytes.fromhex("abcdef01" + "00" * 28)
        
        py_result = merkle_hash_pair(left, right)
        cli_result = call_cli(["pair", "12345678", "abcdef01"])
        
        # Python pads to 32 bytes, CLI returns 4 bytes
        assert py_result[:4] == cli_result, "Python API should match CLI for hash_pair"
        
        # Test leaf_commit
        secret = bytes(32)  # 32 zero bytes
        py_commit = compute_leaf_commitment(secret)
        cli_commit = call_cli(["leaf_commit", "00" * 32])
        
        assert py_commit[:4] == cli_commit, "Python API should match CLI for leaf_commit"
        
        # Test nullifier (now 16 bytes)
        secret = bytes.fromhex("42" * 32)
        session = bytes.fromhex("01" * 32)
        
        py_null = compute_nullifier(secret, session)
        cli_null = call_cli(["nullifier", "42" * 32, "01" * 32])
        
        assert len(cli_null) == 16, "CLI nullifier should be 16 bytes"
        assert py_null[:16] == cli_null, "Python API should match CLI for nullifier"
    
    def test_sbm_tree_matches_cli(self):
        """Test sbm_tree.py produces same results as CLI."""
        from sbm_tree import merkle_hash_pair as tree_hash_pair
        
        # Test hash_pair
        left = bytes.fromhex("12345678" + "00" * 28)
        right = bytes.fromhex("abcdef01" + "00" * 28)
        
        tree_result = tree_hash_pair(left, right)
        cli_result = call_cli(["pair", "12345678", "abcdef01"])
        
        assert tree_result[:4] == cli_result, "sbm_tree should match CLI for hash_pair"
    
    def test_full_tree_consistency(self):
        """Test that Python API and sbm_tree produce identical trees."""
        from routes.membership import build_merkle_tree_with_witnesses
        from sbm_tree import MerkleTree
        
        # Create test commitments (already hashed, simulating leaf commitments)
        commitments = [
            bytes.fromhex("00000001" + "00" * 28),
            bytes.fromhex("00000002" + "00" * 28),
            bytes.fromhex("00000003" + "00" * 28),
            bytes.fromhex("00000004" + "00" * 28),
        ]
        
        # Build with Python API
        api_root, api_witnesses = build_merkle_tree_with_witnesses(commitments)
        
        # Build with sbm_tree (using smaller depth for test)
        tree = MerkleTree(commitments, depth=2)
        
        # Compare roots (first 4 bytes are M31)
        assert api_root[:4] == tree.root[:4], "API and sbm_tree should produce same root"
        
        # Verify witnesses work
        for i, commitment in enumerate(commitments):
            path = tree.get_path(i)
            computed = path.compute_root(commitment)
            assert computed[:4] == tree.root[:4], f"Witness {i} should verify"
    
    def test_cli_self_consistency(self):
        """Test CLI merkle_root matches manual tree construction."""
        # Test with power-of-2 leaves
        leaves = ["00000001", "00000002", "00000003", "00000004"]
        
        # Build manually
        h01 = call_cli(["pair", leaves[0], leaves[1]])
        h23 = call_cli(["pair", leaves[2], leaves[3]])
        manual_root = call_cli(["pair", h01.hex(), h23.hex()])
        
        # Build with merkle_root command
        cli_root = call_cli(["merkle_root"] + leaves)
        
        assert manual_root == cli_root, "CLI merkle_root should match manual construction"


def run_standalone_tests():
    """Run tests without pytest."""
    print("=" * 60)
    print("Poseidon2-M31 Integration Tests")
    print("=" * 60)
    
    if not check_binary_available():
        print(f"\n❌ ERROR: poseidon_hash binary not found at {POSEIDON_HASH_BIN}")
        print("Build with: cd native/signedby_core && cargo build --release")
        sys.exit(1)
    
    print(f"✓ Found poseidon_hash at {POSEIDON_HASH_BIN}")
    
    tests = TestPoseidon2Integration()
    tests.setup_class()
    
    test_methods = [m for m in dir(tests) if m.startswith("test_")]
    
    passed = 0
    failed = 0
    
    for method_name in test_methods:
        try:
            print(f"\n{method_name}... ", end="", flush=True)
            method = getattr(tests, method_name)
            method()
            print("✓ PASSED")
            passed += 1
        except AssertionError as e:
            print(f"✗ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ ERROR: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_standalone_tests()
    sys.exit(0 if success else 1)
