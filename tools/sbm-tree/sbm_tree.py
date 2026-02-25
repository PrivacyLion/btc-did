#!/usr/bin/env python3
"""
sbm-tree: Enterprise Merkle tree builder for SignedByMe

Builds a Merkle tree from leaf commitments using Poseidon2-M31.
Outputs root.json (for API publish) and witnesses/*.json (per-user).

⚠️  ALL HASHING USES RUST CLI (poseidon_hash) ⚠️
This ensures consistency with the Rust library and ZK circuits.
The Rust binary uses Plonky3's verified Poseidon2-M31 implementation.

Usage:
    python sbm_tree.py build --client-id acme_corp --purpose allowlist \
        --commitments commitments.csv --output ./output

Commitments CSV format (one hex commitment per line, no header):
    0x1234...
    0x5678...

Environment variables:
    POSEIDON_HASH_BIN - Path to poseidon_hash binary (defaults to ../native/signedby_core/target/release/poseidon_hash)
"""

import argparse
import json
import os
import sys
import subprocess
from pathlib import Path
from typing import List, Tuple
from dataclasses import dataclass
import time

# Constants matching WITNESS_SPEC.md
TREE_DEPTH = 20
HASH_ALG = "poseidon2-m31"
WITNESS_VERSION = 2  # Bumped for Poseidon2 change

# Path to poseidon_hash binary
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_BIN_PATH = SCRIPT_DIR.parents[1] / "native" / "signedby_core" / "target" / "release" / "poseidon_hash"
POSEIDON_HASH_BIN = os.getenv("POSEIDON_HASH_BIN", str(DEFAULT_BIN_PATH))


# =============================================================================
# Poseidon2 Hashing via Rust CLI
# =============================================================================

def _call_poseidon_hash(args: list) -> bytes:
    """
    Call the poseidon_hash Rust CLI binary.
    
    Returns the hex-decoded output (4 bytes for M31).
    Raises RuntimeError on failure.
    """
    cmd = [POSEIDON_HASH_BIN] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            error_msg = result.stderr.strip() or "Unknown error"
            raise RuntimeError(f"poseidon_hash failed: {error_msg}")
        
        output_hex = result.stdout.strip()
        return bytes.fromhex(output_hex)
        
    except FileNotFoundError:
        raise RuntimeError(
            f"poseidon_hash binary not found at {POSEIDON_HASH_BIN}. "
            "Build with: cd native/signedby_core && cargo build --release"
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("poseidon_hash timed out")


def merkle_hash_pair(left: bytes, right: bytes) -> bytes:
    """
    Hash two children to create a parent node using Poseidon2.
    
    Calls: poseidon_hash pair <left_hex> <right_hex>
    
    Input: Two values (first 4 bytes of each used as M31)
    Output: 4-byte M31 hash (zero-padded to 32 bytes)
    """
    # Extract first 4 bytes as M31 values
    left_m31 = left[:4].hex() if len(left) >= 4 else left.ljust(4, b'\x00').hex()
    right_m31 = right[:4].hex() if len(right) >= 4 else right.ljust(4, b'\x00').hex()
    
    result = _call_poseidon_hash(["pair", left_m31, right_m31])
    
    # Zero-pad to 32 bytes for compatibility
    return result.ljust(32, b'\x00')


def compute_leaf_commitment(leaf_secret: bytes) -> bytes:
    """
    Compute leaf commitment from secret using Poseidon2.
    
    Calls: poseidon_hash leaf_commit <secret_hex>
    
    Input: 32-byte secret
    Output: 4-byte M31 commitment (zero-padded to 32 bytes)
    """
    if len(leaf_secret) != 32:
        raise ValueError(f"leaf_secret must be 32 bytes, got {len(leaf_secret)}")
    
    secret_hex = leaf_secret.hex()
    result = _call_poseidon_hash(["leaf_commit", secret_hex])
    
    return result.ljust(32, b'\x00')


@dataclass
class PathSibling:
    """A sibling in the Merkle path"""
    hash: bytes  # 32 bytes (M31 in first 4, rest zero)
    is_right: bool  # True if sibling is on the right


@dataclass  
class MerklePath:
    """Merkle path from leaf to root"""
    siblings: List[PathSibling]
    
    def compute_root(self, leaf: bytes) -> bytes:
        """Compute root from leaf using this path"""
        current = leaf
        for sibling in self.siblings:
            if sibling.is_right:
                # sibling on right: H(current, sibling)
                current = merkle_hash_pair(current, sibling.hash)
            else:
                # sibling on left: H(sibling, current)
                current = merkle_hash_pair(sibling.hash, current)
        return current


class MerkleTree:
    """Poseidon2-M31 Merkle tree with zero padding"""
    
    def __init__(self, leaves: List[bytes], depth: int = TREE_DEPTH):
        if not leaves:
            raise ValueError("Cannot build empty tree")
        
        self.depth = depth
        
        # Pad to 2^depth leaves
        target_size = 2 ** depth
        self.original_count = len(leaves)
        
        if len(leaves) > target_size:
            raise ValueError(f"Too many leaves: {len(leaves)} > {target_size}")
        
        # Zero padding (32 zero bytes)
        zero_leaf = bytes(32)
        padded = leaves + [zero_leaf] * (target_size - len(leaves))
        
        # Build layers bottom-up
        print(f"Building tree with {len(padded)} leaves (original: {self.original_count})...")
        self.layers = [padded]
        
        layer_num = 0
        while len(self.layers[-1]) > 1:
            prev = self.layers[-1]
            next_layer = []
            for i in range(0, len(prev), 2):
                h = merkle_hash_pair(prev[i], prev[i + 1])
                next_layer.append(h)
            self.layers.append(next_layer)
            layer_num += 1
            if layer_num % 5 == 0:
                print(f"  Layer {layer_num}: {len(next_layer)} nodes")
        
        self.root = self.layers[-1][0]
    
    def get_path(self, leaf_index: int) -> MerklePath:
        """Get Merkle path for a leaf (0-indexed)"""
        if leaf_index < 0 or leaf_index >= self.original_count:
            raise ValueError(f"Invalid leaf index: {leaf_index}")
        
        siblings = []
        idx = leaf_index
        
        for layer in self.layers[:-1]:  # All layers except root
            # Sibling index
            if idx % 2 == 0:
                sibling_idx = idx + 1
                is_right = True  # sibling is on the right
            else:
                sibling_idx = idx - 1
                is_right = False  # sibling is on the left
            
            siblings.append(PathSibling(
                hash=layer[sibling_idx],
                is_right=is_right
            ))
            
            idx //= 2
        
        return MerklePath(siblings)


def parse_hex_commitment(hex_str: str) -> bytes:
    """Parse a hex commitment string to bytes"""
    hex_str = hex_str.strip()
    if hex_str.startswith('0x') or hex_str.startswith('0X'):
        hex_str = hex_str[2:]
    # Pad to 64 hex chars (32 bytes)
    hex_str = hex_str.zfill(64)
    return bytes.fromhex(hex_str)


def load_commitments(filepath: str) -> List[bytes]:
    """Load hex commitments from CSV (one per line)"""
    commitments = []
    with open(filepath, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                commitment = parse_hex_commitment(line)
                if len(commitment) != 32:
                    print(f"Warning: Line {line_num} commitment is not 32 bytes", file=sys.stderr)
                    continue
                commitments.append(commitment)
            except Exception as e:
                print(f"Warning: Invalid commitment on line {line_num}: {e}", file=sys.stderr)
    return commitments


def check_poseidon_binary():
    """Verify the poseidon_hash binary is available."""
    try:
        result = subprocess.run(
            [POSEIDON_HASH_BIN, "help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # Even --help might return non-zero, just check it ran
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return False


def build_tree(args):
    """Build Merkle tree and output root + witnesses"""
    depth = args.depth
    
    # Check for poseidon_hash binary
    if not check_poseidon_binary():
        print(f"ERROR: poseidon_hash binary not found at {POSEIDON_HASH_BIN}", file=sys.stderr)
        print(f"       Build with: cd native/signedby_core && cargo build --release", file=sys.stderr)
        print(f"       Or set POSEIDON_HASH_BIN environment variable", file=sys.stderr)
        sys.exit(1)
    
    if depth != TREE_DEPTH:
        print(f"WARNING: Using depth={depth} (production requires depth={TREE_DEPTH})", file=sys.stderr)
        print(f"         Roots with depth!={TREE_DEPTH} will be REJECTED by the API", file=sys.stderr)
    
    # Load commitments
    print(f"Loading commitments from {args.commitments}...")
    commitments = load_commitments(args.commitments)
    
    if not commitments:
        print("Error: No valid commitments found", file=sys.stderr)
        sys.exit(1)
    
    print(f"Loaded {len(commitments)} commitments")
    print(f"Hash algorithm: {HASH_ALG} (Plonky3 verified parameters)")
    
    # Build tree
    print(f"Building depth-{depth} Merkle tree...")
    tree = MerkleTree(commitments, depth=depth)
    
    # Display root - only first 4 bytes are meaningful (M31)
    root_m31 = tree.root[:4].hex()
    print(f"Root (M31): 0x{root_m31}")
    print(f"Root (full): 0x{tree.root.hex()}")
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    witnesses_dir = output_dir / "witnesses"
    witnesses_dir.mkdir(exist_ok=True)
    
    # Generate root.json
    now = int(time.time())
    root_id = f"{args.client_id}-{args.purpose}-{now}"
    
    purpose_map = {
        "none": 0,
        "allowlist": 1,
        "issuer_batch": 2,
        "revocation": 3
    }
    purpose_id = purpose_map.get(args.purpose, 0)
    
    root_json = {
        "root_id": root_id,
        "client_id": args.client_id,
        "purpose": args.purpose,
        "purpose_id": purpose_id,
        "root": "0x" + tree.root.hex(),
        "root_m31": "0x" + root_m31,  # Explicit M31 value
        "hash_alg": HASH_ALG,
        "depth": depth,
        "not_before": now,
        "expires_at": now + (365 * 86400),  # 1 year
        "description": f"{args.purpose} tree with {len(commitments)} members",
        "member_count": len(commitments)
    }
    
    root_path = output_dir / "root.json"
    with open(root_path, 'w') as f:
        json.dump(root_json, f, indent=2)
    print(f"Wrote {root_path}")
    
    # Generate witnesses
    print(f"Generating {len(commitments)} witnesses...")
    for i, commitment in enumerate(commitments):
        path = tree.get_path(i)
        
        # Verify path is correct
        computed_root = path.compute_root(commitment)
        if computed_root != tree.root:
            print(f"ERROR: Path verification failed for leaf {i}!", file=sys.stderr)
            print(f"  Expected: 0x{tree.root.hex()}", file=sys.stderr)
            print(f"  Computed: 0x{computed_root.hex()}", file=sys.stderr)
            sys.exit(1)
        
        witness = {
            "version": WITNESS_VERSION,
            "client_id": args.client_id,
            "root_id": root_id,
            "purpose_id": purpose_id,
            "hash_alg": HASH_ALG,
            "depth": depth,
            "not_before": root_json["not_before"],
            "expires_at": root_json["expires_at"],
            # Note: leaf_index intentionally omitted (privacy)
            "siblings": ["0x" + s.hash.hex() for s in path.siblings],
            "siblings_m31": ["0x" + s.hash[:4].hex() for s in path.siblings],  # Explicit M31
            "path_bits": [1 if s.is_right else 0 for s in path.siblings]
        }
        
        witness_path = witnesses_dir / f"witness_{i:06d}.json"
        with open(witness_path, 'w') as f:
            json.dump(witness, f, indent=2)
        
        if (i + 1) % 100 == 0:
            print(f"  Generated {i + 1}/{len(commitments)} witnesses")
    
    print(f"Wrote {len(commitments)} witnesses to {witnesses_dir}/")
    
    # Summary
    print("\n=== Summary ===")
    print(f"Root ID: {root_id}")
    print(f"Root (M31): 0x{root_m31}")
    print(f"Hash Algorithm: {HASH_ALG}")
    print(f"Members: {len(commitments)}")
    print(f"Depth: {depth}")
    print(f"\nTo publish root:")
    print(f"  curl -X POST https://api.signedby.me/v1/roots \\")
    print(f"    -H 'X-API-Key: YOUR_API_KEY' \\")
    print(f"    -H 'Content-Type: application/json' \\")
    print(f"    -d @{root_path}")


def verify_witness(args):
    """Verify a witness against a root"""
    # Check for poseidon_hash binary
    if not check_poseidon_binary():
        print(f"ERROR: poseidon_hash binary not found at {POSEIDON_HASH_BIN}", file=sys.stderr)
        sys.exit(1)
    
    with open(args.witness, 'r') as f:
        witness = json.load(f)
    
    commitment = parse_hex_commitment(args.commitment)
    
    # Reconstruct path
    siblings = []
    for i, (sib_hex, is_right) in enumerate(zip(witness["siblings"], witness["path_bits"])):
        sib_bytes = parse_hex_commitment(sib_hex)
        siblings.append(PathSibling(
            hash=sib_bytes,
            is_right=(is_right == 1)
        ))
    path = MerklePath(siblings)
    
    # Compute root
    computed_root = path.compute_root(commitment)
    
    print(f"Commitment: {args.commitment}")
    print(f"Hash Algorithm: {witness.get('hash_alg', HASH_ALG)}")
    print(f"Computed root (M31): 0x{computed_root[:4].hex()}")
    print(f"Computed root (full): 0x{computed_root.hex()}")
    
    if args.root:
        expected = parse_hex_commitment(args.root)
        # Compare only first 4 bytes (M31) for meaningful comparison
        if computed_root[:4] == expected[:4]:
            print("✓ Verification PASSED (M31 match)")
        else:
            print(f"✗ Verification FAILED")
            print(f"  Expected (M31): 0x{expected[:4].hex()}")
            print(f"  Computed (M31): 0x{computed_root[:4].hex()}")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="sbm-tree: Enterprise Merkle tree builder for SignedByMe (Poseidon2-M31)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Build command
    build_parser = subparsers.add_parser("build", help="Build Merkle tree from commitments")
    build_parser.add_argument("--client-id", required=True, help="Enterprise client ID")
    build_parser.add_argument("--purpose", required=True, 
                             choices=["none", "allowlist", "issuer_batch", "revocation"],
                             help="Tree purpose")
    build_parser.add_argument("--commitments", required=True, help="Path to commitments CSV")
    build_parser.add_argument("--output", required=True, help="Output directory")
    build_parser.add_argument("--depth", type=int, default=TREE_DEPTH,
                             help=f"Tree depth (default: {TREE_DEPTH}, use smaller for testing)")
    
    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a witness")
    verify_parser.add_argument("--witness", required=True, help="Path to witness JSON")
    verify_parser.add_argument("--commitment", required=True, help="Leaf commitment (hex)")
    verify_parser.add_argument("--root", help="Expected root (hex, optional)")
    
    args = parser.parse_args()
    
    if args.command == "build":
        build_tree(args)
    elif args.command == "verify":
        verify_witness(args)


if __name__ == "__main__":
    main()
