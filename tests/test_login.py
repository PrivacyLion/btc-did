"""
Phase 8: Login Verification Tests

5 required tests:
1. Valid proof + valid preimages → id_token with correct npub as sub
2. Invalid proof → rejection
3. Valid proof + missing operator preimage → rejection (handled by Pydantic)
4. Valid proof + wrong preimage (hash mismatch) → rejection
5. Valid proof + stale merkle_root (not in last 30) → rejection

Run: pytest tests/test_login.py -v
"""
import pytest
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

# Set up test client before importing app
os.environ["SBM_ADMIN_KEY"] = "test-admin-key"

from fastapi.testclient import TestClient


# === Test Fixtures ===

@pytest.fixture
def test_client():
    """Create test client with mocked dependencies."""
    from app.main import app
    return TestClient(app)


@pytest.fixture
def valid_preimage():
    """Generate a valid preimage/hash pair."""
    preimage = "a" * 64  # 32 bytes of 0xaa
    preimage_bytes = bytes.fromhex(preimage)
    payment_hash = hashlib.sha256(preimage_bytes).hexdigest()
    return preimage, payment_hash


@pytest.fixture
def wrong_preimage():
    """Generate a wrong preimage (doesn't match hash)."""
    preimage = "b" * 64  # Wrong preimage
    payment_hash = hashlib.sha256(bytes.fromhex("a" * 64)).hexdigest()  # Hash of different preimage
    return preimage, payment_hash


@pytest.fixture
def mock_clients():
    """Mock clients.json with a test client."""
    return {
        "test-client": {
            "api_key": "test-api-key-12345",
            "name": "Test Enterprise",
        }
    }


@pytest.fixture
def valid_proof():
    """Generate a valid-looking proof structure."""
    return {
        "pi_a": ["1", "2", "1"],
        "pi_b": [["1", "2"], ["3", "4"], ["1", "1"]],
        "pi_c": ["1", "2", "1"],
        "protocol": "groth16",
        "curve": "bn128",
    }


@pytest.fixture
def valid_public_inputs():
    """Generate valid public inputs (9 elements)."""
    # merkle_root + npub_x[4] + npub_y[4]
    return [
        "0x" + "ab" * 32,  # merkle_root
        "1", "2", "3", "4",  # npub_x (4 limbs)
        "5", "6", "7", "8",  # npub_y (4 limbs)
    ]


@pytest.fixture
def mock_verification_result():
    """Mock successful verification result."""
    from app.lib.verifier import VerificationResult
    return VerificationResult(
        valid=True,
        merkle_root="0x" + "ab" * 32,
        npub_bech32="npub1test123456789abcdefghijklmnopqrstuvwxyz",
        npub_compressed="02" + "ab" * 32,
        verify_time_ms=5.0,
    )


# === Helper Functions ===

def make_request_body(
    proof,
    public_inputs,
    user_preimage,
    user_hash,
    operator_preimage,
    operator_hash,
    client_id="test-client",
    nonce=None,
):
    """Build a login verify request body."""
    return {
        "proof": proof,
        "public_inputs": public_inputs,
        "client_id": client_id,
        "nonce": nonce,
        "user_invoice": "lnbc100n1...",
        "user_payment_hash": user_hash,
        "user_preimage": user_preimage,
        "operator_invoice": "lnbc50n1...",
        "operator_payment_hash": operator_hash,
        "operator_preimage": operator_preimage,
    }


# === Tests ===

def test_valid_proof_valid_preimages_returns_id_token(
    test_client,
    valid_proof,
    valid_public_inputs,
    valid_preimage,
    mock_clients,
    mock_verification_result,
):
    """
    TEST 1: Valid proof + valid preimages → id_token with correct npub as sub
    """
    user_preimage, user_hash = valid_preimage
    # Generate separate valid operator preimage
    op_preimage = "c" * 64
    op_hash = hashlib.sha256(bytes.fromhex(op_preimage)).hexdigest()
    
    body = make_request_body(
        valid_proof,
        valid_public_inputs,
        user_preimage,
        user_hash,
        op_preimage,
        op_hash,
    )
    
    with patch("app.routes.login.load_clients", return_value=mock_clients), \
         patch("app.routes.login.verify_groth16_proof", return_value=mock_verification_result), \
         patch("app.routes.login.is_root_valid_for_client", return_value=True), \
         patch("app.routes.login.KEYS_DIR", Path(__file__).parent.parent / "keys"):
        
        response = test_client.post(
            "/v1/login/verify",
            json=body,
            headers={"X-API-Key": "test-api-key-12345"},
        )
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    data = response.json()
    
    assert data["ok"] is True
    assert "id_token" in data
    assert data["sub"] == mock_verification_result.npub_bech32
    assert data["token_type"] == "Bearer"
    assert data["expires_in"] > 0
    
    # Verify the id_token is a valid JWT structure (3 parts)
    parts = data["id_token"].split(".")
    assert len(parts) == 3, "id_token should be a JWT with 3 parts"


def test_invalid_proof_rejected(
    test_client,
    valid_proof,
    valid_public_inputs,
    valid_preimage,
    mock_clients,
):
    """
    TEST 2: Invalid proof → rejection
    """
    from app.lib.verifier import VerificationResult
    
    user_preimage, user_hash = valid_preimage
    op_preimage = "c" * 64
    op_hash = hashlib.sha256(bytes.fromhex(op_preimage)).hexdigest()
    
    body = make_request_body(
        valid_proof,
        valid_public_inputs,
        user_preimage,
        user_hash,
        op_preimage,
        op_hash,
    )
    
    # Mock failed verification
    failed_result = VerificationResult(
        valid=False,
        error="Invalid proof: verification equation not satisfied",
    )
    
    with patch("app.routes.login.load_clients", return_value=mock_clients), \
         patch("app.routes.login.verify_groth16_proof", return_value=failed_result), \
         patch("app.routes.login.is_verifier_ready", return_value=(True, "ready")):
        
        response = test_client.post(
            "/v1/login/verify",
            json=body,
            headers={"X-API-Key": "test-api-key-12345"},
        )
    
    assert response.status_code == 400
    data = response.json()
    assert data["detail"]["ok"] is False
    assert data["detail"]["error_code"] == "invalid_proof"


def test_missing_operator_preimage_rejected(
    test_client,
    valid_proof,
    valid_public_inputs,
    valid_preimage,
    mock_clients,
):
    """
    TEST 3: Valid proof + missing operator preimage → rejection
    
    This is handled by Pydantic validation since operator_preimage is required.
    """
    user_preimage, user_hash = valid_preimage
    
    # Missing operator_preimage field
    body = {
        "proof": valid_proof,
        "public_inputs": valid_public_inputs,
        "client_id": "test-client",
        "user_invoice": "lnbc100n1...",
        "user_payment_hash": user_hash,
        "user_preimage": user_preimage,
        "operator_invoice": "lnbc50n1...",
        "operator_payment_hash": "d" * 64,
        # operator_preimage intentionally omitted
    }
    
    with patch("app.routes.login.load_clients", return_value=mock_clients):
        response = test_client.post(
            "/v1/login/verify",
            json=body,
            headers={"X-API-Key": "test-api-key-12345"},
        )
    
    # Pydantic returns 422 for validation errors
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    # Check that operator_preimage is mentioned in validation error
    error_fields = [e.get("loc", [])[-1] for e in data["detail"]]
    assert "operator_preimage" in error_fields


def test_wrong_preimage_hash_mismatch_rejected(
    test_client,
    valid_proof,
    valid_public_inputs,
    valid_preimage,
    wrong_preimage,
    mock_clients,
    mock_verification_result,
):
    """
    TEST 4: Valid proof + wrong preimage (hash mismatch) → rejection
    """
    user_preimage, user_hash = valid_preimage
    bad_op_preimage, bad_op_hash = wrong_preimage  # Preimage doesn't match hash
    
    body = make_request_body(
        valid_proof,
        valid_public_inputs,
        user_preimage,
        user_hash,
        bad_op_preimage,  # This preimage won't match bad_op_hash
        bad_op_hash,
    )
    
    with patch("app.routes.login.load_clients", return_value=mock_clients), \
         patch("app.routes.login.verify_groth16_proof", return_value=mock_verification_result), \
         patch("app.routes.login.is_root_valid_for_client", return_value=True):
        
        response = test_client.post(
            "/v1/login/verify",
            json=body,
            headers={"X-API-Key": "test-api-key-12345"},
        )
    
    assert response.status_code == 400
    data = response.json()
    assert data["detail"]["ok"] is False
    assert data["detail"]["error_code"] == "operator_preimage_mismatch"


def test_stale_merkle_root_rejected(
    test_client,
    valid_proof,
    valid_public_inputs,
    valid_preimage,
    mock_clients,
    mock_verification_result,
):
    """
    TEST 5: Valid proof + stale merkle_root (not in last 30) → rejection
    """
    user_preimage, user_hash = valid_preimage
    op_preimage = "c" * 64
    op_hash = hashlib.sha256(bytes.fromhex(op_preimage)).hexdigest()
    
    body = make_request_body(
        valid_proof,
        valid_public_inputs,
        user_preimage,
        user_hash,
        op_preimage,
        op_hash,
    )
    
    with patch("app.routes.login.load_clients", return_value=mock_clients), \
         patch("app.routes.login.verify_groth16_proof", return_value=mock_verification_result), \
         patch("app.routes.login.is_root_valid_for_client", return_value=False):  # Root is stale
        
        response = test_client.post(
            "/v1/login/verify",
            json=body,
            headers={"X-API-Key": "test-api-key-12345"},
        )
    
    assert response.status_code == 400
    data = response.json()
    assert data["detail"]["ok"] is False
    assert data["detail"]["error_code"] == "stale_merkle_root"


# === Additional Helper Tests ===

def test_health_endpoint(test_client):
    """Test the health check endpoint."""
    with patch("app.routes.login.is_verifier_ready", return_value=(True, "Verifier ready")):
        response = test_client.get("/v1/login/verify/health")
    
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True


def test_invalid_api_key_rejected(test_client, valid_proof, valid_public_inputs, valid_preimage):
    """Test that invalid API key is rejected."""
    user_preimage, user_hash = valid_preimage
    op_preimage = "c" * 64
    op_hash = hashlib.sha256(bytes.fromhex(op_preimage)).hexdigest()
    
    body = make_request_body(
        valid_proof,
        valid_public_inputs,
        user_preimage,
        user_hash,
        op_preimage,
        op_hash,
    )
    
    response = test_client.post(
        "/v1/login/verify",
        json=body,
        headers={"X-API-Key": "wrong-api-key"},
    )
    
    assert response.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
