"""
SignedByMe Admin API - Read-Only Dashboard Endpoints (Phase 8)

All endpoints require Basic Auth with SBM_ADMIN_PASSWORD.
No write operations - config changes via clients.json + redeploy.

Phase 8: Stateless architecture - no sessions, no Strike.
All data from SQLite (roots, enrollments, login_verifications).
"""

import os
import json
import base64
import logging
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel

from ..db import (
    get_connection,
    count_verifications,
    get_verifications,
    list_roots,
    list_enrollments,
)

logger = logging.getLogger("admin")

router = APIRouter(prefix="/v1/admin", tags=["admin"])


def verify_admin_auth(authorization: Optional[str]) -> bool:
    """
    Verify Basic Auth credentials.
    
    Expected format: "Basic base64(admin:password)"
    Password from SBM_ADMIN_PASSWORD env var.
    """
    if not authorization:
        return False
    
    expected_password = os.environ.get("SBM_ADMIN_PASSWORD")
    if not expected_password:
        logger.warning("SBM_ADMIN_PASSWORD not set, admin endpoints disabled")
        return False
    
    try:
        if not authorization.startswith("Basic "):
            return False
        
        encoded = authorization[6:]
        decoded = base64.b64decode(encoded).decode("utf-8")
        
        if ":" not in decoded:
            return False
        
        username, password = decoded.split(":", 1)
        return username == "admin" and password == expected_password
        
    except Exception as e:
        logger.warning(f"Admin auth error: {e}")
        return False


def require_admin(authorization: Optional[str] = Header(None)):
    """Dependency to require admin auth."""
    if not verify_admin_auth(authorization):
        raise HTTPException(
            status_code=401,
            detail="Admin authentication required",
            headers={"WWW-Authenticate": "Basic realm=\"SignedByMe Admin\""}
        )


# --- Response Models ---

class AdminStatusResponse(BaseModel):
    """Service status overview."""
    ok: bool
    timestamp: str
    valid_root_count: int
    total_login_verifications: int
    merkle_tree_size: int


class LoginEvent(BaseModel):
    """A login verification event for the dashboard."""
    id: int
    npub: str
    client_id: str
    merkle_root: str
    payment_hash_user: str
    payment_hash_operator: str
    verified_at: int
    timestamp: str


class LoginEventsResponse(BaseModel):
    """List of login events."""
    events: list[LoginEvent]
    total: int


class VerificationRecord(BaseModel):
    """A verification record (renamed from PayoutAttempt)."""
    id: int
    npub: str
    client_id: str
    payment_hash_user: str
    payment_hash_operator: str
    verified_at: int


class VerificationsResponse(BaseModel):
    """List of verification records."""
    verifications: list[VerificationRecord]
    total: int


class ClientConfigView(BaseModel):
    """Read-only view of client config (no secrets)."""
    client_id: str
    name: str
    reward_enabled: bool
    reward_amount_sats: int
    reward_provider: Optional[str] = None
    require_membership: bool
    redirect_uris: list[str]


class ClientsResponse(BaseModel):
    """List of configured clients."""
    clients: list[ClientConfigView]


# --- Endpoints ---

@router.get("/status", response_model=AdminStatusResponse)
async def get_admin_status(authorization: Optional[str] = Header(None)):
    """
    Get service status overview.
    
    Returns counts from SQLite: roots, verifications, enrollments.
    """
    require_admin(authorization)
    
    conn = get_connection()
    
    # Count valid (active) roots
    valid_root_count = conn.execute(
        "SELECT COUNT(*) FROM merkle_roots WHERE active = 1"
    ).fetchone()[0]
    
    # Count login verifications
    total_verifications = count_verifications()
    
    # Count enrollments (merkle tree size = approved enrollments)
    merkle_tree_size = conn.execute(
        "SELECT COUNT(*) FROM enrollments"
    ).fetchone()[0]
    
    return AdminStatusResponse(
        ok=True,
        timestamp=datetime.now(timezone.utc).isoformat(),
        valid_root_count=valid_root_count,
        total_login_verifications=total_verifications,
        merkle_tree_size=merkle_tree_size,
    )


@router.get("/events", response_model=LoginEventsResponse)
async def get_login_events(
    authorization: Optional[str] = Header(None),
    limit: int = Query(100, ge=1, le=1000),
    client_id: Optional[str] = Query(None)
):
    """
    Get recent login verification events.
    
    Optionally filter by client_id.
    """
    require_admin(authorization)
    
    verifications = get_verifications(client_id=client_id, limit=limit)
    
    events = []
    for v in verifications:
        events.append(LoginEvent(
            id=v["id"],
            npub=v["npub"],
            client_id=v["client_id"],
            merkle_root=v["merkle_root"],
            payment_hash_user=v["payment_hash_user"],
            payment_hash_operator=v["payment_hash_operator"],
            verified_at=v["verified_at"],
            timestamp=datetime.fromtimestamp(v["verified_at"], timezone.utc).isoformat(),
        ))
    
    return LoginEventsResponse(
        events=events,
        total=len(events)
    )


@router.get("/verifications", response_model=VerificationsResponse)
async def get_verification_records(
    authorization: Optional[str] = Header(None),
    limit: int = Query(100, ge=1, le=1000),
    client_id: Optional[str] = Query(None)
):
    """
    Get verification records (payment hash receipts).
    
    Renamed from /payments - server verifies preimages but doesn't process payments.
    Optionally filter by client_id.
    """
    require_admin(authorization)
    
    verifications = get_verifications(client_id=client_id, limit=limit)
    
    records = []
    for v in verifications:
        records.append(VerificationRecord(
            id=v["id"],
            npub=v["npub"],
            client_id=v["client_id"],
            payment_hash_user=v["payment_hash_user"],
            payment_hash_operator=v["payment_hash_operator"],
            verified_at=v["verified_at"],
        ))
    
    return VerificationsResponse(
        verifications=records,
        total=len(records)
    )


@router.get("/clients", response_model=ClientsResponse)
async def get_clients(authorization: Optional[str] = Header(None)):
    """
    Get configured clients (read-only, no secrets).
    
    Shows reward policy and membership requirements.
    """
    require_admin(authorization)
    
    # Load clients config
    clients_path = os.environ.get("CLIENTS_JSON", "/opt/sbm-api/clients.json")
    if not os.path.exists(clients_path):
        clients_path = os.path.join(os.path.dirname(__file__), "../../clients.json")
    
    try:
        with open(clients_path) as f:
            clients_data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load clients.json: {e}")
        raise HTTPException(500, "Failed to load client configuration")
    
    clients = []
    for client_id, config in clients_data.items():
        reward_policy = config.get("reward_policy", {})
        clients.append(ClientConfigView(
            client_id=client_id,
            name=config.get("name", client_id),
            reward_enabled=reward_policy.get("enabled", False),
            reward_amount_sats=reward_policy.get("amount_sats", 0),
            reward_provider=reward_policy.get("provider"),
            require_membership=config.get("require_membership", True),  # Default: mandatory
            redirect_uris=config.get("redirect_uris", [])
        ))
    
    return ClientsResponse(clients=clients)
