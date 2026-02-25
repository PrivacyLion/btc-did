"""
Canonical session endpoints for SignedByMe login flow.

POST /v1/session  - Create a login session (RP calls this)
GET  /v1/session/{id} - Poll session status (RP polls this)

Session lifecycle:
1. RP creates session with redirect_uri
2. User scans QR, app calls /v1/login/verify
3. RP polls until status=completed or expired

Storage: SQLite (persistent across restarts)
"""

import os
import json
import time
import secrets
import logging
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Header, Query
from pydantic import BaseModel, Field

from ..db import (
    create_session as db_create_session,
    get_session as db_get_session,
    update_session as db_update_session,
    delete_expired_sessions,
    audit_log,
)

logger = logging.getLogger("session")

router = APIRouter(prefix="/v1/session", tags=["session"])

# Session TTL in seconds (5 minutes)
SESSION_TTL = 300


def load_clients() -> dict:
    """Load clients config."""
    clients_path = os.environ.get("CLIENTS_JSON", "/opt/sbm-api/clients.json")
    # Fallback for local dev
    if not os.path.exists(clients_path):
        from pathlib import Path
        clients_path = Path(__file__).resolve().parents[2] / "clients.json"
    
    if os.path.exists(clients_path):
        with open(clients_path) as f:
            return json.load(f)
    return {}


def get_client_by_api_key(api_key: str) -> tuple[Optional[str], Optional[dict]]:
    """Look up client by API key. Returns (client_id, config) or (None, None)."""
    clients = load_clients()
    for client_id, config in clients.items():
        if config.get("api_key") == api_key:
            return client_id, config
    return None, None


def generate_session_id() -> str:
    """Generate a URL-safe session ID."""
    return secrets.token_urlsafe(16)


def generate_nonce() -> str:
    """Generate a 16-byte nonce (32 hex chars)."""
    return secrets.token_hex(16)


# --- Request/Response Models ---

class CreateSessionRequest(BaseModel):
    redirect_uri: str = Field(..., description="OAuth-style redirect URI for callback")


class CreateSessionResponse(BaseModel):
    session_id: str
    nonce: str
    qr_data: str
    deep_link: str
    amount_sats: int
    employer_name: str
    expires_at: int
    require_membership: bool = True


class SessionStatusResponse(BaseModel):
    session_id: str
    status: str  # pending, completed, expired
    created_at: int
    expires_at: int
    # Populated on completion
    npub: Optional[str] = None
    verified_at: Optional[int] = None
    payout: Optional[dict] = None


# --- Endpoints ---

@router.post("", response_model=CreateSessionResponse)
async def create_session(
    body: CreateSessionRequest,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Create a new login session.
    
    Called by the RP (e.g., Acme Corp website) to initiate a SignedByMe login.
    Returns QR data and deep link for the user to scan/click.
    """
    # Derive client_id from API key (never from request body)
    client_id, client_config = get_client_by_api_key(x_api_key)
    if not client_id:
        raise HTTPException(401, "Invalid API key")
    
    # Validate redirect_uri against allowed list
    allowed_uris = client_config.get("redirect_uris", [])
    if body.redirect_uri not in allowed_uris:
        raise HTTPException(400, f"redirect_uri not in allowed list for client '{client_id}'")
    
    # Get reward amount from server config (not client-provided)
    reward_policy = client_config.get("reward_policy", {})
    amount_sats = reward_policy.get("amount_sats", 0) if reward_policy.get("enabled") else 0
    
    # Get membership requirement (mandatory by default for security)
    require_membership = client_config.get("require_membership", True)
    default_root_id = client_config.get("default_root_id")
    
    # Create session
    session_id = generate_session_id()
    nonce = generate_nonce()
    now = int(time.time())
    expires_at = now + SESSION_TTL
    
    employer_name = client_config.get("name", client_id)
    
    # Store session in SQLite
    db_create_session(
        session_id=session_id,
        client_id=client_id,
        nonce=nonce,
        enterprise=employer_name,
        amount_sats=amount_sats,
        expires_at=expires_at,
        required_root_id=default_root_id,
        required_purpose_id=0,
    )
    
    # Build QR data (deep link format)
    qr_data = f"signedby.me://login?session={session_id}&employer={employer_name}&amount={amount_sats}&nonce={nonce}"
    if require_membership and default_root_id:
        qr_data += f"&root={default_root_id}"
    
    # HTTPS deep link for mobile-to-mobile
    deep_link = f"https://signedby.me/login?session={session_id}&employer={employer_name}&amount={amount_sats}&nonce={nonce}"
    if require_membership and default_root_id:
        deep_link += f"&root={default_root_id}"
    
    # Audit log
    audit_log("session_created", session_id=session_id, client_id=client_id)
    
    logger.info(f"Session created: {session_id} for client={client_id}")
    
    return CreateSessionResponse(
        session_id=session_id,
        nonce=nonce,
        qr_data=qr_data,
        deep_link=deep_link,
        amount_sats=amount_sats,
        employer_name=employer_name,
        expires_at=expires_at,
        require_membership=require_membership
    )


@router.get("/{session_id}", response_model=SessionStatusResponse)
async def get_session_status(session_id: str):
    """
    Poll session status.
    
    Called by the RP to check if the user has completed login.
    No auth required (session_id is the secret).
    """
    session = db_get_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    
    # Determine status
    now = int(time.time())
    if session["verified"]:
        status = "completed"
    elif now > session["expires_at"]:
        status = "expired"
    else:
        status = "pending"
    
    return SessionStatusResponse(
        session_id=session_id,
        status=status,
        created_at=session["created_at"],
        expires_at=session["expires_at"],
        npub=session.get("npub"),
        verified_at=session.get("updated_at") if session["verified"] else None,
        payout=None,  # TODO: Add payout tracking
    )


# --- Internal functions (called by groth16_login.py) ---

def get_session(session_id: str) -> Optional[dict]:
    """Get session record."""
    return db_get_session(session_id)


def complete_session(
    session_id: str,
    npub: str,
    merkle_root: str,
    payout_result: Optional[dict] = None
):
    """
    Mark session as completed.
    
    Called by groth16_login after successful verification.
    """
    session = db_get_session(session_id)
    if not session:
        logger.warning(f"Cannot complete unknown session: {session_id}")
        return
    
    # Update session
    db_update_session(
        session_id,
        verified=1,
        npub=npub,
        merkle_root=merkle_root,
    )
    
    # Audit log
    audit_log(
        "session_completed",
        session_id=session_id,
        client_id=session["client_id"],
        details={"npub": npub[:20] + "...", "merkle_root": merkle_root[:20] + "..."}
    )
    
    logger.info(f"Session completed: {session_id} npub={npub[:20]}...")


def log_payout_attempt(
    session_id: str,
    client_id: str,
    invoice: str,
    result: dict
):
    """Log a payout attempt."""
    audit_log(
        "payout_attempt",
        session_id=session_id,
        client_id=client_id,
        details={"invoice_prefix": invoice[:30], "result": result}
    )


def cleanup_expired_sessions():
    """Remove expired sessions (call periodically)."""
    now = int(time.time())
    # Keep sessions for 1 hour after expiry for debugging
    cutoff = now - 3600
    count = delete_expired_sessions(cutoff)
    if count:
        logger.info(f"Cleaned up {count} expired sessions")
