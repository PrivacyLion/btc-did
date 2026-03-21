"""
Auth routes - DEPRECATED per Bible Decision 10.

Per the Bible:
- Enterprise generates QR locally (no server call)
- App publishes proof_event to NOSTR
- Enterprise catches event, pays invoices, calls POST /v1/login/verify
- /v1/login/verify is in login.py (Phase 26)

All endpoints in this file are DEPRECATED and will be removed.
"""

import time, uuid, os
from fastapi import APIRouter, HTTPException
from ..models.auth import (
    LoginStartRequest, LoginStartResponse, LoginCompleteRequest,
    LoginPRPResponse, LoginStatusResponse
)
from ..models.common import PayTerms, PRP, SettlementRefs
from ..lib.crypto import sha256_hex, verify_secp256k1_signature_stub
from ..lib import store

router = APIRouter(tags=["login"])

# DEPRECATED: All login/* endpoints below are removed per Bible Decision 10.
# Enterprise generates QR locally. Only /v1/login/verify exists (in login.py).

# @router.post("/login/start") - DELETED: Enterprise generates nonce locally
# @router.post("/login/complete") - DELETED: App publishes to NOSTR, not server  
# @router.get("/login/status/{login_id}") - DELETED: No server sessions
# @router.post("/login/settle") - DELETED: Enterprise calls /v1/login/verify directly
