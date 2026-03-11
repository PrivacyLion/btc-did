"""
Session routes - DEPRECATED per Bible Decision 10.

Per the Bible:
- No server-side sessions for login
- Enterprise generates QR locally with format: signedby://{client_id}/{nonce}/{amount_sats}
- App scans QR, generates proof, publishes to NOSTR relay
- Enterprise subscribes to relay, catches proof_event, pays invoices
- Enterprise calls POST /v1/login/verify with proof + preimages
- Server returns id_token

All session management endpoints are removed.
"""

from fastapi import APIRouter

router = APIRouter(tags=["session"], prefix="/v1/session")

# DEPRECATED: All session endpoints removed per Bible Decision 10.
# No server-side sessions. Stateless flow only.

# @router.post("") - DELETED: Enterprise generates QR locally
# @router.get("/{session_id}") - DELETED: No server sessions
