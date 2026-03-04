from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pathlib import Path

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .routes.auth import router as auth_router
from .routes.unlock import router as unlock_router
from .routes.claims import router as claims_router
from .routes.roots import router as roots_router
from .routes.membership import router as membership_router
from .routes.session import router as session_router
from .routes.admin import router as admin_router
from .routes.login import router as login_router  # Phase 8: Stateless login
from .routes.enroll import router as enroll_router

from app.oidc_discovery import router as oidc_router
from app.oidc_endpoints import router as oidc_endpoints_router

# Rate limiter: 100 requests per minute per IP for general endpoints
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

app = FastAPI(title="SignedByMe — Stateless Auth API", version="0.2.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Static site directory
SITE_DIR = Path(__file__).resolve().parents[1] / "site"

# OIDC discovery + endpoints
app.include_router(oidc_router)
app.include_router(oidc_endpoints_router)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# v1 routes
app.include_router(login_router)  # Phase 8: Stateless login (/v1/login/verify)
app.include_router(session_router)  # Session management
app.include_router(enroll_router)   # Enrollment API (3-step + direct)
app.include_router(admin_router)  # Admin dashboard API
app.include_router(roots_router)  # Merkle root registry
app.include_router(membership_router)  # Legacy enrollment + tree building
app.include_router(auth_router, prefix="/v1")
app.include_router(unlock_router, prefix="/v1")
app.include_router(claims_router, prefix="/v1")

@app.get("/healthz")
def health():
    return {"ok": True}


# Serve static site
@app.get("/")
def serve_index():
    index_path = SITE_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"message": "SignedByMe API", "docs": "/docs"}


# Mount static files (JS, CSS, etc.)
if SITE_DIR.exists():
    app.mount("/", StaticFiles(directory=str(SITE_DIR), html=True), name="static")
