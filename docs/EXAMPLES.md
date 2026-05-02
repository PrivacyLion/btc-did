# Code Examples

Copy-paste examples for integrating SignedByMe.

---

## curl

### Create Session

```bash
curl -X POST https://api.signedbyme.com/v1/enterprise/session \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "client_id": "acme",
    "redirect_uri": "https://acme.com/callback",
    "amount_sats": 100,
    "memo": "Login to Acme"
  }'
```

### Poll Session Status

```bash
curl https://api.signedbyme.com/v1/enterprise/session/sess_abc123/status \
  -H "X-API-Key: your_api_key"
```

### Exchange Code for Token

```bash
curl -X POST https://api.signedbyme.com/oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=code_xyz789" \
  -d "client_id=acme" \
  -d "redirect_uri=https://acme.com/callback"
```

### Fetch JWKS

```bash
curl https://api.signedbyme.com/.well-known/jwks.json
```

### Enroll Member

```bash
curl -X POST https://api.signedbyme.com/v1/membership/enroll \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "client_id": "acme",
    "purpose_id": "employees",
    "leaf_commitment": "abc123def456..."
  }'
```

### Publish Root

```bash
curl -X POST https://api.signedbyme.com/v1/roots/publish \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "root_id": "acme-employees-2024-02",
    "root_hash": "def456abc789...",
    "purpose_id": "employees"
  }'
```

---

## JavaScript (Node.js)

### Full Login Flow

```javascript
const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const API_BASE = 'https://api.signedbyme.com';
const API_KEY = process.env.SIGNEDBY_API_KEY;
const CLIENT_ID = 'acme';
const REDIRECT_URI = 'https://acme.com/callback';

// JWKS client for token verification
const jwks = jwksClient({
  jwksUri: `${API_BASE}/.well-known/jwks.json`,
  cache: true,
  cacheMaxAge: 86400000 // 24 hours
});

// 1. Create login session
async function createSession(memo = 'Login') {
  const res = await fetch(`${API_BASE}/v1/enterprise/session`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': API_KEY
    },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      amount_sats: 100,
      memo
    })
  });
  
  if (!res.ok) {
    throw new Error(`Session creation failed: ${res.status}`);
  }
  
  return res.json();
}

// 2. Poll for completion
async function waitForCompletion(sessionId, timeoutMs = 300000) {
  const startTime = Date.now();
  
  while (Date.now() - startTime < timeoutMs) {
    const res = await fetch(
      `${API_BASE}/v1/enterprise/session/${sessionId}/status`,
      { headers: { 'X-API-Key': API_KEY } }
    );
    
    const data = await res.json();
    
    if (data.status === 'complete') {
      return data.auth_code;
    }
    
    if (data.status === 'expired' || data.status === 'failed') {
      throw new Error(`Session ${data.status}`);
    }
    
    // Wait 2 seconds before polling again
    await new Promise(r => setTimeout(r, 2000));
  }
  
  throw new Error('Timeout waiting for login');
}

// 3. Exchange code for token
async function exchangeCode(code) {
  const res = await fetch(`${API_BASE}/oidc/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI
    })
  });
  
  if (!res.ok) {
    throw new Error(`Token exchange failed: ${res.status}`);
  }
  
  const data = await res.json();
  return data.id_token;
}

// 4. Verify token
function getSigningKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    callback(err, key?.getPublicKey());
  });
}

async function verifyToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, getSigningKey, {
      algorithms: ['RS256'],
      issuer: API_BASE,
      audience: CLIENT_ID
    }, (err, decoded) => {
      if (err) reject(err);
      else resolve(decoded);
    });
  });
}

// Full flow
async function login() {
  console.log('Creating session...');
  const session = await createSession('Login to Acme');
  
  console.log('Display this QR to user:', session.qr_data);
  console.log('Waiting for user...');
  
  const authCode = await waitForCompletion(session.session_id);
  
  console.log('Exchanging code...');
  const idToken = await exchangeCode(authCode);
  
  console.log('Verifying token...');
  const claims = await verifyToken(idToken);
  
  console.log('Login successful!');
  console.log('User DID:', claims.sub);
  console.log('Payment:', claims['https://signedby.me/claims/amount_sats'], 'sats');
  
  return claims;
}

login().catch(console.error);
```

### Express.js Integration

```javascript
const express = require('express');
const app = express();

app.get('/login', async (req, res) => {
  const session = await createSession('Login to MyApp');
  
  res.render('login', {
    qrData: session.qr_data,
    sessionId: session.session_id
  });
});

app.get('/login/status/:sessionId', async (req, res) => {
  const response = await fetch(
    `${API_BASE}/v1/enterprise/session/${req.params.sessionId}/status`,
    { headers: { 'X-API-Key': API_KEY } }
  );
  
  res.json(await response.json());
});

app.post('/login/callback', async (req, res) => {
  const { code } = req.body;
  
  const idToken = await exchangeCode(code);
  const claims = await verifyToken(idToken);
  
  // Create session for user
  req.session.user = {
    did: claims.sub,
    membership: claims['https://signedby.me/claims/membership_purpose']
  };
  
  res.redirect('/dashboard');
});
```

---

## Python

### Full Login Flow

```python
import os
import time
import requests
from jwt import PyJWKClient
import jwt

API_BASE = "https://api.signedbyme.com"
API_KEY = os.environ["SIGNEDBY_API_KEY"]
CLIENT_ID = "acme"
REDIRECT_URI = "https://acme.com/callback"

# JWKS client
jwks_client = PyJWKClient(f"{API_BASE}/.well-known/jwks.json")


def create_session(memo: str = "Login") -> dict:
    """Create a new login session."""
    response = requests.post(
        f"{API_BASE}/v1/enterprise/session",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY
        },
        json={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "amount_sats": 100,
            "memo": memo
        }
    )
    response.raise_for_status()
    return response.json()


def wait_for_completion(session_id: str, timeout_seconds: int = 300) -> str:
    """Poll until session completes or times out."""
    start_time = time.time()
    
    while time.time() - start_time < timeout_seconds:
        response = requests.get(
            f"{API_BASE}/v1/enterprise/session/{session_id}/status",
            headers={"X-API-Key": API_KEY}
        )
        data = response.json()
        
        if data["status"] == "complete":
            return data["auth_code"]
        
        if data["status"] in ("expired", "failed"):
            raise Exception(f"Session {data['status']}")
        
        time.sleep(2)
    
    raise TimeoutError("Login timed out")


def exchange_code(code: str) -> str:
    """Exchange auth code for ID token."""
    response = requests.post(
        f"{API_BASE}/oidc/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI
        }
    )
    response.raise_for_status()
    return response.json()["id_token"]


def verify_token(token: str) -> dict:
    """Verify and decode ID token."""
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    
    return jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=CLIENT_ID,
        issuer=API_BASE
    )


def login():
    """Complete login flow."""
    print("Creating session...")
    session = create_session("Login to Acme")
    
    print(f"Display this QR to user: {session['qr_data']}")
    print("Waiting for user...")
    
    auth_code = wait_for_completion(session["session_id"])
    
    print("Exchanging code...")
    id_token = exchange_code(auth_code)
    
    print("Verifying token...")
    claims = verify_token(id_token)
    
    print("Login successful!")
    print(f"User DID: {claims['sub']}")
    print(f"Payment: {claims['https://signedby.me/claims/amount_sats']} sats")
    
    if claims.get("https://signedby.me/claims/membership_verified"):
        print(f"Member of: {claims['https://signedby.me/claims/membership_purpose']}")
    
    return claims


if __name__ == "__main__":
    login()
```

### Flask Integration

```python
from flask import Flask, render_template, request, session, redirect, jsonify

app = Flask(__name__)


@app.route("/login")
def login_page():
    session_data = create_session("Login to MyApp")
    return render_template("login.html",
        qr_data=session_data["qr_data"],
        session_id=session_data["session_id"]
    )


@app.route("/login/status/<session_id>")
def login_status(session_id):
    response = requests.get(
        f"{API_BASE}/v1/enterprise/session/{session_id}/status",
        headers={"X-API-Key": API_KEY}
    )
    return jsonify(response.json())


@app.route("/login/callback", methods=["POST"])
def login_callback():
    code = request.form["code"]
    
    id_token = exchange_code(code)
    claims = verify_token(id_token)
    
    # Store in session
    session["user"] = {
        "did": claims["sub"],
        "membership": claims.get("https://signedby.me/claims/membership_purpose")
    }
    
    return redirect("/dashboard")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")
    
    return render_template("dashboard.html", user=session["user"])
```

### Django Integration

```python
# views.py
from django.shortcuts import render, redirect
from django.http import JsonResponse

def login_view(request):
    session_data = create_session("Login to MyApp")
    return render(request, "login.html", {
        "qr_data": session_data["qr_data"],
        "session_id": session_data["session_id"]
    })

def login_status_view(request, session_id):
    response = requests.get(
        f"{API_BASE}/v1/enterprise/session/{session_id}/status",
        headers={"X-API-Key": API_KEY}
    )
    return JsonResponse(response.json())

def login_callback_view(request):
    code = request.POST["code"]
    
    id_token = exchange_code(code)
    claims = verify_token(id_token)
    
    request.session["user_did"] = claims["sub"]
    request.session["membership"] = claims.get(
        "https://signedby.me/claims/membership_purpose"
    )
    
    return redirect("dashboard")
```

---

## HTML/JavaScript (Browser)

### Self-Contained Login Page

```html
<!DOCTYPE html>
<html>
<head>
  <title>Sign in with SignedByMe</title>
  <script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
  <style>
    body { font-family: system-ui; max-width: 400px; margin: 50px auto; text-align: center; }
    #qr { margin: 20px 0; }
    #status { padding: 10px; border-radius: 4px; }
    .pending { background: #fff3cd; }
    .complete { background: #d4edda; }
    .error { background: #f8d7da; }
  </style>
</head>
<body>
  <h1>Sign in with SignedByMe</h1>
  <p>Scan this QR code with your SignedByMe app</p>
  
  <div id="qr"></div>
  <div id="status" class="pending">Waiting for you to scan...</div>
  <p><small>You'll receive <strong>100 sats</strong> for logging in!</small></p>

  <script>
    // Replace with your backend endpoint that creates sessions
    const CREATE_SESSION_URL = '/api/login/create';
    const CHECK_STATUS_URL = '/api/login/status/';
    const COMPLETE_URL = '/api/login/complete';
    
    let sessionId = null;
    let pollInterval = null;
    
    async function init() {
      // 1. Create session via your backend
      const res = await fetch(CREATE_SESSION_URL, { method: 'POST' });
      const data = await res.json();
      
      sessionId = data.session_id;
      
      // 2. Display QR code
      QRCode.toCanvas(
        document.querySelector('#qr'),
        data.qr_data,
        { width: 256 }
      );
      
      // 3. Start polling
      pollInterval = setInterval(checkStatus, 2000);
    }
    
    async function checkStatus() {
      const res = await fetch(CHECK_STATUS_URL + sessionId);
      const data = await res.json();
      
      const statusEl = document.getElementById('status');
      
      if (data.status === 'complete') {
        clearInterval(pollInterval);
        statusEl.textContent = 'Success! Redirecting...';
        statusEl.className = 'complete';
        
        // Send code to your backend for token exchange
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = COMPLETE_URL;
        
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'code';
        input.value = data.auth_code;
        
        form.appendChild(input);
        document.body.appendChild(form);
        form.submit();
      } else if (data.status === 'expired' || data.status === 'failed') {
        clearInterval(pollInterval);
        statusEl.textContent = 'Login failed. Please refresh and try again.';
        statusEl.className = 'error';
      } else if (data.status === 'proof_submitted') {
        statusEl.textContent = 'Verifying payment...';
      }
    }
    
    init();
  </script>
</body>
</html>
```

---

## Membership Examples

### Enroll After Stripe Payment

```python
# Stripe webhook handler
@app.route("/webhook/stripe", methods=["POST"])
def stripe_webhook():
    event = stripe.Webhook.construct_event(
        request.data,
        request.headers["Stripe-Signature"],
        STRIPE_WEBHOOK_SECRET
    )
    
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        user_commitment = session["metadata"]["signedby_commitment"]
        
        # Enroll in premium tree
        requests.post(
            f"{API_BASE}/v1/membership/enroll",
            headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
            json={
                "client_id": CLIENT_ID,
                "purpose_id": "premium",
                "leaf_commitment": user_commitment
            }
        )
    
    return "", 200
```

### Check Membership at Login

```python
def require_membership(purpose: str):
    """Decorator to require membership."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            user = get_current_user()
            
            if not user.get("membership_verified"):
                abort(403, "Membership required")
            
            if user.get("membership_purpose") != purpose:
                abort(403, f"Must be {purpose}")
            
            return f(*args, **kwargs)
        return wrapped
    return decorator


@app.route("/admin")
@require_membership("employees")
def admin_panel():
    return render_template("admin.html")


@app.route("/premium-content")
@require_membership("premium")
def premium_content():
    return render_template("premium.html")
```
