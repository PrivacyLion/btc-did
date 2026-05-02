#!/bin/bash
set -euo pipefail

# =============================================================================
# SignedByMe Relay Setup Script
# Phase 29: Multiple Relay Infrastructure
#
# Usage: ./setup-relay.sh <relay-name> <domain>
# Example: ./setup-relay.sh relay-sfo relay-sfo.privacy-lion.com
#
# Requirements:
# - Fresh Ubuntu 22.04/24.04 droplet (2GB RAM, 50GB disk minimum)
# - Root access
# - Domain DNS already pointing to this server's IP
# =============================================================================

RELAY_NAME="${1:-}"
RELAY_DOMAIN="${2:-}"

if [[ -z "$RELAY_NAME" || -z "$RELAY_DOMAIN" ]]; then
    echo "Usage: $0 <relay-name> <domain>"
    echo "Example: $0 relay-sfo relay-sfo.privacy-lion.com"
    exit 1
fi

echo "=============================================="
echo "SignedByMe Relay Setup"
echo "Relay Name: $RELAY_NAME"
echo "Domain: $RELAY_DOMAIN"
echo "=============================================="

# -----------------------------------------------------------------------------
# 1. System Updates & Dependencies
# -----------------------------------------------------------------------------
echo "[1/9] Installing system dependencies..."
apt-get update
apt-get install -y \
    git \
    build-essential \
    liblmdb-dev \
    libflatbuffers-dev \
    libsecp256k1-dev \
    libssl-dev \
    zlib1g-dev \
    libzstd-dev \
    libb2-dev \
    nginx \
    certbot \
    python3-certbot-nginx \
    python3 \
    ufw

# -----------------------------------------------------------------------------
# 2. Build strfry from source
# -----------------------------------------------------------------------------
echo "[2/9] Building strfry 1.0.4..."
cd /tmp
if [[ -d strfry ]]; then
    rm -rf strfry
fi
git clone --branch 1.0.4 https://github.com/hoytech/strfry.git
cd strfry
git submodule update --init
make setup-golpe
make -j$(nproc)
cp strfry /usr/local/bin/
chmod +x /usr/local/bin/strfry

echo "strfry version: $(strfry version)"

# -----------------------------------------------------------------------------
# 3. Create strfry user and directories
# -----------------------------------------------------------------------------
echo "[3/9] Setting up strfry user and directories..."
id -u strfry &>/dev/null || useradd -r -s /bin/false strfry
mkdir -p /var/lib/strfry/db
mkdir -p /etc/strfry/policies
chown -R strfry:strfry /var/lib/strfry

# -----------------------------------------------------------------------------
# 4. Create strfry config
# -----------------------------------------------------------------------------
echo "[4/9] Creating strfry config..."
cat > /etc/strfry.conf << 'STRFRY_CONF'
## SignedByMe Audit Relay Configuration

db = "/var/lib/strfry/db"

dbParams {
    maxreaders = 256
    mapsize = 10995116277760
    noReadAhead = false
}

events {
    maxEventSize = 65536
    rejectEventsNewerThanSeconds = 900
    rejectEventsOlderThanSeconds = 94608000
    rejectEphemeralEventsOlderThanSeconds = 60
    ephemeralEventsLifetimeSeconds = 300
    maxNumTags = 2000
    maxTagValSize = 1024
}

relay {
    bind = "0.0.0.0"
    port = 7777
    nofiles = 524288
    realIpHeader = "x-real-ip"

    info {
        name = "RELAY_NAME_PLACEHOLDER"
        description = "SignedByMe Audit Relay - RELAY_DOMAIN_PLACEHOLDER"
        pubkey = ""
        contact = "contact@signedbyme.com"
        icon = ""
        nips = ""
    }

    maxWebsocketPayloadSize = 131072
    maxReqFilterSize = 200
    autoPingSeconds = 55
    enableTcpKeepalive = false
    queryTimesliceBudgetMicroseconds = 10000
    maxFilterLimit = 500
    maxSubsPerConnection = 20

    writePolicy {
        plugin = "/etc/strfry/policies/signedby.py"
    }

    compression {
        enabled = true
        slidingWindow = true
    }

    logging {
        dumpInAll = false
        dumpInEvents = false
        dumpInReqs = false
        dbScanPerf = false
        invalidEvents = true
    }

    numThreads {
        ingester = 3
        reqWorker = 3
        reqMonitor = 3
        negentropy = 2
    }

    negentropy {
        enabled = true
        maxSyncEvents = 1000000
    }
}
STRFRY_CONF

# Replace placeholders with actual values
sed -i "s/RELAY_NAME_PLACEHOLDER/$RELAY_NAME/g" /etc/strfry.conf
sed -i "s/RELAY_DOMAIN_PLACEHOLDER/$RELAY_DOMAIN/g" /etc/strfry.conf

# -----------------------------------------------------------------------------
# 5. Create write policy plugin
# -----------------------------------------------------------------------------
echo "[5/9] Creating write policy plugin..."
cat > /etc/strfry/policies/signedby.py << 'POLICY_EOF'
#!/usr/bin/env python3
"""
strfry-policy-signedby.py

NIP-42 write-restricted policy plugin for SignedByMe audit relay.

Requirements:
- Requires NIP-42 auth before accepting any write (publish)
- Accept event kinds 28101, 28102, 28103, 28200, 28201, 28202, 28250, 28251 only
- Read/query access stays open to anyone (handled by strfry, not this plugin)
"""
import sys
import json

# SignedByMe event kinds
ALLOWED_KINDS = {
    28101,  # proof_event (agent)
    28102,  # auth_complete (agent)
    28103,  # login_complete (agent)
    28200,  # enrollment_authorization (enterprise)
    28201,  # kyc_verification (server - legacy)
    28202,  # enrollment_response (agent)
    28250,  # delegation_grant (human)
    28251,  # delegation_revocation (human)
}

def process_event(input_data: dict) -> dict:
    """Process a single event and return accept/reject decision."""
    event = input_data.get("event", {})
    authed_pubkey = input_data.get("authedPubkey")
    event_id = event.get("id", "")
    event_pubkey = event.get("pubkey", "")
    event_kind = event.get("kind", 0)

    # 1. Check NIP-42 authentication
    if not authed_pubkey:
        return {
            "id": event_id,
            "action": "reject",
            "msg": "blocked: NIP-42 authentication required to publish",
        }

    # 2. Verify the event pubkey matches the authenticated pubkey
    if event_pubkey != authed_pubkey:
        return {
            "id": event_id,
            "action": "reject",
            "msg": "blocked: event pubkey must match authenticated pubkey",
        }

    # 3. Check if event kind is in allowlist
    if event_kind not in ALLOWED_KINDS:
        return {
            "id": event_id,
            "action": "reject",
            "msg": f"blocked: kind {event_kind} not allowed",
        }

    # 4. Event passes all checks — accept
    return {
        "id": event_id,
        "action": "accept",
    }

def main():
    """Main loop: read JSON lines from stdin, output decisions."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            input_data = json.loads(line)
            output = process_event(input_data)
            print(json.dumps(output), flush=True)
        except json.JSONDecodeError as e:
            sys.stderr.write(f"Policy JSON error: {e}\n")
            sys.stderr.flush()
        except Exception as e:
            sys.stderr.write(f"Policy error: {e}\n")
            sys.stderr.flush()

if __name__ == "__main__":
    main()
POLICY_EOF

chmod +x /etc/strfry/policies/signedby.py

# -----------------------------------------------------------------------------
# 6. Create systemd service
# -----------------------------------------------------------------------------
echo "[6/9] Creating systemd service..."
cat > /etc/systemd/system/strfry.service << 'SERVICE_EOF'
[Unit]
Description=strfry nostr relay
After=network.target

[Service]
Type=simple
User=strfry
Group=strfry
ExecStart=/usr/local/bin/strfry relay
Restart=always
RestartSec=5
LimitNOFILE=524288

[Install]
WantedBy=multi-user.target
SERVICE_EOF

systemctl daemon-reload
systemctl enable strfry
systemctl start strfry

echo "Waiting for strfry to start..."
sleep 3
systemctl status strfry --no-pager || true

# -----------------------------------------------------------------------------
# 7. Configure nginx
# -----------------------------------------------------------------------------
echo "[7/9] Configuring nginx..."
cat > /etc/nginx/sites-available/strfry << NGINX_EOF
server {
    listen 80;
    server_name $RELAY_DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:7777;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 3600s;
    }
}
NGINX_EOF

ln -sf /etc/nginx/sites-available/strfry /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx

# -----------------------------------------------------------------------------
# 8. Configure UFW firewall
# -----------------------------------------------------------------------------
echo "[8/9] Configuring firewall..."
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# -----------------------------------------------------------------------------
# 9. SSL Certificate via Certbot
# -----------------------------------------------------------------------------
echo "[9/9] Obtaining SSL certificate..."
certbot --nginx -d "$RELAY_DOMAIN" --non-interactive --agree-tos --email contact@signedbyme.com --redirect

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------
echo ""
echo "=============================================="
echo "Setup complete!"
echo ""
echo "Relay: wss://$RELAY_DOMAIN"
echo ""
echo "Verify with:"
echo "  curl -I https://$RELAY_DOMAIN"
echo "  systemctl status strfry"
echo ""
echo "To sync events from existing relay:"
echo "  strfry sync wss://relay.privacy-lion.com --dir down"
echo "=============================================="
