# Relay Setup - relay.privacy-lion.com

## VPS Info
- **IP:** 174.138.66.8
- **DNS:** relay.privacy-lion.com (configured)
- **Provider:** DigitalOcean
- **Purpose:** Nostr relay for SignedByMe users

## Option A: strfry (Recommended)

strfry is high-performance, C++, single binary. Best for production.

### Install strfry

```bash
# SSH to relay VPS
ssh root@174.138.66.8

# Install dependencies
apt update && apt install -y git build-essential libssl-dev zlib1g-dev liblmdb-dev libflatbuffers-dev libsecp256k1-dev pkg-config

# Clone and build
cd /opt
git clone https://github.com/hoytech/strfry.git
cd strfry
git submodule update --init
make setup-golpe
make -j$(nproc)

# Install
cp strfry /usr/local/bin/

# Create config
mkdir -p /etc/strfry
cat > /etc/strfry/strfry.conf << 'EOF'
relay {
    name = "SignedByMe Relay"
    description = "Nostr relay for SignedByMe identity proofs"
    contact = "admin@privacy-lion.com"
}

database {
    path = "/var/lib/strfry/strfry-db"
}

network {
    bind = "127.0.0.1"
    port = 7777
}

# Only allow specific event kinds (DID proofs, etc.)
# Uncomment to restrict:
# writePolicy {
#     plugin = "/etc/strfry/write-policy.js"
# }
EOF

# Create systemd service
cat > /etc/systemd/system/strfry.service << 'EOF'
[Unit]
Description=strfry Nostr relay
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/strfry relay
Restart=always
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Create data dir
mkdir -p /var/lib/strfry
chown nobody:nogroup /var/lib/strfry

# Start
systemctl daemon-reload
systemctl enable strfry
systemctl start strfry
```

### Configure Caddy (HTTPS reverse proxy)

```bash
# Install Caddy
apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt update && apt install -y caddy

# Configure
cat > /etc/caddy/Caddyfile << 'EOF'
relay.privacy-lion.com {
    reverse_proxy 127.0.0.1:7777
}
EOF

systemctl restart caddy
```

### Verify

```bash
# Local test
curl -s http://127.0.0.1:7777 | head

# External test
wscat -c wss://relay.privacy-lion.com
# Send: ["REQ", "test", {}]
```

## Option B: nostr-rs-relay (Rust)

Alternative if you prefer Rust ecosystem.

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone and build
cd /opt
git clone https://github.com/scsibug/nostr-rs-relay.git
cd nostr-rs-relay
cargo build --release

# Install
cp target/release/nostr-rs-relay /usr/local/bin/

# Config at /etc/nostr-rs-relay/config.toml
# Similar systemd setup...
```

## Firewall

```bash
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

## SignedByMe Integration

After relay is running, update app constants:

```kotlin
// In MainActivity.kt or config
const val SIGNEDBY_RELAY = "wss://relay.privacy-lion.com"
```

The app will publish:
- NIP-01 events for identity proofs
- NIP-05 verification (if using /.well-known/nostr.json on the domain)

## Monitoring

```bash
# Check status
systemctl status strfry

# View logs
journalctl -u strfry -f

# Database size
du -sh /var/lib/strfry/
```
