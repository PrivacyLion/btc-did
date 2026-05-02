# SignedByMe Relay Deployment Guide

## Phase 29: Multiple Relay Infrastructure

### Current Infrastructure

| Relay | Region | Domain | IP |
|-------|--------|--------|-----|
| Primary | US East (ATL) | relay.signedbyme.com | 174.138.66.8 |
| SFO | US West | relay-sfo.signedbyme.com | TBD |
| AMS | Europe | relay-ams.signedbyme.com | TBD |
| SGP | Asia | relay-sgp.signedbyme.com | TBD |

### Deployment Steps

#### 1. Provision Droplet

On DigitalOcean:
- **Image:** Ubuntu 24.04 LTS
- **Size:** Basic, Regular, 2GB RAM / 1 vCPU / 50GB SSD ($12/mo)
- **Region:** SFO3 / AMS3 / SGP1
- **Hostname:** `signedby-relay-sfo` (or ams/sgp)
- **SSH Key:** Add your key

#### 2. Configure DNS

In GoDaddy (or your DNS provider):
```
relay-sfo.signedbyme.com  A  <droplet-ip>
relay-ams.signedbyme.com  A  <droplet-ip>
relay-sgp.signedbyme.com  A  <droplet-ip>
```

Wait for DNS propagation (5-15 minutes).

#### 3. Run Setup Script

SSH into the new droplet and run:

```bash
# Download setup script
curl -O https://raw.githubusercontent.com/PrivacyLion/SignedByMe/main/scripts/setup-relay.sh
chmod +x setup-relay.sh

# Run with relay name and domain
./setup-relay.sh relay-sfo relay-sfo.signedbyme.com
```

The script will:
1. Install all dependencies
2. Build strfry 1.0.4 from source
3. Configure strfry with SignedByMe write policy
4. Set up systemd service
5. Configure nginx reverse proxy
6. Obtain SSL certificate via Certbot
7. Configure UFW firewall

#### 4. Sync Events from Primary

After setup, sync existing events from the primary relay:

```bash
strfry sync wss://relay.signedbyme.com --dir down
```

This pulls all existing SignedByMe events to the new relay.

#### 5. Verify

```bash
# Check strfry is running
systemctl status strfry

# Check HTTPS
curl -I https://relay-sfo.signedbyme.com

# Test WebSocket (requires wscat)
npm install -g wscat
wscat -c wss://relay-sfo.signedbyme.com
```

### Write Policy

All relays enforce the same NIP-42 write policy:

- **Requires NIP-42 authentication** before accepting writes
- **Allowed event kinds:** 28101, 28102, 28103, 28200, 28201, 28202, 28250, 28251
- **Read access:** Open to anyone

Policy file: `/etc/strfry/policies/signedby.py`

### Monitoring

Add each relay to Uptime Kuma:
- Monitor type: HTTP(s)
- URL: `https://relay-sfo.signedbyme.com`
- Expected status: 200

### Troubleshooting

**strfry won't start:**
```bash
journalctl -u strfry -f
```

**SSL certificate issues:**
```bash
certbot renew --dry-run
```

**Firewall blocking:**
```bash
ufw status
ufw allow 443/tcp
```

### Event Synchronization

Relays are independent peers. To keep them in sync:

**Manual sync (one-time):**
```bash
strfry sync wss://relay.signedbyme.com --dir both
```

**Continuous sync (optional):**
Not required for v1. Agents publish to multiple relays. 
Each relay is authoritative for events it receives directly.

### Relay Configuration in Kind 28200

Enterprises can specify preferred relays in their enrollment authorization events:

```json
{
  "kind": 28200,
  "content": "{\"relays\":[\"wss://relay.signedbyme.com\",\"wss://relay-sfo.signedbyme.com\"],...}"
}
```

If no relays specified, agents default to all SignedByMe relays.
