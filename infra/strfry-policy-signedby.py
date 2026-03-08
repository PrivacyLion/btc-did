#!/usr/bin/env python3
"""
strfry-policy-signedby.py

NIP-42 write-restricted policy plugin for SignedByMe audit relay.

Requirements:
- Requires NIP-42 auth before accepting any write (publish)
- Accept event kinds 28101, 28102, 28103 only — reject everything else
- Read/query access stays open to anyone (handled by strfry, not this plugin)

Install:
1. Copy to /etc/strfry/policies/signedby.py
2. chmod +x /etc/strfry/policies/signedby.py
3. In strfry.conf, set: relay.writePolicy.plugin = "/etc/strfry/policies/signedby.py"

No external dependencies (stdlib only).
"""

import sys
import json

# SignedByMe audit event kinds
ALLOWED_KINDS = {28101, 28102, 28103}


def process_event(input_data: dict) -> dict:
    """Process a single event and return accept/reject decision."""
    event = input_data.get("event", {})
    authed_pubkey = input_data.get("authedPubkey")
    event_id = event.get("id", "")
    event_pubkey = event.get("pubkey", "")
    event_kind = event.get("kind", 0)
    
    # 1. Check NIP-42 authentication
    # If authedPubkey is not set, the client has not completed NIP-42 auth
    if not authed_pubkey:
        return {
            "id": event_id,
            "action": "reject",
            "msg": "blocked: NIP-42 authentication required to publish",
        }
    
    # 2. Verify the event pubkey matches the authenticated pubkey
    # This prevents a client from publishing events with a different pubkey
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
            "msg": f"blocked: kind {event_kind} not allowed (only 28101, 28102, 28103)",
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
            # Log error but continue processing
            sys.stderr.write(f"Policy JSON error: {e}\n")
            sys.stderr.flush()
        except Exception as e:
            sys.stderr.write(f"Policy error: {e}\n")
            sys.stderr.flush()


if __name__ == "__main__":
    main()
