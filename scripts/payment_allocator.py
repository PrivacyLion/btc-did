#!/usr/bin/env python3
"""
SignedByMe Monthly Payment Allocator (Section 7.2)

Runs on 1st of each month via cron. Separate process from API server.
Reads login_verifications table, calculates revenue share, pays out.

Revenue split:
- 50% retained by SignedByMe
- 30% distributed to enterprises (frequency-weighted by logins)
- 20% distributed to agents (proportional to their share of logins)

Payments via Strike Business API (Lightning + USD fiat offramp).
Minimum payout: 1000 sats (configurable).
"""

import os
import sys
import json
import sqlite3
import logging
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/sbm-allocator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
MIN_PAYOUT_SATS = int(os.environ.get('SBM_MIN_PAYOUT_SATS', '1000'))
STRIKE_API_KEY = os.environ.get('STRIKE_BUSINESS_API_KEY', '')
STRIKE_API_URL = 'https://api.strike.me/v1'
RELAY_URL = os.environ.get('SBM_RELAY_URL', 'wss://relay.privacy-lion.com')
DB_PATH = os.environ.get('SBM_DB_PATH', '/opt/sbm-api/signedby.db')
CLIENTS_JSON = os.environ.get('CLIENTS_JSON', '/opt/sbm-api/clients.json')
DRY_RUN = os.environ.get('SBM_DRY_RUN', 'false').lower() == 'true'


@dataclass
class PayoutRecord:
    """A payout to be made."""
    recipient_type: str  # 'enterprise' or 'agent'
    recipient_id: str    # client_id or npub
    amount_sats: int
    lightning_address: Optional[str] = None
    login_count: int = 0


def get_db_connection() -> sqlite3.Connection:
    """Get read-only connection to the database."""
    conn = sqlite3.connect(f'file:{DB_PATH}?mode=ro', uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def get_write_connection() -> sqlite3.Connection:
    """Get write connection for payout_log table only."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_month_boundaries(month: str) -> tuple[int, int]:
    """Get Unix timestamps for start/end of a YYYY-MM month."""
    year, mon = int(month[:4]), int(month[5:7])
    start = datetime(year, mon, 1, tzinfo=timezone.utc)
    if mon == 12:
        end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(year, mon + 1, 1, tzinfo=timezone.utc)
    return int(start.timestamp()), int(end.timestamp())


def get_login_counts(conn: sqlite3.Connection, month: str) -> dict:
    """
    Get login counts per client_id and per npub for the month.
    
    Returns: {
        'by_client': {client_id: count, ...},
        'by_npub': {npub: count, ...},
        'total': int
    }
    """
    start_ts, end_ts = get_month_boundaries(month)
    
    # Logins by client_id (for enterprise share)
    by_client = {}
    rows = conn.execute("""
        SELECT client_id, COUNT(*) as cnt
        FROM login_verifications
        WHERE verified_at >= ? AND verified_at < ?
        GROUP BY client_id
    """, (start_ts, end_ts)).fetchall()
    for row in rows:
        by_client[row['client_id']] = row['cnt']
    
    # Logins by npub (for agent share)
    by_npub = {}
    rows = conn.execute("""
        SELECT npub, COUNT(*) as cnt
        FROM login_verifications
        WHERE verified_at >= ? AND verified_at < ?
        GROUP BY npub
    """, (start_ts, end_ts)).fetchall()
    for row in rows:
        by_npub[row['npub']] = row['cnt']
    
    total = sum(by_client.values())
    
    return {
        'by_client': by_client,
        'by_npub': by_npub,
        'total': total
    }


def get_strike_revenue(month: str) -> int:
    """
    Get total subscription revenue received this month from Strike Business API.
    Returns amount in sats.
    """
    if not STRIKE_API_KEY:
        logger.warning("STRIKE_BUSINESS_API_KEY not set, using 0 revenue")
        return 0
    
    start_ts, end_ts = get_month_boundaries(month)
    start_iso = datetime.utcfromtimestamp(start_ts).isoformat() + 'Z'
    end_iso = datetime.utcfromtimestamp(end_ts).isoformat() + 'Z'
    
    try:
        headers = {
            'Authorization': f'Bearer {STRIKE_API_KEY}',
            'Content-Type': 'application/json'
        }
        
        # Get received payments for the month
        # Note: Strike API endpoint may vary - adjust based on actual API
        resp = requests.get(
            f'{STRIKE_API_URL}/accounts/handle/signedbyme/transactions',
            headers=headers,
            params={
                'from': start_iso,
                'to': end_iso,
                'type': 'DEPOSIT'
            },
            timeout=30
        )
        resp.raise_for_status()
        
        total_sats = 0
        for tx in resp.json().get('items', []):
            if tx.get('state') == 'COMPLETED':
                amount = tx.get('amount', {})
                if amount.get('currency') == 'BTC':
                    # Convert BTC to sats
                    total_sats += int(float(amount.get('amount', 0)) * 100_000_000)
        
        return total_sats
        
    except Exception as e:
        logger.error(f"Failed to get Strike revenue: {e}")
        return 0


def get_agent_lightning_address(npub: str) -> Optional[str]:
    """
    Get agent's lud16 Lightning address from NOSTR kind 0 profile.
    Queries the relay via WebSocket REQ message.
    """
    try:
        import websocket
        
        # Convert npub to hex if needed
        if npub.startswith('npub'):
            import bech32
            _, data = bech32.bech32_decode(npub)
            if data:
                hex_pubkey = bytes(bech32.convertbits(data, 5, 8, False)).hex()
            else:
                return None
        else:
            hex_pubkey = npub
        
        # Query relay for kind 0 via WebSocket
        ws = websocket.create_connection(RELAY_URL, timeout=10)
        try:
            # Send REQ for kind 0 (profile) by author
            req = json.dumps(['REQ', 'profile', {'kinds': [0], 'authors': [hex_pubkey], 'limit': 1}])
            ws.send(req)
            
            # Read responses until EOSE
            while True:
                msg = ws.recv()
                data = json.loads(msg)
                
                if data[0] == 'EVENT' and data[1] == 'profile':
                    event = data[2]
                    if event.get('kind') == 0:
                        content = json.loads(event.get('content', '{}'))
                        lud16 = content.get('lud16')
                        if lud16:
                            return lud16
                elif data[0] == 'EOSE':
                    break
            
            return None
        finally:
            ws.close()
        
    except Exception as e:
        logger.warning(f"Failed to get Lightning address for {npub[:16]}...: {e}")
        return None


def get_enterprise_lightning_address(client_id: str) -> Optional[str]:
    """
    Get enterprise's Lightning address from NIP-05 nostr.json.
    Reads domain from clients.json, fetches /.well-known/nostr.json.
    """
    try:
        with open(CLIENTS_JSON) as f:
            clients = json.load(f)
        
        client_config = clients.get(client_id, {})
        domain = client_config.get('domain')
        
        if not domain:
            logger.warning(f"No domain found for client {client_id}")
            return None
        
        # Fetch NIP-05
        resp = requests.get(
            f'https://{domain}/.well-known/nostr.json',
            timeout=10
        )
        
        if resp.status_code == 200:
            nostr_json = resp.json()
            # Look for 'lightning' field (our extension)
            return nostr_json.get('lightning')
        
        return None
        
    except Exception as e:
        logger.warning(f"Failed to get Lightning address for enterprise {client_id}: {e}")
        return None


def pay_via_strike(lightning_address: str, amount_sats: int, memo: str) -> tuple[bool, str]:
    """
    Pay to a Lightning address via Strike Business API.
    Returns (success, status_message).
    """
    if DRY_RUN:
        logger.info(f"[DRY RUN] Would pay {amount_sats} sats to {lightning_address}")
        return True, 'dry_run'
    
    if not STRIKE_API_KEY:
        return False, 'no_api_key'
    
    try:
        headers = {
            'Authorization': f'Bearer {STRIKE_API_KEY}',
            'Content-Type': 'application/json'
        }
        
        # Step 1: Create a quote for the Lightning payment
        quote_resp = requests.post(
            f'{STRIKE_API_URL}/payment-quotes/lightning',
            headers=headers,
            json={
                'lnAddressOrInvoice': lightning_address,
                'sourceCurrency': 'BTC',
                'amount': {
                    'currency': 'BTC',
                    'amount': str(amount_sats / 100_000_000)
                },
                'description': memo
            },
            timeout=30
        )
        quote_resp.raise_for_status()
        quote = quote_resp.json()
        quote_id = quote['paymentQuoteId']
        
        # Step 2: Execute the payment
        pay_resp = requests.patch(
            f'{STRIKE_API_URL}/payment-quotes/{quote_id}/execute',
            headers=headers,
            timeout=60
        )
        pay_resp.raise_for_status()
        result = pay_resp.json()
        
        if result.get('state') == 'COMPLETED':
            return True, 'paid'
        else:
            return False, f"payment_state_{result.get('state', 'unknown')}"
        
    except requests.exceptions.HTTPError as e:
        logger.error(f"Strike API error: {e.response.text if e.response else e}")
        return False, f'api_error_{e.response.status_code if e.response else "unknown"}'
    except Exception as e:
        logger.error(f"Payment error: {e}")
        return False, f'error_{type(e).__name__}'


def get_carried_forward(conn: sqlite3.Connection, recipient_id: str) -> int:
    """Get carried-forward balance from previous months."""
    row = conn.execute("""
        SELECT SUM(amount_sats) as total
        FROM payout_log
        WHERE recipient_id = ? AND status = 'carried_forward'
    """, (recipient_id,)).fetchone()
    return row['total'] or 0


def clear_carried_forward(conn: sqlite3.Connection, recipient_id: str):
    """Mark carried-forward records as applied."""
    conn.execute("""
        UPDATE payout_log
        SET status = 'applied'
        WHERE recipient_id = ? AND status = 'carried_forward'
    """, (recipient_id,))


def record_payout(conn: sqlite3.Connection, month: str, payout: PayoutRecord, 
                  status: str, paid_at: Optional[int] = None):
    """Record a payout in payout_log."""
    conn.execute("""
        INSERT INTO payout_log 
        (month, recipient_type, recipient_id, amount_sats, lightning_address, status, paid_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (month, payout.recipient_type, payout.recipient_id, 
          payout.amount_sats, payout.lightning_address, status, paid_at))


def get_failure_count(conn: sqlite3.Connection, recipient_id: str) -> int:
    """Get consecutive failure count for a recipient."""
    rows = conn.execute("""
        SELECT status FROM payout_log
        WHERE recipient_id = ?
        ORDER BY created_at DESC
        LIMIT 3
    """, (recipient_id,)).fetchall()
    
    count = 0
    for row in rows:
        if row['status'] == 'failed':
            count += 1
        else:
            break
    return count


def run_allocation(month: str):
    """
    Run the monthly allocation for the specified month (YYYY-MM).
    """
    logger.info(f"Starting allocation for {month}")
    
    if DRY_RUN:
        logger.info("DRY RUN MODE - no payments will be made")
    
    # Get connections
    read_conn = get_db_connection()
    write_conn = get_write_connection()
    
    try:
        # Step 1: Get login counts
        login_counts = get_login_counts(read_conn, month)
        logger.info(f"Total logins for {month}: {login_counts['total']}")
        logger.info(f"Enterprises: {len(login_counts['by_client'])}")
        logger.info(f"Agents: {len(login_counts['by_npub'])}")
        
        if login_counts['total'] == 0:
            logger.info("No logins this month, nothing to allocate")
            return
        
        # Step 2: Get total revenue
        total_revenue_sats = get_strike_revenue(month)
        logger.info(f"Total revenue: {total_revenue_sats} sats")
        
        if total_revenue_sats == 0:
            logger.warning("No revenue recorded, skipping allocation")
            return
        
        # Step 3: Calculate pools
        retained = int(total_revenue_sats * 0.50)  # 50% SignedByMe
        enterprise_pool = int(total_revenue_sats * 0.30)  # 30% enterprises
        agent_pool = int(total_revenue_sats * 0.20)  # 20% agents
        
        logger.info(f"Pools: retained={retained}, enterprise={enterprise_pool}, agent={agent_pool}")
        
        # Step 4: Calculate enterprise payouts (frequency-weighted)
        enterprise_payouts = []
        for client_id, login_count in login_counts['by_client'].items():
            weight = login_count / login_counts['total']
            amount = int(enterprise_pool * weight)
            
            # Add carried forward
            carried = get_carried_forward(write_conn, client_id)
            total_amount = amount + carried
            
            if total_amount >= MIN_PAYOUT_SATS:
                enterprise_payouts.append(PayoutRecord(
                    recipient_type='enterprise',
                    recipient_id=client_id,
                    amount_sats=total_amount,
                    login_count=login_count
                ))
                if carried > 0:
                    clear_carried_forward(write_conn, client_id)
            elif amount > 0:
                # Below threshold, carry forward
                record_payout(write_conn, month, PayoutRecord(
                    recipient_type='enterprise',
                    recipient_id=client_id,
                    amount_sats=amount,
                    login_count=login_count
                ), 'carried_forward')
                logger.info(f"Enterprise {client_id}: {amount} sats carried forward (below {MIN_PAYOUT_SATS} threshold)")
        
        # Step 5: Calculate agent payouts
        agent_payouts = []
        for npub, login_count in login_counts['by_npub'].items():
            weight = login_count / login_counts['total']
            amount = int(agent_pool * weight)
            
            # Add carried forward
            carried = get_carried_forward(write_conn, npub)
            total_amount = amount + carried
            
            if total_amount >= MIN_PAYOUT_SATS:
                agent_payouts.append(PayoutRecord(
                    recipient_type='agent',
                    recipient_id=npub,
                    amount_sats=total_amount,
                    login_count=login_count
                ))
                if carried > 0:
                    clear_carried_forward(write_conn, npub)
            elif amount > 0:
                # Below threshold, carry forward
                record_payout(write_conn, month, PayoutRecord(
                    recipient_type='agent',
                    recipient_id=npub,
                    amount_sats=amount,
                    login_count=login_count
                ), 'carried_forward')
                logger.info(f"Agent {npub[:16]}...: {amount} sats carried forward (below {MIN_PAYOUT_SATS} threshold)")
        
        # Step 6: Get Lightning addresses and pay enterprises
        logger.info(f"Processing {len(enterprise_payouts)} enterprise payouts")
        for payout in enterprise_payouts:
            payout.lightning_address = get_enterprise_lightning_address(payout.recipient_id)
            
            if not payout.lightning_address:
                record_payout(write_conn, month, payout, 'failed')
                logger.warning(f"Enterprise {payout.recipient_id}: no Lightning address found")
                continue
            
            success, status = pay_via_strike(
                payout.lightning_address,
                payout.amount_sats,
                f"SignedByMe revenue share {month}"
            )
            
            if success:
                record_payout(write_conn, month, payout, 'paid', int(datetime.now(timezone.utc).timestamp()))
                logger.info(f"Enterprise {payout.recipient_id}: paid {payout.amount_sats} sats")
            else:
                failure_count = get_failure_count(write_conn, payout.recipient_id) + 1
                record_payout(write_conn, month, payout, 'failed')
                logger.warning(f"Enterprise {payout.recipient_id}: payment failed ({status}), consecutive failures: {failure_count}")
                
                if failure_count >= 3:
                    logger.error(f"ALERT: Enterprise {payout.recipient_id} has 3+ consecutive payment failures - manual review required")
        
        # Step 7: Get Lightning addresses and pay agents
        logger.info(f"Processing {len(agent_payouts)} agent payouts")
        for payout in agent_payouts:
            payout.lightning_address = get_agent_lightning_address(payout.recipient_id)
            
            if not payout.lightning_address:
                # No lud16 in kind 0, carry forward
                record_payout(write_conn, month, payout, 'carried_forward')
                logger.info(f"Agent {payout.recipient_id[:16]}...: no lud16 found, {payout.amount_sats} sats carried forward")
                continue
            
            success, status = pay_via_strike(
                payout.lightning_address,
                payout.amount_sats,
                f"SignedByMe agent share {month}"
            )
            
            if success:
                record_payout(write_conn, month, payout, 'paid', int(datetime.now(timezone.utc).timestamp()))
                logger.info(f"Agent {payout.recipient_id[:16]}...: paid {payout.amount_sats} sats")
            else:
                # Carry forward on failure (agents don't get flagged like enterprises)
                record_payout(write_conn, month, payout, 'carried_forward')
                logger.warning(f"Agent {payout.recipient_id[:16]}...: payment failed ({status}), carried forward")
        
        write_conn.commit()
        logger.info(f"Allocation complete for {month}")
        
    except Exception as e:
        logger.error(f"Allocation failed: {e}")
        write_conn.rollback()
        raise
    finally:
        read_conn.close()
        write_conn.close()


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        # Default to previous month
        today = datetime.now(timezone.utc)
        first_of_month = today.replace(day=1)
        prev_month = first_of_month - timedelta(days=1)
        month = prev_month.strftime('%Y-%m')
    else:
        month = sys.argv[1]
    
    # Validate month format
    try:
        datetime.strptime(month, '%Y-%m')
    except ValueError:
        print(f"Invalid month format: {month}. Use YYYY-MM.")
        sys.exit(1)
    
    run_allocation(month)


if __name__ == '__main__':
    main()
