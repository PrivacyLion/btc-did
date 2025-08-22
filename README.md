# Enterprise Pay-to-Verify Login Flow

This diagram shows the **BTC DID Enterprise Login** process end-to-end, including DID signing, STWO proofs, DLC contract enforcement, Oracle signing, and Lightning settlement.  
All enterprise verifications require a **90/10 split** payout (90% user, 10% operator), enforced via a DLC-tagged payment token delivered in a QR code.

```mermaid
sequenceDiagram
    autonumber

    participant EA as Enterprise App (Web/Mobile)
    participant SA as Stateless Auth API
    participant UM as User Mobile App (BTC DID)
    participant ZK as STWO Prover (on mobile)
    participant DLC as DLC Engine (on mobile)
    participant OR as Oracle (DID/Operator key)
    participant LN as Lightning Network

    EA->>SA: 1) Start login → request nonce (domain-scoped, expiring)
    SA-->>EA: 2) Return nonce + login_id + pay_terms
    EA->>UM: 3) Display QR: {nonce, domain, login_id, pay_terms}

    UM->>ZK: 4) Generate STWO LoginProof(nonce, device_hash, ts)
    ZK-->>UM: 5) zkProof

    UM->>DLC: 6) Build DLC: outcome=auth_verified, payout=90/10
    DLC->>OR: 7) Request outcome-sign policy (auth_verified)
    OR-->>DLC: 8) Oracle policy/descriptor acknowledged

    UM->>SA: 9) Submit DID_signature(nonce) + zkProof + DLC metadata

    SA-->>EA: 10) Return **QR code** containing a Payment Request Package (PRP) for a single DLC-tagged payment token that enforces the split
    EA->>LN: 11) Present PRP (scan/forward QR) → initiate payment

    LN-->>SA: 12) Payment settled (preimages / settlement refs)
    SA-->>UM: 13) Settlement refs delivered to mobile (receipt)

    DLC->>OR: 14) Request outcome signature: "auth_verified"
    OR-->>DLC: 15) Oracle outcome signature
    DLC->>LN: 16) DLC path enforces 90/10 split via contract metadata
    LN-->>UM: 17) Funds received to user wallet
    deactivate DLC

    SA-->>EA: 18) Login Verified → session token + audit refs (DID pubkey, proof hashes, payment refs)
