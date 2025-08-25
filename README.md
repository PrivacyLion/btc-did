# BTC DID — Flows A, B, C

```mermaid
sequenceDiagram

    %% Shared participants for all sections
    participant EA as Enterprise App (Web/Mobile)
    participant SA as Stateless Auth API
    participant UM as SignedByMe Mobile App
    participant ZK as STWO Prover (on mobile)
    participant DLC as DLC Engine (on mobile)
    participant OR as Oracle (DID/Operator key)
    participant LN as Lightning Network
    participant DID as BTC DID Key (on device)

    %% =======================
    %% Section A — Verified Content Claim (VCC) Anchoring (creator-only)
    %% =======================
    rect rgb(245,245,245)
    Note over UM: Section A — VCC Anchoring (creator-only; no enterprise)

    UM->>UM: 1) Select asset (file/URL); fetch minimal metadata
    UM->>UM: 2) Canonicalize & compute sha256(content) -> content_hash
    UM->>ZK: 3) Generate STWO proof (HashIntegrity / ContentTransform)
    ZK-->>UM: 4) Return zkProof -> proof_hash
    UM->>DID: 5) Ensure DID key (generate if first use, Secure Enclave/Keystore)
    DID-->>UM: 6) DID_pubkey available
    UM->>UM: 7) Build pre-anchor VCC JSON {did_pubkey, content_hash, withdraw_to, proof_hash, ts}
    UM->>UM: 8) Create PRP (Payment Request Package) for anchoring micro-payment

    alt Cash App
        UM->>UM: 9a) Show PRP as QR/deeplink compatible with Cash App
        UM->>LN: 10a) Pay PRP via Cash App
        LN-->>UM: 11a) Settlement refs returned (preimage/txid)
    else Custodial Wallet
        UM->>UM: 9b) Show PRP as QR/deeplink for custodial wallet
        UM->>LN: 10b) Pay PRP via custodial wallet
        LN-->>UM: 11b) Settlement refs returned (preimage/txid)
    else Non-Custodial Wallet
        UM->>UM: 9c) Show PRP as QR/deeplink for non-custodial wallet
        UM->>LN: 10c) Pay PRP via non-custodial wallet
        LN-->>UM: 11c) Settlement refs returned (preimage/txid)
    end

    UM->>UM: 12) Bind preimage/txid into VCC JSON (economic/timestamp anchor)
    UM->>DID: 13) SIGN VCC JSON with DID private key (on-device)
    DID-->>UM: 14) VCC signature
    UM->>UM: 15) Store/export signed VCC; generate share artifact (QR/URL/snippet)
    end

    %% =======================
    %% Section B — Enterprise Pay-to-Verify Login (DLC-enforced 90/10)
    %% =======================
    rect rgb(235,245,255)
    Note over EA,UM: Section B — Enterprise Pay-to-Verify Login (DLC-enforced 90/10)

    EA->>SA: 1) Start login -> request nonce (domain-scoped, expiring)
    SA-->>EA: 2) Return nonce + login_id + pay_terms
    EA->>UM: 3) Display QR: {nonce, domain, login_id, pay_terms}
    UM->>ZK: 4) Generate STWO LoginProof(nonce, device_hash, ts)
    ZK-->>UM: 5) zkProof
    UM->>DLC: 6) Build DLC: outcome=auth_verified, payout=90/10
    DLC->>OR: 7) Request outcome-sign policy (auth_verified)
    OR-->>DLC: 8) Oracle policy/descriptor acknowledged
    UM->>SA: 9) Submit DID_signature(nonce) + zkProof + DLC metadata
    SA-->>EA: 10) Return **QR code** containing a Payment Request Package (PRP) for a single DLC-tagged payment token that enforces the split.
    EA->>LN: 11) Present PRP (scan/forward QR) -> initiate payment
    LN-->>SA: 12) Payment settled (preimages / settlement refs)
    SA-->>UM: 13) Settlement refs delivered to mobile (receipt)
    DLC->>OR: 14) Request outcome signature: "auth_verified"
    OR-->>DLC: 15) Oracle outcome signature
    DLC->>LN: 16) Enforce 90/10 split via DLC contract metadata
    LN-->>UM: 17) Funds received to user wallet
    SA-->>EA: 18) Login Verified -> session token + audit refs (DID pubkey, proof hashes, payment refs)
    end

    %% =======================
    %% Section C — Content Unlock / Licensing (DLC-enforced 90/10, single PRP)
    %% =======================
    rect rgb(245,235,245)
    Note over EA,UM: Section C — Content Unlock/Licensing (single PRP; no dual payments)

    EA->>SA: 1) Request unlock/license for claim_id or content_hash
    SA-->>EA: 2) Return terms + **QR with PRP** for a single DLC-tagged payment token (enforces 90/10)
    EA->>LN: 3) Present PRP (scan/forward QR) -> initiate payment
    LN-->>DLC: 4) Payment event with DLC contract metadata
    DLC->>OR: 5) Request outcome signature: "paid=true"
    OR-->>DLC: 6) Oracle outcome signature
    DLC->>LN: 7) Enforce 90/10 split and finalize settlement
    SA-->>EA: 8) Deliver unlock token/license proof
    EA->>UM: 9) (If needed) fetch/decrypt asset using unlock token
    SA-->>EA: 10) Provide verification receipt (claim_id, did_pubkey, anchor refs, proof_hashes)
    EA-->>EA: 11) Record DID-authenticated view for analytics/compliance
    end
