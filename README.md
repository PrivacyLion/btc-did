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

    SA-->>EA: 18) Login Verified → session token + audit refs (DID pubkey, proof hashes, payment refs)

## Verified Content Claim Anchoring

The SignedByMe mobile app:
1) computes a content hash, 2) generates a **mandatory STWO** proof, 3) performs a **micro BTC payment** to anchor the claim (captures **preimage/txid**), 4) **signs** the VCC with the creator’s **BTC DID** key, and 5) saves/exports the signed claim.  

```mermaid
sequenceDiagram
    autonumber
    participant UM as SignedByMe Mobile App (Creator)
    participant ZK as STWO Prover (on device)
    participant DID as BTC DID Key (on device)
    participant LN as Lightning Network

    UM->>UM: 1) Select asset (file/URL); fetch minimal metadata
    UM->>UM: 2) Canonicalize & compute sha256(content) → content_hash

    UM->>ZK: 3) Generate STWO proof (HashIntegrity / ContentTransform)
    ZK-->>UM: 4) Return zkProof → proof_hash

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

    UM->>UM: 15) Store/export signed VCC locally; generate share artifact (QR/URL/snippet)
