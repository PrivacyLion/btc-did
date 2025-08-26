# BTC DID — All Flows
```mermaid
sequenceDiagram

title BTC DID - All Flows
participant EA as Enterprise App (Web/Mobile)
participant SA as Stateless Auth API
participant UM as SignedByMe Mobile App
participant ZK as STWO Prover (on mobile)
participant DLC as DLC Engine (on mobile)
participant OR as Oracle (DID/Operator key)
participant LN as Lightning Network
participant DID as BTC DID Key (on device)

Note over EA,DID: --- Section A: Verified Content Claim Anchoring ---
UM->>UM: 1) Select asset (file or URL), fetch minimal metadata
UM->>UM: 2) Canonicalize and compute sha256 content to content_hash
UM->>ZK: 3) Generate STWO proof (hash integrity or content transform)
ZK-->>UM: 4) Return zkProof and proof_hash
UM->>DID: 5) Ensure DID key (first use generate in secure enclave)
DID-->>UM: 6) DID pubkey available
UM->>UM: 7) Build pre anchor VCC JSON {did_pubkey, content_hash, withdraw_to, proof_hash, ts}
UM->>UM: 8) Create PRP for anchoring micro payment
alt Cash App
    UM->>UM: 9a) Show PRP as QR or deeplink for Cash App
    UM->>LN: 10a) Pay PRP via Cash App
    LN-->>UM: 11a) Settlement refs returned (preimage and txid)
else Custodial Wallet
    UM->>UM: 9b) Show PRP as QR or deeplink for custodial wallet
    UM->>LN: 10b) Pay PRP via custodial wallet
    LN-->>UM: 11b) Settlement refs returned (preimage and txid)
else Non Custodial Wallet
    UM->>UM: 9c) Show PRP as QR or deeplink for non custodial wallet
    UM->>LN: 10c) Pay PRP via non custodial wallet
    LN-->>UM: 11c) Settlement refs returned (preimage and txid)
end
UM->>UM: 12) Bind preimage and txid into VCC JSON
UM->>DID: 13) Sign VCC JSON with DID private key on device
DID-->>UM: 14) VCC signature ready
UM->>UM: 15) Store or export signed VCC, generate share artifact

Note over EA,DID: --- Section B: Enterprise Login Pay to Verify ---
EA->>SA: 1) Start login, request nonce (domain scoped, expiring)
SA-->>EA: 2) Return nonce, login_id, pay_terms
EA->>UM: 3) Display QR {nonce, domain, login_id, pay_terms}
UM->>ZK: 4) Generate STWO LoginProof with nonce and device hash
ZK-->>UM: 5) zkProof
UM->>DLC: 6) Build DLC outcome auth_verified, payout 90/10
DLC->>OR: 7) Request outcome sign policy for auth_verified
OR-->>DLC: 8) Oracle policy acknowledged
UM->>SA: 9) Submit DID signature over nonce, zkProof, DLC metadata
SA-->>EA: 10) Return QR with PRP for a single DLC tagged payment token that enforces the split
EA->>LN: 11) Present PRP (scan or forward QR) to initiate payment
LN-->>SA: 12) Payment settled (preimages and settlement refs)
SA-->>UM: 13) Settlement refs delivered to mobile (receipt)
DLC->>OR: 14) Request outcome signature auth_verified
OR-->>DLC: 15) Oracle outcome signature
DLC->>LN: 16) Enforce 90/10 split via DLC contract metadata
LN-->>UM: 17) Funds received to user wallet
SA-->>EA: 18) Login verified, session token and audit refs

Note over EA,DID: --- Section C: Content Unlock ---
EA->>SA: 1) Request unlock or license for claim_id or content_hash
SA-->>EA: 2) Return terms and QR with PRP for a single DLC tagged payment token
EA->>LN: 3) Present PRP (scan or forward QR) to initiate payment
LN-->>DLC: 4) Payment event with DLC contract metadata
DLC->>OR: 5) Request outcome signature paid equals true
OR-->>DLC: 6) Oracle outcome signature
DLC->>LN: 7) Enforce 90/10 split and finalize settlement
SA-->>EA: 8) Deliver unlock token or license proof
EA->>UM: 9) If needed, fetch or decrypt asset using unlock token
SA-->>EA: 10) Provide verification receipt (claim_id, did_pubkey, anchor refs, proof_hashes)
EA-->>EA: 11) Record DID authenticated view for analytics and compliance
