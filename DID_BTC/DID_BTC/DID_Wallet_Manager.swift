// File: DIDWalletManager.swift
import Foundation
import P256K
import Security
import SwiftUI
import CryptoKit

class DIDWalletManager: ObservableObject {
    @Published var publicDID: String?
    
    private let keychainService = "Privacy-Lion.DID-BTC"
    private let privateKeyTag = "signedby.privatekey"
    
    func generateKeyPair() throws -> String {
        print("🟡 Generating key pair...")
        let privateKey = try P256K.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let publicKeyHex = publicKey.dataRepresentation.hexString
        let newPublicDID = "did:btcr:\(publicKeyHex)"
        try storePrivateKey(privateKey.dataRepresentation)
        DispatchQueue.main.async {
            self.publicDID = newPublicDID
            print("publicDID set to: \(newPublicDID)")
        }
        print("🟡 Key pair generated successfully")
        return newPublicDID
    }
    
    func regenerateKeyPair() throws -> String {
        try deletePrivateKey()
        return try generateKeyPair()
    }
    
    func retrievePrivateKey() throws -> P256K.Signing.PrivateKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: privateKeyTag,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        print("Keychain retrieve status: \(status)")  // Log the status code for debugging
        
        if status != errSecSuccess {
            print("Keychain error details: \(SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error")")
            return nil
        }
        
        guard let data = item as? Data else {
            print("Item is not Data, type: \(type(of: item))")  // Log if casting fails
            return nil
        }
        
        return try P256K.Signing.PrivateKey(dataRepresentation: data)
    }
    
    private func storePrivateKey(_ keyData: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: privateKeyTag,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly  // Explicit accessibility
        ]
        SecItemDelete(query as CFDictionary)  // Ignore result, as before
        let status = SecItemAdd(query as CFDictionary, nil)
        print("Keychain store status: \(status)")  // Log store status for debugging
        guard status == errSecSuccess else {
            throw NSError(domain: "KeychainError", code: Int(status), userInfo: [NSLocalizedDescriptionKey: SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error"])
        }
    }
    
    private func deletePrivateKey() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: privateKeyTag
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw NSError(domain: "KeychainError", code: Int(status))
        }
    }
    
    func getPublicDID() throws -> String? {
        guard let privateKey = try retrievePrivateKey() else { return nil }
        let publicKey = privateKey.publicKey
        let newPublicDID = "did:btcr:\(publicKey.dataRepresentation.hexString)"
        DispatchQueue.main.async {
            self.publicDID = newPublicDID
        }
        return newPublicDID
    }
    
    func verifyIdentity(withNonce challenge: String, lightningWallet: LightningWalletProtocol, withdrawTo: String = "mock_withdraw_to") async throws -> (signature: String, paymentPreimage: String) {
        guard let privateKey = try retrievePrivateKey() else {
            throw NSError(domain: "DIDError", code: -1, userInfo: [NSLocalizedDescriptionKey: "No private key found"])
        }
        
        let challengeData = Data(challenge.utf8)
        let digest = CryptoKit.SHA256.hash(data: challengeData)
        let signature = try privateKey.signature(for: digest.data)
        let signatureHex = signature.dataRepresentation.hexString
        
        let paymentPreimage = try await lightningWallet.authorizePayment(amountSats: 100, withdrawTo: withdrawTo)
        
        return (signatureHex, paymentPreimage)
    }
    
    func proveOwnership(walletType: WalletType, withdrawTo: String, amountSats: Int = 100) async throws -> String {
        guard let privateKey = try retrievePrivateKey() else {
            throw NSError(domain: "DIDError", code: -1, userInfo: [NSLocalizedDescriptionKey: "No private key found"])
        }
        
        let lightningWallet = getLightningWallet(for: walletType)
        let paymentPreimage = try await lightningWallet.authorizePayment(amountSats: amountSats, withdrawTo: withdrawTo)
        
        var claimDict: [String: String] = [
            "wallet_type": walletType.rawValue,
            "withdraw_to": withdrawTo,
            "paid": "true",
            "preimage": paymentPreimage
        ]
        
        if isIncentivePaid(paymentPreimage: paymentPreimage, amountSats: amountSats) {
            claimDict["login_paid"] = "true"
            handlePayoutSplit(withdrawTo: withdrawTo, amountSats: amountSats, preimage: paymentPreimage)
        }
        
        let jsonData = try JSONSerialization.data(withJSONObject: claimDict, options: .sortedKeys)
        let digest = CryptoKit.SHA256.hash(data: jsonData)
        let signature = try privateKey.signature(for: digest.data)
        let signatureHex = signature.dataRepresentation.hexString
        
        claimDict["signature"] = signatureHex
        let finalJsonData = try JSONSerialization.data(withJSONObject: claimDict, options: .prettyPrinted)
        let signedClaim = String(data: finalJsonData, encoding: .utf8) ?? ""
        
        print("Generated signed claim: \(signedClaim)")
        return signedClaim
    }
    
    private func getLightningWallet(for walletType: WalletType) -> LightningWalletProtocol {
        switch walletType {
        case .lightning:
            return MockLightningWallet() // or create a dedicated LightningWallet class
        case .embedded:
            return BreezLightningWallet()
        case .custodial:
            return CustodialLightningWallet()
        }
    }
    
    private func isIncentivePaid(paymentPreimage: String, amountSats: Int) -> Bool {
        return amountSats >= 100
    }
    
    private func handlePayoutSplit(withdrawTo: String, amountSats: Int, preimage: String) {
        let userShare = Int(Double(amountSats) * 0.9)
        let creatorShare = amountSats - userShare
        print("Payout: User gets \(userShare) sats to \(withdrawTo), Creator gets \(creatorShare) sats")
    }
    
    func generateComputationProof(input: Data, output: Data, circuit: String) async throws -> (proof: String, signedMetadata: String) {
        let inputHashCStr = input.sha256().hexString.cString(using: .utf8)
        let outputHashCStr = output.sha256().hexString.cString(using: .utf8)
        let circuitCStr = circuit.cString(using: .utf8)
        
        let proofPtr = generate_stwo_proof(circuitCStr, inputHashCStr, outputHashCStr)
        guard let proofPtr = proofPtr else {
            throw NSError(domain: "STWOError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to generate proof"])
        }

        let proofCStr = UnsafePointer(proofPtr)  // Convert to immutable pointer
        let proof = String(cString: proofCStr)
        free_proof(proofPtr)
        
        let metadata = "proof_hash:\(Data(proof.utf8).sha256().hexString),circuit:\(circuit)"
        let metadataData = Data(metadata.utf8)
        let digest = CryptoKit.SHA256.hash(data: metadataData)
        guard let privateKey = try retrievePrivateKey() else {
            throw NSError(domain: "DIDError", code: -1, userInfo: [NSLocalizedDescriptionKey: "No private key found"])
        }
        let signature = try privateKey.signature(for: digest.data)
        let signedMetadata = signature.dataRepresentation.hexString
        
        return (proof, signedMetadata)
    }
    
    func createDLC(outcome: String, payout: [Double], oraclePubKey: String) throws -> String {
        let outcomeCStr = outcome.cString(using: .utf8)
        let oracleCStr = oraclePubKey.cString(using: .utf8)
        
        var payoutMut = payout
        let contractPtr = create_dlc_contract(outcomeCStr, &payoutMut, Int32(payout.count), oracleCStr)
        guard let contractPtr = contractPtr else {
            throw NSError(domain: "DLCError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to create DLC"])
        }
        
        let contractCStr = UnsafePointer(contractPtr)
        let contract = String(cString: contractCStr)
        free_contract(contractPtr)
        
        return contract
    }
        
    func signDLCOutcome(outcome: String) throws -> String {
        guard let outcomeCStr = outcome.cString(using: .utf8) else {
            throw NSError(domain: "EncodingError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to encode outcome"])
        }
        
        let signaturePtr = sign_dlc_outcome(outcomeCStr)
        guard let signaturePtr = signaturePtr else {
            throw NSError(domain: "DLCError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to sign DLC outcome"])
        }
        
        let signature = String(cString: signaturePtr)
        free_signature(signaturePtr)
        
        return signature
    }
    
    func publishProof(kind: Int, signedProof: String) async throws {
        ProofPublisher.publish(kind: kind, signedProof: signedProof)
    }
    
    /// Generates a Verified Content Claim (VCC) with optional licensing splits and origin claim for derivative content.
    func generateVCC(contentURL: String, lnAddress: String, originClaim: String? = nil, splits: [(did: String, percentage: Double)]? = nil, metadata: [String: String]? = nil) async throws -> String {
        // Compute mock content hash (await since it's async)
        let contentHash = try await computeContentHash(from: contentURL)
        
        // Build VCC payload
        var payload: [String: String] = [
            "created_by": publicDID ?? "",
            "content_hash": contentHash,
            "ln_address": lnAddress
        ]
        
        // Add optional licensing metadata
        if let originClaim = originClaim {
            payload["origin_claim"] = originClaim
        }
        if let splits = splits, !splits.isEmpty {
            // Validate total percentage
            let totalPercentage = splits.reduce(0.0) { $0 + $1.percentage }
            guard abs(1.0 - totalPercentage) < 0.01 else { // Allow small rounding error
                throw NSError(domain: "LicensingError", code: -6, userInfo: [NSLocalizedDescriptionKey: "Split percentages must sum to 100%"])
            }
            // Convert splits to string-keyed dictionary for JSON compatibility
            let splitDict = splits.map { ("\($0.did)", "\($0.percentage)") }
            payload["split"] = splitDict.map { "did:\($0.0),pct:\($0.1)" }.joined(separator: ";")
        }
        
        // Merge additional metadata
        if let metadata = metadata {
            payload.merge(metadata) { (_, new) in new }
        }
        
        // Convert to JSON string
        let jsonData = try JSONSerialization.data(withJSONObject: payload)
        let digest = CryptoKit.SHA256.hash(data: jsonData)
        guard let privateKey = try retrievePrivateKey() else {
            throw NSError(domain: "DIDError", code: -1, userInfo: [NSLocalizedDescriptionKey: "No private key found"])
        }
        let signature = try privateKey.signature(for: digest.data)
        let vcc = "\(String(data: jsonData, encoding: .utf8) ?? "")|\(signature.dataRepresentation.hexString)"
        
        // Mock anchoring preimage (simulating payment settlement)
        let anchorPreimage = "mock_anchor_preimage_\(UUID().uuidString.prefix(8))"
        print("Anchored with preimage: \(anchorPreimage)")
        
        return vcc
    }
    private func computeContentHash(from url: String) async throws -> String {
        return "sha256_\(url)"
    }
    
    /// Handles a viewer's request to unlock content for a given claim_id or content_hash, returning a mocked PRP with DLC metadata.
    func requestContentUnlock(claimIdOrHash: String, amountSats: Int = 100) async throws -> String {
        guard let publicDID = try getPublicDID() else {
            throw NSError(domain: "DIDError", code: -1, userInfo: [NSLocalizedDescriptionKey: "No public DID available"])
        }
        
        // Mock payment terms for the unlock
        let payTerms: [String: Any] = [
            "amount_sats": amountSats,
            "description": "Unlock content for \(claimIdOrHash)",
            "expires": Int(Date().timeIntervalSince1970) + 3600 // 1-hour expiry
        ]
        
        // Create DLC for unlock (90/10 split)
        let dlcOutcome = "paid=true"
        let payout: [Double] = [0.9, 0.1] // 90% to user, 10% to creator
        let dlcContract = try createDLC(outcome: dlcOutcome, payout: payout, oraclePubKey: publicDID)
        
        // Build PRP JSON with mocked LN invoice and DLC metadata
        let prp: [String: Any] = [
            "claim_id_or_hash": claimIdOrHash,
            "pay_terms": payTerms,
            "dlc_metadata": dlcContract,
            "ln_invoice": "mock_invoice_\(UUID().uuidString)", // Mocked LN invoice
            "timestamp": Int(Date().timeIntervalSince1970)
        ]
        
        let jsonData = try JSONSerialization.data(withJSONObject: prp, options: .prettyPrinted)
        let prpString = String(data: jsonData, encoding: .utf8) ?? ""
        
        print("Generated PRP for unlock: \(prpString)")
        return prpString
    }
    
    /// Simulates delivering an unlock token or license proof after a mocked payment, enabling content access.
    func deliverUnlockToken(claimIdOrHash: String, paymentPreimage: String) async throws -> String {
        guard let publicDID = try getPublicDID() else {
            throw NSError(domain: "DIDError", code: -1, userInfo: [NSLocalizedDescriptionKey: "No public DID available"])
        }
        
        // Validate the payment preimage (mocked check)
        guard !paymentPreimage.isEmpty else {
            throw NSError(domain: "PaymentError", code: -2, userInfo: [NSLocalizedDescriptionKey: "Invalid payment preimage"])
        }
        
        // Mock generation of an unlock token based on claim ID, DID, and payment preimage
        let tokenPayload: [String: Any] = [
            "claim_id_or_hash": claimIdOrHash,
            "did_pubkey": publicDID,
            "payment_preimage": paymentPreimage,
            "token_type": "unlock",
            "expiration": Int(Date().timeIntervalSince1970) + 86400, // 24-hour expiry
            "content_url": "https://example.com/content/\(claimIdOrHash)" // Mock content URL
        ]
        
        let jsonData = try JSONSerialization.data(withJSONObject: tokenPayload, options: .prettyPrinted)
        let unlockToken = String(data: jsonData, encoding: .utf8) ?? ""
        
        // Simulate content access (e.g., print mock URL or decryption)
        print("Delivered unlock token for \(claimIdOrHash). Access content at: \(tokenPayload["content_url"] as? String ?? "N/A")")
        
        return unlockToken
    }
    
    /// Simulates generating a verification receipt for content access, including claim details and audit references.
    func generateVerificationReceipt(claimIdOrHash: String, paymentPreimage: String) async throws -> String {
        guard let publicDID = try getPublicDID() else {
            throw NSError(domain: "DIDError", code: -1, userInfo: [NSLocalizedDescriptionKey: "No public DID available"])
        }
        
        // Mock data for the receipt
        let receiptPayload: [String: Any] = [
            "claim_id_or_hash": claimIdOrHash,
            "did_pubkey": publicDID,
            "anchor_references": [
                "preimage": paymentPreimage,
                "txid": "mock_txid_\(UUID().uuidString.prefix(8))" // Mock transaction ID
            ],
            "proof_hashes": [
                "content_hash": "sha256_\(claimIdOrHash)", // Mock content hash
                "proof_hash": "mock_proof_hash_\(UUID().uuidString.prefix(8))" // Mock proof hash
            ],
            "timestamp": Int(Date().timeIntervalSince1970), // Current timestamp
            "status": "verified"
        ]
        
        let jsonData = try JSONSerialization.data(withJSONObject: receiptPayload, options: .prettyPrinted)
        let receipt = String(data: jsonData, encoding: .utf8) ?? ""
        
        print("Generated verification receipt for \(claimIdOrHash): \(receipt)")
        
        return receipt
    }
}

// MARK: - Supporting Types and Extensions

enum WalletType: String {
    case lightning = "lightning"
    case embedded = "embedded"
    case custodial = "custodial"
}

protocol LightningWalletProtocol {
    func authorizePayment(amountSats: Int, withdrawTo: String) async throws -> String
}

class BreezLightningWallet: LightningWalletProtocol {
    func authorizePayment(amountSats: Int, withdrawTo: String) async throws -> String {
        try await Task.sleep(nanoseconds: 800_000_000)
        return "breez_preimage_\(UUID().uuidString)"
    }
}

class CustodialLightningWallet: LightningWalletProtocol {
    func authorizePayment(amountSats: Int, withdrawTo: String) async throws -> String {
        try await Task.sleep(nanoseconds: 600_000_000)
        return "custodial_preimage_\(UUID().uuidString)"
    }
}

// Mock implementations for compilation
class MockLightningWallet: LightningWalletProtocol {
    func authorizePayment(amountSats: Int, withdrawTo: String) async throws -> String {
        return "mock_preimage_\(UUID().uuidString)"
    }
}

// Helper classes
class ProofPublisher {
    static func publish(kind: Int, signedProof: String) {
        print("Published proof: kind \(kind), \(signedProof)")
    }
}

// MARK: - Data Extensions

extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
    
    func sha256() -> Data {
        CryptoKit.SHA256.hash(data: self).data
    }
    
    init?(hex: String) {
        let hex = hex.replacingOccurrences(of: " ", with: "").uppercased()
        guard hex.count % 2 == 0 else { return nil }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let endIndex = hex.index(index, offsetBy: 2)
            let bytes = hex[index..<endIndex]
            if let byte = UInt8(bytes, radix: 16) {
                data.append(byte)
            } else {
                return nil
            }
            index = endIndex
        }
        self = data
    }
}

extension CryptoKit.Digest {
    var data: Data {
        Data(self)
    }
}
