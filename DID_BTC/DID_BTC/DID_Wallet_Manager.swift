import Foundation
import CryptoKit
import Security

extension DIDWalletManager {
    // Phase 0/1: Verify Identity (async version)
    func verifyIdentity(withNonce challenge: String, lightningWallet: LightningWalletProtocol, withdrawTo: String = "mock_withdraw_to") async throws -> (signature: String, paymentPreimage: String) {
        guard let privateKey = try retrievePrivateKey() else {
            throw NSError(domain: "DIDError", code: -1, userInfo: [NSLocalizedDescriptionKey: "No private key found"])
        }
        
        // Sign nonce with DID private key
        let challengeData = Data(challenge.utf8)
        let signature = try privateKey.signature(for: challengeData)
        let signatureHex = signature.rawRepresentation.hexString
        
        // Authorize Lightning payment (now async)
        let paymentPreimage = try await lightningWallet.authorizePayment(amountSats: 100, withdrawTo: withdrawTo)
        
        return (signatureHex, paymentPreimage)
    }
    
    // Phase 2: Lightning-Based Ownership Proof (async version)
    func proveOwnership(walletType: WalletType, withdrawTo: String, amountSats: Int = 100) async throws -> String {
        guard let privateKey = try retrievePrivateKey() else {
            throw NSError(domain: "DIDError", code: -1, userInfo: [NSLocalizedDescriptionKey: "No private key found"])
        }
        
        // Simulate Lightning payment and get proof (preimage)
        let lightningWallet = getLightningWallet(for: walletType)
        let paymentPreimage = try await lightningWallet.authorizePayment(amountSats: amountSats, withdrawTo: withdrawTo)
        
        // Create NOSTR event with tags
        var tags = [
            ["wallet_type", walletType.rawValue],
            ["withdraw_to", withdrawTo],
            ["paid", "true"]
        ]
        
        // If incentive payment received (mock verification)
        if isIncentivePaid(paymentPreimage: paymentPreimage, amountSats: amountSats) {
            tags.append(["login_paid", "true"])
            handlePayoutSplit(withdrawTo: withdrawTo, amountSats: amountSats, preimage: paymentPreimage)
        }
        
        let event = try createNostrEvent(kind: 30078, content: "", tags: tags, privateKey: privateKey)
        
        // Publish to NOSTR relay (mock; implement URLSessionWebSocketTask in production)
        print("Publishing event: \(event)")
        return event  // Return event JSON string for further use
    }
    
    private func getLightningWallet(for walletType: WalletType) -> LightningWalletProtocol {
        switch walletType {
        case .nwc:
            return NWCLightningWallet()
        case .embedded:
            return BreezLightningWallet()
        case .custodial:
            return CustodialLightningWallet()
        }
    }
    
    private func isIncentivePaid(paymentPreimage: String, amountSats: Int) -> Bool {
        // Mock verification of incentive payment from platform/bank
        // In prod, check against expected hash or API
        return amountSats >= 100  // Example logic
    }
    
    private func handlePayoutSplit(withdrawTo: String, amountSats: Int, preimage: String) {
        // Mock payout split: 90% to user, 10% to creator
        let userShare = Int(Double(amountSats) * 0.9)
        let creatorShare = amountSats - userShare
        print("Payout: User gets \(userShare) sats to \(withdrawTo), Creator gets \(creatorShare) sats")
        // In prod, use Lightning lib to route payments
    }
    
    func createNostrEvent(kind: Int, content: String, tags: [[String]], privateKey: P256.Signing.PrivateKey) throws -> String {
        let pubkey = privateKey.publicKey.x963Representation.hexString
        let createdAt = Int(Date().timeIntervalSince1970)
        
        // Create simplified event JSON
        let tagsJSON = tagsToJSON(tags)
        let eventJSON = """
        {
            "kind": \(kind),
            "pubkey": "\(pubkey)",
            "created_at": \(createdAt),
            "tags": \(tagsJSON),
            "content": "\(content)"
        }
        """
        return eventJSON
    }
    
    private func tagsToJSON(_ tags: [[String]]) -> String {
        let tagsJSON = tags.map { tag in
            let escapedTag = tag.map { "\"\($0)\"" }.joined(separator: ", ")
            return "[\(escapedTag)]"
        }.joined(separator: ", ")
        return "[\(tagsJSON)]"
    }
    
    private func serializeEventArray(_ array: [Any]) throws -> Data {
        var serialized = Data()
        for item in array {
            if let str = item as? String {
                serialized.append(contentsOf: str.utf8)
            } else if let num = item as? Int {
                serialized.append(contentsOf: String(num).utf8)
            } else if let arr = item as? [[String]] {
                for subArr in arr {
                    serialized.append(contentsOf: subArr.joined(separator: ",").utf8)
                }
            } else {
                throw NSError(domain: "SerializationError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Unsupported type in event array"])
            }
        }
        return serialized
    }
}

// Wallet Type Enum for Phase 2
enum WalletType: String {
    case nwc = "NWC"
    case embedded = "embedded"
    case custodial = "custodial"
}

// Protocol for Lightning wallet (async version)
protocol LightningWalletProtocol {
    func authorizePayment(amountSats: Int, withdrawTo: String) async throws -> String
}

class NWCLightningWallet: LightningWalletProtocol {
    func authorizePayment(amountSats: Int, withdrawTo: String) async throws -> String {
        // Mock NWC implementation with delay
        try await Task.sleep(nanoseconds: 500_000_000) // 0.5 seconds
        return "nwc_preimage_\(UUID().uuidString)"
    }
}

class BreezLightningWallet: LightningWalletProtocol {
    func authorizePayment(amountSats: Int, withdrawTo: String) async throws -> String {
        // Mock Breez SDK implementation with delay
        try await Task.sleep(nanoseconds: 800_000_000) // 0.8 seconds
        return "breez_preimage_\(UUID().uuidString)"
    }
}

class CustodialLightningWallet: LightningWalletProtocol {
    func authorizePayment(amountSats: Int, withdrawTo: String) async throws -> String {
        // Mock custodial (e.g., Coinbase) implementation with delay
        try await Task.sleep(nanoseconds: 600_000_000) // 0.6 seconds
        return "custodial_preimage_\(UUID().uuidString)"
    }
}
