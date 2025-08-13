// File: DIDWalletManager.swift
import Foundation
import P256K
import Security
import SwiftUI
import CryptoKit

class DIDWalletManager: ObservableObject {
    @Published var publicDID: String?
    
    private let keychainService = "Privacy-Lion.DID-BTC"
    private let privateKeyTag = "btcdid.privatekey"
    
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
        let outcomeCStr = outcome.cString(using: .utf8)
        
        let signaturePtr = sign_dlc_outcome(outcomeCStr)
        guard let signaturePtr = signaturePtr else {
            throw NSError(domain: "DLCError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to sign outcome"])
        }

        let sigCStr = UnsafePointer(signaturePtr)  // Convert to immutable
        let signature = String(cString: sigCStr)
        free_signature(signaturePtr)
        
        return signature
    }
    
    func publishProof(kind: Int, signedProof: String) async throws {
        ProofPublisher.publish(kind: kind, signedProof: signedProof)
    }
    
    func generateVCC(contentURL: String, lnAddress: String, metadata: [String: String]? = nil) async throws -> String {
        let contentHash = try await computeContentHash(from: contentURL)
        
        var payload: [String: String] = [
            "created_by": publicDID ?? "",
            "content_hash": contentHash,
            "ln_address": lnAddress
        ]
        if let metadata = metadata {
            payload.merge(metadata) { (_, new) in new }
        }
        
        let jsonData = try JSONSerialization.data(withJSONObject: payload)
        let digest = CryptoKit.SHA256.hash(data: jsonData)
        guard let privateKey = try retrievePrivateKey() else {
            throw NSError(domain: "DIDError", code: -1, userInfo: [NSLocalizedDescriptionKey: "No private key found"])
        }
        let signature = try privateKey.signature(for: digest.data)
        let vcc = "\(String(data: jsonData, encoding: .utf8) ?? "")|\(signature.dataRepresentation.hexString)"
        
        let anchorPreimage = "mock_anchor_preimage"
        print("Anchored with preimage: \(anchorPreimage)")
        
        return vcc
    }
    
    private func computeContentHash(from url: String) async throws -> String {
        return "sha256_\(url)"
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
