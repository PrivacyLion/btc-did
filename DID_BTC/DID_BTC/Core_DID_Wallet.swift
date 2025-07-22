import Foundation
import CryptoKit
import Security


class DIDWalletManager: ObservableObject {
    private let keychainService = "com.yourapp.btcdid"
    private let privateKeyTag = "btcdid.privatekey"
    
    @Published var publicDID: String? = nil  // Reactive property for UI
    
    func generateKeyPair() throws -> (privateKey: P256.Signing.PrivateKey, publicDID: String) {
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let newPublicDID = "did:btcr:\(publicKey.x963Representation.hexString)"
        try storePrivateKey(privateKey.rawRepresentation)
        DispatchQueue.main.async {
            self.publicDID = newPublicDID  // Update on main thread for UI
        }
        return (privateKey, newPublicDID)
    }
    
    private func storePrivateKey(_ keyData: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: privateKeyTag,
            kSecValueData as String: keyData
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: "KeychainError", code: Int(status)) }
    }
    
    func retrievePrivateKey() throws -> P256.Signing.PrivateKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: privateKeyTag,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return try P256.Signing.PrivateKey(rawRepresentation: data)
    }
    
    func regenerateKeyPair() throws -> (privateKey: P256.Signing.PrivateKey, publicDID: String) {
        try deletePrivateKey()
        return try generateKeyPair()
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
        let newPublicDID = "did:btcr:\(publicKey.x963Representation.hexString)"
        DispatchQueue.main.async {
            self.publicDID = newPublicDID
        }
        return newPublicDID
    }
}

extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
    
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
