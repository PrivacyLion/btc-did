import SwiftUI

@main
struct BTCDIDAuthApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    @StateObject private var didManager = DIDWalletManager()
    @State private var eventResult: String = "No event yet"
    @State private var nonce: String = "SampleNonce123"
    @State private var withdrawTo: String = "lnbc1..."
    @State private var isLoading: Bool = false
    
    
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    Text("BTC DID Auth")
                        .font(.largeTitle)
                        .fontWeight(.bold)
                        .padding()
                        .background(Material.ultraThinMaterial)  // Glass effect on title
                        .cornerRadius(10)
                    
                    // Public DID Display
                    Text("Public DID: \(didManager.publicDID ?? "Not generated")")
                        .font(.body)
                        .multilineTextAlignment(.center)
                        .padding()
                        .frame(maxWidth: .infinity)
                        .background(Material.ultraThinMaterial)
                        .cornerRadius(10)
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .stroke(Color.gray.opacity(0.2), lineWidth: 1)
                        )
                    
                    // Action Buttons with Glass Effect
                    Button(action: {
                        isLoading = true
                        Task {
                            do {
                                _ = try didManager.generateKeyPair()
                            } catch {
                                print("Generate Error: \(error)")
                            }
                            isLoading = false
                        }
                    }) {
                        Text("Generate Keypair")
                            .padding()
                            .frame(maxWidth: .infinity)
                            .background(isLoading ? .regularMaterial : Material.ultraThinMaterial)
                            .foregroundColor(.black)
                            .cornerRadius(10)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(Color.blue.opacity(0.5), lineWidth: 1)
                            )
                    }
                    .disabled(isLoading)
                    
                    Button(action: {
                        isLoading = true
                        Task {
                            do {
                                _ = try didManager.regenerateKeyPair()
                            } catch {
                                print("Regenerate Error: \(error)")
                            }
                            isLoading = false
                        }
                    }) {
                        Text("Regenerate Keypair")
                            .padding()
                            .frame(maxWidth: .infinity)
                            .background(isLoading ? .regularMaterial : Material.ultraThinMaterial)
                            .foregroundColor(.black)
                            .cornerRadius(10)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(Color.green.opacity(0.5), lineWidth: 1)
                            )
                    }
                    .disabled(isLoading)
                    
                    Button(action: {
                        isLoading = true
                        Task {
                            do {
                                let mockWallet = MockLightningWallet()
                                let (signature, preimage) = try await didManager.verifyIdentity(withNonce: nonce, lightningWallet: mockWallet, withdrawTo: withdrawTo)
                                print("Verified: Sig=\(signature), Preimage=\(preimage)")
                            } catch {
                                print("Verify Error: \(error)")
                            }
                            isLoading = false
                        }
                    }) {
                        Text("Verify Identity")
                            .padding()
                            .frame(maxWidth: .infinity)
                            .background(isLoading ? .regularMaterial : Material.ultraThinMaterial)
                            .foregroundColor(.black)
                            .cornerRadius(10)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(Color.orange.opacity(0.5), lineWidth: 1)
                            )
                    }
                    .disabled(isLoading)
                    
                    Button(action: {
                        isLoading = true
                        Task {
                            do {
                                let event = try await didManager.proveOwnership(walletType: .nwc, withdrawTo: withdrawTo)
                                eventResult = event
                            } catch {
                                eventResult = "Error: \(error.localizedDescription)"
                            }
                            isLoading = false
                        }
                    }) {
                        Text("Prove Ownership")
                            .padding()
                            .frame(maxWidth: .infinity)
                            .background(isLoading ? .regularMaterial : Material.ultraThinMaterial)
                            .foregroundColor(.black)
                            .cornerRadius(10)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10)
                                    .stroke(Color.purple.opacity(0.5), lineWidth: 1)
                            )
                    }
                    .disabled(isLoading)
                    
                    // Event Result
                    Text("Event Result: \(eventResult)")
                        .font(.caption)
                        .multilineTextAlignment(.leading)
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Material.ultraThinMaterial)
                        .cornerRadius(10)
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .stroke(Color.gray.opacity(0.2), lineWidth: 1)
                        )
                    
                    // Withdraw To Input
                    TextField("Withdraw To (e.g., lnbc1...)", text: $withdrawTo)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .padding()
                        .background(Material.ultraThinMaterial)
                        .cornerRadius(10)
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .stroke(Color.gray.opacity(0.2), lineWidth: 1)
                        )
                    
                    // Loading Indicator
                    if isLoading {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle())
                            .padding()
                    }
                }
                .padding()
            }
            .navigationTitle("BTC DID Auth")
        }
    }
}

// Mock Lightning Wallet
class MockLightningWallet: LightningWalletProtocol {
    func authorizePayment(amountSats: Int, withdrawTo: String) async throws -> String {
        return "mock_preimage_\(UUID().uuidString)"
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
