// File: ContentView.swift
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
    @State private var claimResult: String = "No claim yet"
    @State private var nonce: String = "SampleNonce123"
    @State private var withdrawTo: String = "lnbc1..."
    @State private var isLoading: Bool = false
    
    // States for advanced features
    @State private var inputHash: String = "input_hash"
    @State private var outputHash: String = "output_hash"
    @State private var circuit: String = "hash_integrity"
    @State private var proofResult: String = "No proof yet"
    @State private var vccContentURL: String = "https://example.com/content"
    @State private var vccLnAddress: String = "ln@address.com"
    @State private var vccResult: String = "No VCC yet"
    @State private var dlcOutcome: String = "auth_verified"
    @State private var dlcResult: String = "No DLC yet"
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    Text("BTC DID Auth")
                        .font(.largeTitle)
                        .fontWeight(.bold)
                        .padding()
                        .background(Material.ultraThinMaterial)
                        .cornerRadius(10)
                    
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
                    
                    // Phase 1: Core DID Functions
                    VStack(spacing: 15) {
                        Text("Phase 1: Core DID Wallet")
                            .font(.headline)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        
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
                    }
                    
                    // Phase 2: Lightning Authentication
                    VStack(spacing: 15) {
                        Text("Phase 2: Lightning Authentication")
                            .font(.headline)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        
                        TextField("Withdraw To (e.g., lnbc1...)", text: $withdrawTo)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                            .padding(.horizontal)
                        
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
                                    let claim = try await didManager.proveOwnership(walletType: .embedded, withdrawTo: withdrawTo)
                                    claimResult = claim
                                } catch {
                                    claimResult = "Error: \(error.localizedDescription)"
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
                    }
                    
                    Text("Claim Result: \(claimResult)")
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
                    
                    // Phase 3: STWO Proof Generation
                    VStack(spacing: 15) {
                        Text("Phase 3: STWO Zero-Knowledge Proofs")
                            .font(.headline)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        
                        TextField("Input Hash", text: $inputHash)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                        TextField("Output Hash", text: $outputHash)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                        TextField("Circuit (e.g., hash_integrity)", text: $circuit)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                        
                        Button(action: {
                            isLoading = true
                            Task {
                                do {
                                    let (proof, signed) = try await didManager.generateComputationProof(input: Data(inputHash.utf8), output: Data(outputHash.utf8), circuit: circuit)
                                    proofResult = "Proof: \(proof), Signed: \(signed)"
                                } catch {
                                    proofResult = "Error: \(error)"
                                }
                                isLoading = false
                            }
                        }) {
                            Text("Generate STWO Proof")
                                .padding()
                                .frame(maxWidth: .infinity)
                                .background(isLoading ? .regularMaterial : Material.ultraThinMaterial)
                                .foregroundColor(.black)
                                .cornerRadius(10)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 10)
                                        .stroke(Color.red.opacity(0.5), lineWidth: 1)
                                )
                        }
                        .disabled(isLoading)
                    }
                    
                    Text("Proof Result: \(proofResult)")
                        .font(.caption)
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Material.ultraThinMaterial)
                        .cornerRadius(10)
                    
                    // Phase 4 & 5: DLC Contracts
                    VStack(spacing: 15) {
                        Text("Phase 4-5: Mobile DLC Contracts")
                            .font(.headline)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        
                        TextField("DLC Outcome", text: $dlcOutcome)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                        
                        Button(action: {
                            isLoading = true
                            Task {
                                do {
                                    let contract = try didManager.createDLC(outcome: dlcOutcome, payout: [0.9, 0.1], oraclePubKey: didManager.publicDID ?? "")
                                    dlcResult = contract
                                } catch {
                                    dlcResult = "Error: \(error)"
                                }
                                isLoading = false
                            }
                        }) {
                            Text("Create DLC Contract")
                                .padding()
                                .frame(maxWidth: .infinity)
                                .background(isLoading ? .regularMaterial : Material.ultraThinMaterial)
                                .foregroundColor(.black)
                                .cornerRadius(10)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 10)
                                        .stroke(Color.teal.opacity(0.5), lineWidth: 1)
                                )
                        }
                        .disabled(isLoading)
                    }
                    
                    Text("DLC Result: \(dlcResult)")
                        .font(.caption)
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Material.ultraThinMaterial)
                        .cornerRadius(10)
                    
                    // Phase 6: Verified Content Claims
                    VStack(spacing: 15) {
                        Text("Phase 6: Verified Content Claims")
                            .font(.headline)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        
                        TextField("Content URL", text: $vccContentURL)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                        TextField("LN Address", text: $vccLnAddress)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                        
                        Button(action: {
                            isLoading = true
                            Task {
                                do {
                                    let vcc = try await didManager.generateVCC(contentURL: vccContentURL, lnAddress: vccLnAddress)
                                    vccResult = vcc
                                } catch {
                                    vccResult = "Error: \(error)"
                                }
                                isLoading = false
                            }
                        }) {
                            Text("Generate VCC")
                                .padding()
                                .frame(maxWidth: .infinity)
                                .background(isLoading ? .regularMaterial : Material.ultraThinMaterial)
                                .foregroundColor(.black)
                                .cornerRadius(10)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 10)
                                        .stroke(Color.indigo.opacity(0.5), lineWidth: 1)
                                )
                        }
                        .disabled(isLoading)
                    }
                    
                    Text("VCC Result: \(vccResult)")
                        .font(.caption)
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Material.ultraThinMaterial)
                        .cornerRadius(10)
                    
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

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
