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
    
    // Wallet selection states
    @State private var selectedWalletType: WalletType?
    @State private var lightningAddress: String = ""
    @State private var custodialUsername: String = ""
    @State private var breezSetup: String = ""
    
    // Step completion tracking
    @State private var step1Complete = false
    @State private var step2Complete = false
    @State private var step3Complete = false

    // Add this debug line:
    init() { print("🟡 isLoading initial state: \(isLoading)") }
    
    var body: some View {
        print("🟡 ContentView body is rendering")
        return ZStack {
            // Clean gradient background
            LinearGradient(
                colors: [
                    Color(red: 0.97, green: 0.98, blue: 1.0),
                    Color(red: 0.94, green: 0.96, blue: 0.99),
                    Color(red: 0.90, green: 0.94, blue: 0.98)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()
            
            ScrollView(showsIndicators: false) {
                VStack(spacing: 32) {
                    // Header
                    headerSection
                    
                    // Step 1: Create Identity
                    stepCard(
                        stepNumber: 1,
                        title: "Create",
                        subtitle: "",
                        isComplete: step1Complete,
                        isEnabled: true
                    ) {
                        step1Content
                    }
                    
                    // Step 2: Connect Wallet
                    stepCard(
                        stepNumber: 2,
                        title: "Connect",
                        subtitle: "",
                        isComplete: step2Complete,
                        isEnabled: step1Complete
                    ) {
                        step2Content
                    }
                    
                    // Step 3: Authenticate
                    stepCard(
                        stepNumber: 3,
                        title: "Push",
                        subtitle: "",
                        isComplete: step3Complete,
                        isEnabled: step1Complete && step2Complete
                    ) {
                        step3Content
                    }
                    
                    // Advanced Features (collapsible)
                    if step1Complete {
                        advancedFeaturesSection
                    }
                    
                    Spacer(minLength: 60)
                }
                .padding(.horizontal, 24)
                .padding(.top, 20)
            }
        }
        .preferredColorScheme(.light)
        .onAppear {
            checkExistingSetup()
        }
    }
    
    // MARK: - Header Section
    private var headerSection: some View {
        VStack(spacing: 16) {
            Text("SignedByMe")
                .font(.system(size: 36, weight: .bold, design: .rounded))
                .foregroundStyle(
                    LinearGradient(
                        colors: [Color.blue, Color.purple],
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
            
            // DID Status
            if let publicDID = didManager.publicDID {
                VStack(spacing: 8) {
                    HStack {
                        Image(systemName: "checkmark.shield.fill")
                            .foregroundColor(.green)
                            .font(.title2)
                        Text("Identity Active")
                            .font(.headline)
                            .fontWeight(.semibold)
                        Spacer()
                    }
                    
                    Text("Public DID: \(publicDID)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(16)
                .background(
                    RoundedRectangle(cornerRadius: 16)
                        .fill(.ultraThinMaterial)
                        .shadow(color: .black.opacity(0.05), radius: 10, x: 0, y: 5)
                )
            }
            
            if isLoading {
                ProgressView("Working...")
                    .font(.headline)
                    .tint(.blue)
                    .padding(.top, 8)
            }
        }
        .padding(.vertical, 20)
    }
    
    // MARK: - Step Card Builder
    private func stepCard<Content: View>(
        stepNumber: Int,
        title: String,
        subtitle: String,
        isComplete: Bool,
        isEnabled: Bool,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(spacing: 0) {
            // Step header
            HStack(alignment: .center, spacing: 16) {
                ZStack {
                    Circle()
                        .fill(stepBackgroundColor(isComplete: isComplete, isEnabled: isEnabled))
                        .frame(width: 60, height: 60)
                        .shadow(color: stepShadowColor(isComplete: isComplete, isEnabled: isEnabled), radius: 8, x: 0, y: 4)
                    
                    if isComplete {
                        Image(systemName: "checkmark")
                            .font(.system(size: 24, weight: .bold))
                            .foregroundColor(.white)
                    } else {
                        Text("\(stepNumber)")
                            .font(.system(size: 24, weight: .bold))
                            .foregroundColor(isEnabled ? .white : .gray)
                    }
                }
                
                VStack(alignment: .center, spacing: 4) {
                    Text(title)
                        .font(.system(size: 28, weight: .bold))
                        .foregroundColor(isEnabled ? .primary : .gray)
                        .baselineOffset(-13)
                    
                    Text(subtitle)
                        .font(.system(size: 18))
                        .foregroundColor(.secondary)
                }
                
                Spacer()
            }
            .padding(.horizontal, 24)
            .padding(.top, 24)
            
            // Step content
            if isEnabled || isComplete {
                content()
                    .padding(.horizontal, 24)
                    .padding(.bottom, 24)
                    .padding(.top, 20)
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 24)
                .fill(.ultraThinMaterial)
                .shadow(color: .black.opacity(isEnabled ? 0.08 : 0.03), radius: 15, x: 0, y: 8)
        )
        .opacity(isEnabled ? 1.0 : 0.6)
    }
    
    // MARK: - Step 1 Content (Identity Creation)
    private var step1Content: some View {
        VStack(spacing: 20) {
            if !step1Complete {
                VStack(spacing: 16) {
                    Text("To create a digital signature press the button below.")
                        .font(.system(size: 16))
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                    
                    bigActionButton(
                        title: "Generate",
                        icon: "plus.circle.fill",
                        colors: [.blue, .purple]
                    ) {
                        generateKeyPair()
                    }
                    
                    if didManager.publicDID != nil {
                        bigActionButton(
                            title: "Regenerate",
                            icon: "arrow.clockwise.circle.fill",
                            colors: [.orange, .red]
                        ) {
                            regenerateKeyPair()
                        }
                    }
                }
            } else {
                completedStepView(
                    title: "Success!",
                    details: didManager.publicDID ?? "No DID available",
                    resetAction: {
                        step1Complete = false
                        step2Complete = false
                        step3Complete = false
                    },
                    resetLabel: "Reset Identity"
                )
            }
        }
    }
    
    // MARK: - Step 2 Content (Connect Wallet)
    private var step2Content: some View {
        VStack(spacing: 20) {
            if !step2Complete {
                VStack(spacing: 16) {
                    Text("Choose your wallet type for Lightning payments.")
                        .font(.system(size: 16))
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                    
                    // Wallet Type Selection (3 options)
                    VStack(spacing: 12) {
                        // Lightning Wallet Option
                        walletTypeButton(
                            title: "Lightning Wallet",
                            subtitle: "Direct Lightning Network",
                            icon: "bolt.fill",
                            walletType: .lightning,
                            isSelected: selectedWalletType == .lightning
                        )
                        
                        // Breez Embedded Wallet Option
                        walletTypeButton(
                            title: "Breez Wallet",
                            subtitle: "Embedded Lightning SDK",
                            icon: "bolt.circle.fill",
                            walletType: .embedded,
                            isSelected: selectedWalletType == .embedded
                        )
                        
                        // Custodial Wallet Option
                        walletTypeButton(
                            title: "Custodial Wallet",
                            subtitle: "Coinbase, Cash App, etc.",
                            icon: "building.2.fill",
                            walletType: .custodial,
                            isSelected: selectedWalletType == .custodial
                        )
                    }
                    
                    // Input field based on wallet type
                    if let walletType = selectedWalletType {
                        VStack(spacing: 12) {
                            switch walletType {
                            case .lightning:
                                inputField(
                                    title: "Lightning Address",
                                    placeholder: "lnbc1... or user@lightning.com",
                                    text: $lightningAddress
                                )
                            case .embedded:
                                inputField(
                                    title: "Breez Setup",
                                    placeholder: "Enter Breez credentials",
                                    text: $breezSetup
                                )
                            case .custodial:
                                inputField(
                                    title: "Username or Email",
                                    placeholder: "username@coinbase.com",
                                    text: $custodialUsername
                                )
                            }
                            
                            bigActionButton(
                                title: "Connect \(getWalletDisplayName(walletType))",
                                icon: "link",
                                colors: [.orange, .yellow]
                            ) {
                                connectWallet()
                            }
                            .disabled(getInputText(walletType).isEmpty)
                        }
                    }
                }
            } else {
                completedStepView(
                    title: "Wallet Connected!",
                    details: getConnectedWalletDetails(),
                    resetAction: {
                        step2Complete = false
                        step3Complete = false
                        selectedWalletType = nil
                        lightningAddress = ""
                        custodialUsername = ""
                        breezSetup = ""
                    },
                    resetLabel: "Change Wallet"
                )
            }
        }
    }
    
    // MARK: - Step 3 Content (Authentication)
    private var step3Content: some View {
        VStack(spacing: 20) {
            Text("Complete your authentication process using Lightning payments.")
                .font(.system(size: 16))
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
            
            VStack(spacing: 12) {
                bigActionButton(
                    title: "Verify Identity",
                    icon: "checkmark.shield.fill",
                    colors: [.green, .mint]
                ) {
                    verifyIdentity()
                }
                
                bigActionButton(
                    title: "Prove Ownership",
                    icon: "signature",
                    colors: [.purple, .pink]
                ) {
                    proveOwnership()
                }
            }
            
            if claimResult != "No claim yet" {
                resultCard(title: "Authentication Result", content: claimResult)
            }
        }
    }
    
    // MARK: - Advanced Features Section
    private var advancedFeaturesSection: some View {
        VStack(spacing: 20) {
            Text("Advanced Features")
                .font(.system(size: 24, weight: .bold))
                .frame(maxWidth: .infinity, alignment: .leading)
                .foregroundColor(.primary)
            
            // STWO Zero-Knowledge Proofs
            featureCard(title: "Zero-Knowledge Proofs") {
                VStack(spacing: 16) {
                    inputField(title: "Input Hash", placeholder: "input_hash", text: $inputHash)
                    inputField(title: "Output Hash", placeholder: "output_hash", text: $outputHash)
                    inputField(title: "Circuit", placeholder: "hash_integrity", text: $circuit)
                    
                    bigActionButton(
                        title: "Generate STWO Proof",
                        icon: "number.square.fill",
                        colors: [.red, .orange]
                    ) {
                        generateSTWOProof()
                    }
                    
                    if proofResult != "No proof yet" {
                        resultCard(title: "Proof Result", content: proofResult)
                    }
                }
            }
            
            // DLC Contracts
            featureCard(title: "DLC Contracts") {
                VStack(spacing: 16) {
                    inputField(title: "DLC Outcome", placeholder: "auth_verified", text: $dlcOutcome)
                    
                    bigActionButton(
                        title: "Create DLC Contract",
                        icon: "doc.text.fill",
                        colors: [.teal, .cyan]
                    ) {
                        createDLCContract()
                    }
                    
                    if dlcResult != "No DLC yet" {
                        resultCard(title: "DLC Result", content: dlcResult)
                    }
                }
            }
            
            // Verified Content Claims
            featureCard(title: "Content Claims") {
                VStack(spacing: 16) {
                    inputField(title: "Content URL", placeholder: "https://example.com/content", text: $vccContentURL)
                    inputField(title: "LN Address", placeholder: "ln@address.com", text: $vccLnAddress)
                    
                    bigActionButton(
                        title: "Generate VCC",
                        icon: "doc.badge.plus.fill",
                        colors: [.indigo, .blue]
                    ) {
                        generateVCC()
                    }
                    
                    if vccResult != "No VCC yet" {
                        resultCard(title: "VCC Result", content: vccResult)
                    }
                }
            }
        }
    }
    
    // MARK: - Helper Views
    private func bigActionButton(
        title: String,
        icon: String,
        colors: [Color],
        action: @escaping () -> Void
    ) -> some View {
        print("🟠 Creating button: \(title)")
        return Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.title2)
                Text(title)
                    .font(.system(size: 18, weight: .semibold))
            }
            .foregroundColor(.white)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 18)
            .background(
                LinearGradient(
                    colors: colors,
                    startPoint: .leading,
                    endPoint: .trailing
                )
            )
            .clipShape(RoundedRectangle(cornerRadius: 16))
            .shadow(color: colors.first?.opacity(0.4) ?? .clear, radius: 12, x: 0, y: 6)
        }
        // .disabled(isLoading)  // Temporarily commented out
    }
    
    private func inputField(title: String, placeholder: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.system(size: 16, weight: .medium))
                .foregroundColor(.primary)
            
            TextField(placeholder, text: text)
                .font(.system(size: 16))
                .padding(16)
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(.background.opacity(0.7))
                        .stroke(.gray.opacity(0.2), lineWidth: 1)
                )
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
        }
    }
    
    private func completedStepView(
        title: String,
        details: String,
        resetAction: @escaping () -> Void,
        resetLabel: String
    ) -> some View {
        VStack(spacing: 12) {
            HStack {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(.green)
                    .font(.title2)
                
                Text(title)
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundColor(.green)
                
                Spacer()
            }
            
            Text(details)
                .font(.system(size: 14, design: .monospaced))
                .foregroundColor(.primary)
                .padding(12)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(.background.opacity(0.7))
                        .stroke(.gray.opacity(0.2), lineWidth: 1)
                )
                .frame(maxWidth: .infinity, alignment: .leading)
            
            Button(resetLabel) {
                resetAction()
            }
            .font(.system(size: 16))
            .foregroundColor(.orange)
            .padding(.top, 8)
        }
    }
    
    private func featureCard<Content: View>(
        title: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(title)
                .font(.system(size: 20, weight: .semibold))
                .foregroundColor(.primary)
            
            content()
        }
        .padding(20)
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(.ultraThinMaterial)
                .shadow(color: .black.opacity(0.05), radius: 12, x: 0, y: 6)
        )
    }
    
    private func resultCard(title: String, content: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.system(size: 14, weight: .medium))
                .foregroundColor(.secondary)
            
            Text(content)
                .font(.system(size: 12))
                .foregroundColor(.primary)
                .padding(12)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(.background.opacity(0.7))
                        .stroke(.gray.opacity(0.2), lineWidth: 1)
                )
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
    
    private func walletTypeButton(
        title: String,
        subtitle: String,
        icon: String,
        walletType: WalletType,
        isSelected: Bool
    ) -> some View {
        Button(action: {
            selectedWalletType = walletType
        }) {
            HStack(spacing: 16) {
                ZStack {
                    RoundedRectangle(cornerRadius: 12)
                        .fill(isSelected ? Color.blue.opacity(0.2) : Color.gray.opacity(0.1))
                        .frame(width: 50, height: 50)
                    
                    Image(systemName: icon)
                        .font(.title2)
                        .foregroundColor(isSelected ? .blue : .gray)
                }
                
                VStack(alignment: .leading, spacing: 4) {
                    Text(title)
                        .font(.headline)
                        .fontWeight(.semibold)
                        .foregroundColor(.primary)
                    
                    Text(subtitle)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
                
                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                    .font(.title2)
                    .foregroundColor(isSelected ? .blue : .gray)
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 16)
                    .fill(.ultraThinMaterial)
                    .stroke(isSelected ? .blue.opacity(0.5) : .clear, lineWidth: 2)
            )
        }
        .buttonStyle(PlainButtonStyle())
    }
    
    // MARK: - Helper Functions
    private func stepBackgroundColor(isComplete: Bool, isEnabled: Bool) -> LinearGradient {
        if isComplete {
            return LinearGradient(colors: [.green, .mint], startPoint: .topLeading, endPoint: .bottomTrailing)
        } else if isEnabled {
            return LinearGradient(colors: [.blue, .purple], startPoint: .topLeading, endPoint: .bottomTrailing)
        } else {
            return LinearGradient(colors: [.gray, .gray], startPoint: .topLeading, endPoint: .bottomTrailing)
        }
    }
    
    private func stepShadowColor(isComplete: Bool, isEnabled: Bool) -> Color {
        if isComplete {
            return .green.opacity(0.3)
        } else if isEnabled {
            return .blue.opacity(0.3)
        } else {
            return .clear
        }
    }
        
    private func getWalletDisplayName(_ walletType: WalletType) -> String {
            switch walletType {
            case .lightning: return "Lightning Wallet"
            case .embedded: return "Breez Wallet"
            case .custodial: return "Custodial Wallet"
            }
        }

    private func getInputText(_ walletType: WalletType) -> String {
            switch walletType {
            case .lightning: return lightningAddress
            case .embedded: return breezSetup
            case .custodial: return custodialUsername
            }
        }

    private func getConnectedWalletDetails() -> String {
            guard let walletType = selectedWalletType else { return "No wallet selected" }
            switch walletType {
            case .lightning: return lightningAddress
            case .embedded: return breezSetup
            case .custodial: return custodialUsername
            }
        }
    
    // MARK: - Action Functions
    private func checkExistingSetup() {
        Task {
            do {
                if let publicDID = try didManager.getPublicDID(), !publicDID.isEmpty {
                    await MainActor.run {
                        step1Complete = true
                        print("Found existing DID: \(publicDID)")
                    }
                } else {
                    print("No existing DID found - user needs to generate")
                }
            } catch {
                print("No existing setup found: \(error)")
            }
        }
    }
    
    private func generateKeyPair() {
        print("🔴 FUNCTION CALLED - This should always print")
        print("🔵 Generate button tapped!")
        isLoading = true
        
        Task {
            do {
                print("🔵 About to call didManager.generateKeyPair()...")
                let result = try didManager.generateKeyPair()
                print("🔵 SUCCESS! Generated DID: \(result)")
                
                await MainActor.run {
                    print("🔵 Setting step1Complete = true")
                    didManager.objectWillChange.send()
                    step1Complete = true
                    isLoading = false
                    print("🔵 isLoading set to false")
                }
            } catch {
                print("🔴 ERROR in Task: \(error)")  // Catch any Task-related errors
                print("🔴 Error type: \(type(of: error))")
                print("🔴 Error description: \(error.localizedDescription)")
                
                await MainActor.run {
                    isLoading = false
                    print("🔴 isLoading set to false due to error")
                }
            }
        }
    }
    private func regenerateKeyPair() {
        isLoading = true
        Task {
            do {
                _ = try didManager.regenerateKeyPair()
                await MainActor.run {
                    step1Complete = true
                    step2Complete = false
                    step3Complete = false
                    isLoading = false
                }
            } catch {
                await MainActor.run {
                    print("Regenerate Error: \(error)")
                    isLoading = false
                }
            }
        }
    }
    
    private func connectWallet() {
        step2Complete = true
    }
    
    private func verifyIdentity() {
        isLoading = true
        Task {
            do {
                let mockWallet = MockLightningWallet()
                let (signature, preimage) = try await didManager.verifyIdentity(withNonce: nonce, lightningWallet: mockWallet, withdrawTo: withdrawTo)
                await MainActor.run {
                    claimResult = "Verified: Signature=\(signature.prefix(16))..., Preimage=\(preimage.prefix(16))..."
                    step3Complete = true
                    isLoading = false
                }
            } catch {
                await MainActor.run {
                    claimResult = "Verify Error: \(error.localizedDescription)"
                    isLoading = false
                }
            }
        }
    }
    
    private func proveOwnership() {
        isLoading = true
        Task {
            do {
                let claim = try await didManager.proveOwnership(walletType: .embedded, withdrawTo: withdrawTo)
                await MainActor.run {
                    claimResult = claim
                    step3Complete = true
                    isLoading = false
                }
            } catch {
                await MainActor.run {
                    claimResult = "Error: \(error.localizedDescription)"
                    isLoading = false
                }
            }
        }
    }
    
    private func generateSTWOProof() {
        isLoading = true
        Task {
            do {
                let (proof, signed) = try await didManager.generateComputationProof(input: Data(inputHash.utf8), output: Data(outputHash.utf8), circuit: circuit)
                await MainActor.run {
                    proofResult = "Proof: \(proof.prefix(50))..., Signed: \(signed.prefix(20))..."
                    isLoading = false
                }
            } catch {
                await MainActor.run {
                    proofResult = "Error: \(error)"
                    isLoading = false
                }
            }
        }
    }
    
    private func createDLCContract() {
        isLoading = true
        Task {
            do {
                let contract = try didManager.createDLC(outcome: dlcOutcome, payout: [0.9, 0.1], oraclePubKey: didManager.publicDID ?? "")
                await MainActor.run {
                    dlcResult = contract
                    isLoading = false
                }
            } catch {
                await MainActor.run {
                    dlcResult = "Error: \(error)"
                    isLoading = false
                }
            }
        }
    }
    
    private func generateVCC() {
        isLoading = true
        Task {
            do {
                let vcc = try await didManager.generateVCC(contentURL: vccContentURL, lnAddress: vccLnAddress)
                await MainActor.run {
                    vccResult = vcc
                    isLoading = false
                }
            } catch {
                await MainActor.run {
                    vccResult = "Error: \(error)"
                    isLoading = false
                }
            }
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
