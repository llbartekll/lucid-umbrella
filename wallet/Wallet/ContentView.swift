import SwiftUI
import ReownWalletKit

struct ContentView: View {
    @State private var viewModel = WalletViewModel()

    var body: some View {
        NavigationStack {
            Form {
                KeyImportSection(viewModel: viewModel)

                if viewModel.ethereumAddress != nil, viewModel.wcConfigured {
                    walletConnectSection
                    sessionsSection
                } else if viewModel.ethereumAddress != nil, !viewModel.wcConfigured {
                    Section("WalletConnect") {
                        Text("WalletConnect not configured. Set WALLETCONNECT_PROJECT_ID in Config.xcconfig.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Wallet")
            .sheet(isPresented: $viewModel.showScanner) {
                QRScannerSheet { code in
                    viewModel.pairFromQR(code)
                }
            }
            .sheet(isPresented: $viewModel.showProposal) {
                if let proposal = viewModel.pendingProposal {
                    SessionProposalSheet(
                        proposal: proposal,
                        onApprove: { viewModel.approveProposal() },
                        onReject: { viewModel.rejectProposal() }
                    )
                }
            }
            .sheet(isPresented: $viewModel.showRequest) {
                SessionRequestSheet(
                    method: viewModel.pendingRequest?.method ?? "unknown",
                    displayModel: viewModel.displayModel,
                    error: viewModel.requestError,
                    rawJSON: viewModel.rawRequestJSON,
                    onReject: { viewModel.rejectRequest() }
                )
            }
            .onAppear {
                viewModel.configureWalletConnect()
            }
        }
    }

    // MARK: - Sections

    private var walletConnectSection: some View {
        Section("WalletConnect") {
            TextField("Paste WC URI", text: $viewModel.pairingURI)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .font(.caption.monospaced())

            HStack {
                Button("Pair") { viewModel.pair() }
                    .disabled(viewModel.pairingURI.isEmpty)

                Spacer()

                Button {
                    viewModel.showScanner = true
                } label: {
                    Label("Scan QR", systemImage: "qrcode.viewfinder")
                }
            }

            if viewModel.isPaired {
                Label("Paired", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .font(.caption)
            }

            if let error = viewModel.pairingError {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
    }

    private var sessionsSection: some View {
        Section("Active Sessions") {
            if viewModel.activeSessions.isEmpty {
                Text("No active sessions")
                    .foregroundStyle(.secondary)
                    .font(.footnote)
            } else {
                ForEach(viewModel.activeSessions, id: \.topic) { session in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(session.peer.name)
                            .font(.subheadline)
                        Text(session.peer.url)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }
}
