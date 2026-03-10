import SwiftUI

struct KeyImportSection: View {
    @Bindable var viewModel: WalletViewModel

    var body: some View {
        Section("Ethereum Key") {
            if let address = viewModel.ethereumAddress {
                LabeledContent("Address") {
                    Text(address)
                        .font(.caption.monospaced())
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                Button("Clear Key", role: .destructive) {
                    viewModel.clearKey()
                }
            } else {
                SecureField("Private key (hex)", text: $viewModel.privateKeyHex)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.caption.monospaced())

                Button("Import") {
                    viewModel.importKey()
                }
                .disabled(viewModel.privateKeyHex.isEmpty)

                if let error = viewModel.keyError {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }
        }
    }
}
