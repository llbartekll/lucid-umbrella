import SwiftUI
import ReownWalletKit

struct SessionProposalSheet: View {
    let proposal: Session.Proposal
    let onApprove: () -> Void
    let onReject: () -> Void

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section("Dapp") {
                    LabeledContent("Name", value: proposal.proposer.name)
                    if !proposal.proposer.description.isEmpty {
                        LabeledContent("Description", value: proposal.proposer.description)
                    }
                    LabeledContent("URL", value: proposal.proposer.url)
                }

                Section("Required Namespaces") {
                    ForEach(Array(proposal.requiredNamespaces.keys.sorted()), id: \.self) { ns in
                        if let namespace = proposal.requiredNamespaces[ns] {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(ns).font(.subheadline.bold())
                                if let chains = namespace.chains {
                                    Text("Chains: \(chains.map(\.absoluteString).joined(separator: ", "))")
                                        .font(.caption)
                                }
                                Text("Methods: \(namespace.methods.joined(separator: ", "))")
                                    .font(.caption)
                                Text("Events: \(namespace.events.joined(separator: ", "))")
                                    .font(.caption)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Session Proposal")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Reject") {
                        onReject()
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Approve") {
                        onApprove()
                        dismiss()
                    }
                }
            }
        }
    }
}
