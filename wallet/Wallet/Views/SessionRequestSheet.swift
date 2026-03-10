import SwiftUI
import UIKit
import Erc7730

struct SessionRequestSheet: View {
    let method: String
    let displayModel: DisplayModel?
    let error: String?
    let rawJSON: String?
    let onReject: () -> Void

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Label(method, systemImage: "doc.text")
                        .font(.headline)

                    if let model = displayModel {
                        DisplayModelView(model: model)
                            .padding()
                            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
                    }

                    if let error {
                        Button {
                            copyToClipboard(error)
                        } label: {
                            Label(error, systemImage: "xmark.circle")
                                .font(.footnote)
                                .foregroundStyle(.red)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .buttonStyle(.plain)
                        .contentShape(Rectangle())
                    }

                    if let raw = rawJSON {
                        DisclosureGroup("Raw Data") {
                            Button {
                                copyToClipboard(raw)
                            } label: {
                                Text(raw)
                                    .font(.caption2.monospaced())
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                            .buttonStyle(.plain)
                            .contentShape(Rectangle())
                        }
                    }
                }
                .padding()
            }
            .navigationTitle("Session Request")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Reject") {
                        onReject()
                        dismiss()
                    }
                }
            }
        }
    }

    private func copyToClipboard(_ value: String) {
        UIPasteboard.general.string = value
    }
}
