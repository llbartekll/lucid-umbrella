import SwiftUI
import CodeScanner

struct QRScannerSheet: View {
    let onScan: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            CodeScannerView(codeTypes: [.qr]) { result in
                switch result {
                case .success(let scan):
                    onScan(scan.string)
                case .failure:
                    dismiss()
                }
            }
            .navigationTitle("Scan QR Code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }
}
