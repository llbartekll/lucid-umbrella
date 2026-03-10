import Foundation
import Erc7730
import ReownWalletKit

@Observable
final class WalletViewModel {

    // Key management
    var privateKeyHex = ""
    var ethereumAddress: String?
    var keyError: String?

    // WalletConnect
    var pairingURI = ""
    var isPaired = false
    var pairingError: String?

    // Sessions
    var activeSessions: [Session] = []

    // Proposal
    var pendingProposal: Session.Proposal?
    var showProposal = false

    // Request
    var pendingRequest: Request?
    var displayModel: DisplayModel?
    var requestError: String?
    var rawRequestJSON: String?
    var showRequest = false

    // QR
    var showScanner = false

    private var keyManager: KeyManager?
    private let clearSigning = ClearSigningService()
    private let wc = WalletConnectService.shared
    var wcConfigured = false

    init() {
        if let restored = KeyManager.restore() {
            keyManager = restored
            ethereumAddress = restored.ethereumAddress
        }
    }

    // MARK: - Key Import

    func importKey() {
        keyError = nil
        do {
            let km = try KeyManager(privateKeyHex: privateKeyHex)
            km.save()
            keyManager = km
            ethereumAddress = km.ethereumAddress
            privateKeyHex = ""
        } catch {
            keyError = error.localizedDescription
        }
    }

    func clearKey() {
        KeyManager.clear()
        keyManager = nil
        ethereumAddress = nil
        privateKeyHex = ""
    }

    // MARK: - WalletConnect

    func configureWalletConnect() {
        let projectId = Bundle.main.infoDictionary?["WalletConnectProjectID"] as? String ?? ""
        guard !projectId.isEmpty, projectId != "YOUR_PROJECT_ID_HERE" else { return }
        Task {
            await wc.configure(projectId: projectId)
            await MainActor.run { wcConfigured = true }
            listenForProposals()
            listenForRequests()
            refreshSessions()
        }
    }

    func pair() {
        pairingError = nil
        let uri = pairingURI.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !uri.isEmpty else { return }
        Task {
            do {
                try await wc.pair(uri: uri)
                await MainActor.run {
                    isPaired = true
                    pairingURI = ""
                }
            } catch {
                await MainActor.run { pairingError = error.localizedDescription }
            }
        }
    }

    func pairFromQR(_ code: String) {
        pairingURI = code
        showScanner = false
        pair()
    }

    // MARK: - Proposal

    func approveProposal() {
        guard let proposal = pendingProposal, let address = ethereumAddress else { return }
        Task {
            do {
                try await wc.approveProposal(proposal, address: address)
                await MainActor.run {
                    showProposal = false
                    pendingProposal = nil
                    refreshSessions()
                }
            } catch {
                await MainActor.run { pairingError = error.localizedDescription }
            }
        }
    }

    func rejectProposal() {
        guard let proposal = pendingProposal else { return }
        Task {
            try? await wc.rejectProposal(proposal)
            await MainActor.run {
                showProposal = false
                pendingProposal = nil
            }
        }
    }

    // MARK: - Request

    func processRequest(_ request: Request) {
        pendingRequest = request
        displayModel = nil
        requestError = nil
        rawRequestJSON = nil

        let method = request.method

        if method == "eth_sendTransaction" {
            processTransaction(request)
        } else if method == "eth_signTypedData" || method == "eth_signTypedData_v4" {
            processTypedData(request)
        } else {
            rawRequestJSON = prettyJSON(request.params)
            requestError = "Unsupported method: \(method)"
        }
        showRequest = true
    }

    func rejectRequest() {
        guard let request = pendingRequest else { return }
        Task {
            try? await wc.rejectRequest(request)
            await MainActor.run {
                showRequest = false
                pendingRequest = nil
                displayModel = nil
                requestError = nil
                rawRequestJSON = nil
            }
        }
    }

    func refreshSessions() {
        guard wcConfigured else { return }
        Task {
            let sessions = await wc.sessions
            await MainActor.run { activeSessions = sessions }
        }
    }

    // MARK: - Private

    private func processTransaction(_ request: Request) {
        guard let paramsArray = try? request.params.get([TransactionParams].self),
              let tx = paramsArray.first else {
            requestError = "Could not parse transaction params"
            rawRequestJSON = prettyJSON(request.params)
            return
        }

        rawRequestJSON = prettyJSON(request.params)

        let chainRef = request.chainId
        let chainId = UInt64(chainRef.reference) ?? 1

        let calldata = tx.data ?? "0x"
        let result = clearSigning.formatCalldata(
            chainId: chainId,
            to: tx.to,
            calldata: calldata,
            value: tx.value,
            from: tx.from
        )

        switch result {
        case .success(let model):
            displayModel = model
        case .failure(let error):
            requestError = error.localizedDescription
        }
    }

    private func processTypedData(_ request: Request) {
        guard let paramsArray = try? request.params.get([String].self),
              paramsArray.count >= 2 else {
            requestError = "Could not parse typed data params"
            rawRequestJSON = prettyJSON(request.params)
            return
        }

        let typedDataJson = paramsArray[1]
        rawRequestJSON = typedDataJson

        let result = clearSigning.formatTypedData(typedDataJson: typedDataJson)
        switch result {
        case .success(let model):
            displayModel = model
        case .failure(let error):
            requestError = error.localizedDescription
        }
    }

    private func listenForProposals() {
        Task {
            for await proposal in await wc.sessionProposals {
                await MainActor.run {
                    pendingProposal = proposal
                    showProposal = true
                }
            }
        }
    }

    private func listenForRequests() {
        Task {
            for await request in await wc.sessionRequests {
                await MainActor.run {
                    processRequest(request)
                }
            }
        }
    }

    private func prettyJSON(_ value: AnyCodable) -> String? {
        guard let data = try? JSONEncoder().encode(value) else { return nil }
        guard let obj = try? JSONSerialization.jsonObject(with: data),
              let pretty = try? JSONSerialization.data(withJSONObject: obj, options: .prettyPrinted) else {
            return String(data: data, encoding: .utf8)
        }
        return String(data: pretty, encoding: .utf8)
    }
}

// MARK: - Transaction params

private struct TransactionParams: Codable {
    let from: String?
    let to: String
    let data: String?
    let value: String?
    let gas: String?
    let gasPrice: String?
}
