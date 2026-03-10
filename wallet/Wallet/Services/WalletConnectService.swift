import Foundation
import ReownWalletKit
import secp256k1

actor WalletConnectService {

    static let shared = WalletConnectService()

    private init() {}

    func configure(projectId: String) {
        let redirect = try! AppMetadata.Redirect(native: "wallet-demo://", universal: nil, linkMode: false)
        let metadata = AppMetadata(
            name: "ERC-7730 Wallet Demo",
            description: "Clear signing demo wallet",
            url: "https://github.com/nicklawls/lucid-umbrella",
            icons: [],
            redirect: redirect
        )
        Networking.configure(
            groupIdentifier: "group.com.lucidumbrella.wallet",
            projectId: projectId,
            socketFactory: DefaultSocketFactory()
        )
        WalletKit.configure(metadata: metadata, crypto: Secp256k1CryptoProvider())
    }

    func pair(uri: String) async throws {
        let wcUri = try WalletConnectURI(uriString: uri)
        try await WalletKit.instance.pair(uri: wcUri)
    }

    func approveProposal(_ proposal: Session.Proposal, address: String) async throws {
        let account = Account(blockchain: Blockchain("eip155:1")!, address: address)!
        let namespaces = try AutoNamespaces.build(
            sessionProposal: proposal,
            chains: [Blockchain("eip155:1")!],
            methods: ["eth_sendTransaction", "eth_signTypedData", "eth_signTypedData_v4", "personal_sign", "eth_sign"],
            events: ["chainChanged", "accountsChanged"],
            accounts: [account]
        )
        _ = try await WalletKit.instance.approve(proposalId: proposal.id, namespaces: namespaces)
    }

    func rejectProposal(_ proposal: Session.Proposal) async throws {
        try await WalletKit.instance.rejectSession(proposalId: proposal.id, reason: .userRejected)
    }

    func rejectRequest(_ request: Request) async throws {
        try await WalletKit.instance.respond(
            topic: request.topic,
            requestId: request.id,
            response: .error(JSONRPCError(code: 4001, message: "User rejected"))
        )
    }

    nonisolated var sessionProposals: AsyncStream<Session.Proposal> {
        AsyncStream { continuation in
            Task {
                for await (proposal, _) in WalletKit.instance.sessionProposalPublisher.values {
                    continuation.yield(proposal)
                }
            }
        }
    }

    nonisolated var sessionRequests: AsyncStream<Request> {
        AsyncStream { continuation in
            Task {
                for await (request, _) in WalletKit.instance.sessionRequestPublisher.values {
                    continuation.yield(request)
                }
            }
        }
    }

    var sessions: [Session] {
        WalletKit.instance.getSessions()
    }
}

// MARK: - CryptoProvider (required by WalletKit)

struct Secp256k1CryptoProvider: CryptoProvider {
    func recoverPubKey(signature: EthereumSignature, message: Data) throws -> Data {
        // Build 65-byte recovery signature: r (32) + s (32) + v (1)
        var sigBytes = Data(signature.r + signature.s)
        sigBytes.append(UInt8(signature.v % 27))
        let recoverySignature = try secp256k1.Recovery.ECDSASignature(dataRepresentation: sigBytes)
        // Note: uses SHA256 internally; Ethereum would need keccak256.
        // This demo app is review-only and never signs/verifies messages.
        let recoveredKey = try secp256k1.Recovery.PublicKey(message, signature: recoverySignature, format: .uncompressed)
        return recoveredKey.dataRepresentation
    }

    func keccak256(_ data: Data) -> Data {
        KeyManager_keccak256(data)
    }
}

// MARK: - Default Socket Factory

struct DefaultSocketFactory: WebSocketFactory {
    func create(with url: URL) -> WebSocketConnecting {
        URLSessionWebSocket(url: url)
    }
}

final class URLSessionWebSocket: NSObject, WebSocketConnecting, URLSessionWebSocketDelegate {
    var isConnected = false
    var onConnect: (() -> Void)?
    var onDisconnect: ((Error?) -> Void)?
    var onText: ((String) -> Void)?
    var request: URLRequest

    private var task: URLSessionWebSocketTask?
    private lazy var session: URLSession = URLSession(
        configuration: .default,
        delegate: self,
        delegateQueue: nil
    )

    init(url: URL) {
        self.request = URLRequest(url: url)
        super.init()
        self.task = session.webSocketTask(with: url)
    }

    func connect() {
        task?.resume()
        receiveMessage()
    }

    func disconnect() {
        task?.cancel(with: .normalClosure, reason: nil)
        isConnected = false
    }

    func write(string: String, completion: (() -> Void)?) {
        task?.send(.string(string)) { _ in
            completion?()
        }
    }

    private func receiveMessage() {
        task?.receive { [weak self] result in
            switch result {
            case .success(let message):
                if case .string(let text) = message {
                    self?.onText?(text)
                }
                self?.receiveMessage()
            case .failure:
                break
            }
        }
    }

    // MARK: URLSessionWebSocketDelegate

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask,
                    didOpenWithProtocol protocol: String?) {
        isConnected = true
        onConnect?()
    }

    func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask,
                    didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        isConnected = false
        onDisconnect?(nil)
    }
}
