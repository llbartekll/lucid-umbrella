import Foundation
import os
import ReownWalletKit
import secp256k1
import Starscream

private let log = Logger(subsystem: "com.lucidumbrella.wallet", category: "WalletConnectService")

actor WalletConnectService {

    static let shared = WalletConnectService()

    private init() {}

    func configure(projectId: String) {
        log.info("Networking.configure projectId=\(projectId) groupId=group.com.lucidumbrella.wallet")
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
        log.info("WalletKit configured")
    }

    func pair(uri: String) async throws {
        log.info("Pairing with URI: \(uri.prefix(40))...")
        let wcUri = try WalletConnectURI(uriString: uri)
        try await WalletKit.instance.pair(uri: wcUri)
        log.info("Pair call completed")
    }

    func approveProposal(_ proposal: Session.Proposal, address: String) async throws {
        let supportedMethods = Set(proposal.requiredNamespaces.flatMap { $0.value.methods } +
                                   (proposal.optionalNamespaces?.flatMap { $0.value.methods } ?? []))
        let supportedEvents = Set(proposal.requiredNamespaces.flatMap { $0.value.events } +
                                  (proposal.optionalNamespaces?.flatMap { $0.value.events } ?? []))

        let supportedRequiredChains = proposal.requiredNamespaces["eip155"]?.chains ?? []
        let supportedOptionalChains = proposal.optionalNamespaces?["eip155"]?.chains ?? []
        let supportedChains = supportedRequiredChains + supportedOptionalChains

        let accounts = supportedChains.map { Account(blockchain: $0, address: address)! }

        let namespaces = try AutoNamespaces.build(
            sessionProposal: proposal,
            chains: supportedChains,
            methods: Array(supportedMethods),
            events: Array(supportedEvents),
            accounts: accounts
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

    func disconnect(topic: String) async throws {
        try await WalletKit.instance.disconnect(topic: topic)
    }

    func disconnectAllSessions() async {
        let sessions = WalletKit.instance.getSessions()
        for session in sessions {
            do {
                try await WalletKit.instance.disconnect(topic: session.topic)
            } catch {
                log.error("Disconnect failed for topic \(session.topic.prefix(8)): \(error)")
            }
        }
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

    nonisolated var sessionDeletes: AsyncStream<(topic: String, reason: Reason)> {
        AsyncStream { continuation in
            Task {
                for await (topic, reason) in WalletKit.instance.sessionDeletePublisher.values {
                    continuation.yield((topic: topic, reason: reason))
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

// MARK: - Default Socket Factory (Starscream)

extension WebSocket: WebSocketConnecting { }

struct DefaultSocketFactory: WebSocketFactory {
    func create(with url: URL) -> WebSocketConnecting {
        let socket = WebSocket(url: url)
        let queue = DispatchQueue(label: "com.walletconnect.sdk.sockets", qos: .utility, attributes: .concurrent)
        socket.callbackQueue = queue
        return socket
    }
}
