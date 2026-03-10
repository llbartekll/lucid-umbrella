import Foundation
import secp256k1

struct KeyManager {
    private static let storageKey = "wallet.privateKeyHex"

    let privateKeyHex: String
    let ethereumAddress: String

    init(privateKeyHex hex: String) throws {
        let cleaned = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
        guard cleaned.count == 64, let keyData = Data(hexString: cleaned) else {
            throw KeyError.invalidPrivateKey
        }
        let sk = try secp256k1.Signing.PrivateKey(dataRepresentation: keyData, format: .uncompressed)
        let pubBytes = sk.publicKey.dataRepresentation
        // Drop the 0x04 prefix byte, keccak256 the remaining 64 bytes
        let hashInput = pubBytes.dropFirst()
        let hash = keccak256(Data(hashInput))
        let addressBytes = hash.suffix(20)
        let address = EIP55.checksum(addressBytes)

        self.privateKeyHex = cleaned
        self.ethereumAddress = address
    }

    func save() {
        UserDefaults.standard.set(privateKeyHex, forKey: Self.storageKey)
    }

    static func restore() -> KeyManager? {
        guard let hex = UserDefaults.standard.string(forKey: storageKey) else { return nil }
        return try? KeyManager(privateKeyHex: hex)
    }

    static func clear() {
        UserDefaults.standard.removeObject(forKey: storageKey)
    }
}

enum KeyError: LocalizedError {
    case invalidPrivateKey

    var errorDescription: String? {
        switch self {
        case .invalidPrivateKey: return "Invalid private key (expected 32 hex bytes)"
        }
    }
}

// MARK: - Keccak-256

/// Alias for cross-file access.
func KeyManager_keccak256(_ data: Data) -> Data { keccak256(data) }

/// Minimal Keccak-256 implementation (FIPS 202 / SHA-3, rate=1088, capacity=512).
func keccak256(_ data: Data) -> Data {
    let rate = 136 // 1088 / 8
    var state = [UInt64](repeating: 0, count: 25)

    // Padding: append 0x01, pad to rate, set last byte |= 0x80
    var message = Array(data)
    message.append(0x01)
    let padLen = rate - (message.count % rate)
    message.append(contentsOf: [UInt8](repeating: 0, count: padLen))
    message[message.count - 1] |= 0x80

    // Absorb
    for blockStart in stride(from: 0, to: message.count, by: rate) {
        for i in 0..<(rate / 8) {
            let offset = blockStart + i * 8
            var word: UInt64 = 0
            for b in 0..<8 { word |= UInt64(message[offset + b]) << (b * 8) }
            state[i] ^= word
        }
        keccakF1600(&state)
    }

    // Squeeze 32 bytes
    var result = Data(count: 32)
    for i in 0..<4 {
        var w = state[i]
        for b in 0..<8 {
            result[i * 8 + b] = UInt8(w & 0xFF)
            w >>= 8
        }
    }
    return result
}

private func keccakF1600(_ state: inout [UInt64]) {
    let rc: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    let rotations: [Int] = [
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14,
    ]
    let piLane: [Int] = [
         0, 10,  7, 11, 17,
        20,  4,  1,  5,  8,
        15, 23,  2, 13, 24,
        21, 16,  3, 19, 12,
        14, 22,  9,  6, 18,
    ]

    for round in 0..<24 {
        // θ
        var c = [UInt64](repeating: 0, count: 5)
        for x in 0..<5 { c[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20] }
        for x in 0..<5 {
            let d = c[(x+4)%5] ^ rotl64(c[(x+1)%5], 1)
            for y in stride(from: 0, to: 25, by: 5) { state[y+x] ^= d }
        }
        // ρ and π
        var temp = [UInt64](repeating: 0, count: 25)
        for i in 0..<25 { temp[piLane[i]] = rotl64(state[i], rotations[i]) }
        // χ
        for y in stride(from: 0, to: 25, by: 5) {
            for x in 0..<5 {
                state[y+x] = temp[y+x] ^ (~temp[y+(x+1)%5] & temp[y+(x+2)%5])
            }
        }
        // ι
        state[0] ^= rc[round]
    }
}

private func rotl64(_ x: UInt64, _ n: Int) -> UInt64 {
    (x << n) | (x >> (64 - n))
}

// MARK: - EIP-55 Checksum

enum EIP55 {
    static func checksum(_ addressBytes: Data) -> String {
        let hexAddr = addressBytes.map { String(format: "%02x", $0) }.joined()
        let hash = keccak256(Data(hexAddr.utf8))
        var result = "0x"
        for (i, char) in hexAddr.enumerated() {
            let hashByte = hash[i / 2]
            let nibble = (i % 2 == 0) ? (hashByte >> 4) : (hashByte & 0x0F)
            result.append(nibble >= 8 ? char.uppercased() : String(char))
        }
        return result
    }
}

// MARK: - Data hex helpers

extension Data {
    init?(hexString: String) {
        let hex = hexString.hasPrefix("0x") ? String(hexString.dropFirst(2)) : hexString
        guard hex.count % 2 == 0 else { return nil }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
