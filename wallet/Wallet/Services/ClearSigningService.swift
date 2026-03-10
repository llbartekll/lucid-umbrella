import Foundation
import Erc7730

struct ClearSigningService {

    /// Format a contract call using the ERC-7730 library.
    /// Resolves descriptors from the GitHub registry internally.
    func formatCalldata(
        chainId: UInt64,
        to: String,
        calldata: String,
        value: String?,
        from: String?
    ) -> Result<DisplayModel, Error> {
        do {
            let model = try erc7730Format(
                chainId: chainId,
                to: to,
                calldataHex: calldata,
                valueHex: value,
                fromAddress: from,
                tokens: []
            )
            return .success(model)
        } catch {
            return .failure(error)
        }
    }

    /// Format EIP-712 typed data.
    /// Resolves descriptors from the GitHub registry internally.
    func formatTypedData(typedDataJson: String) -> Result<DisplayModel, Error> {
        do {
            let model = try erc7730FormatTyped(
                typedDataJson: typedDataJson,
                tokens: []
            )
            return .success(model)
        } catch {
            return .failure(error)
        }
    }
}
