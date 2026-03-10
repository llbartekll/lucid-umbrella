import Foundation
import Erc7730

struct ClearSigningService {

    /// Format a contract call using the ERC-7730 library.
    /// Builds a minimal descriptor for the target contract and relies on
    /// graceful degradation for unknown selectors (raw hex preview).
    func formatCalldata(
        chainId: UInt64,
        to: String,
        calldata: String,
        value: String?,
        from: String?
    ) -> Result<DisplayModel, Error> {
        let descriptor = minimalDescriptor(chainId: chainId, to: to)
        do {
            let model = try erc7730FormatCalldata(
                descriptorJson: descriptor,
                chainId: chainId,
                to: to,
                calldataHex: calldata,
                valueHex: value,
                tokens: []
            )
            return .success(model)
        } catch {
            return .failure(error)
        }
    }

    /// Format EIP-712 typed data.
    func formatTypedData(typedDataJson: String) -> Result<DisplayModel, Error> {
        let descriptor = emptyDescriptor()
        do {
            let model = try erc7730FormatTypedData(
                descriptorJson: descriptor,
                typedDataJson: typedDataJson,
                tokens: []
            )
            return .success(model)
        } catch {
            return .failure(error)
        }
    }

    // MARK: - Private

    private func minimalDescriptor(chainId: UInt64, to: String) -> String {
        """
        {
            "context": {
                "contract": {
                    "deployments": [
                        { "chainId": \(chainId), "address": "\(to.lowercased())" }
                    ]
                }
            },
            "metadata": {
                "owner": "wallet-demo",
                "contractName": "Unknown",
                "enums": {},
                "constants": {},
                "addressBook": {},
                "maps": {}
            },
            "display": {
                "definitions": {},
                "formats": {}
            }
        }
        """
    }

    private func emptyDescriptor() -> String {
        """
        {
            "context": {
                "contract": {
                    "deployments": []
                }
            },
            "metadata": {
                "owner": "wallet-demo",
                "contractName": "Unknown",
                "enums": {},
                "constants": {},
                "addressBook": {},
                "maps": {}
            },
            "display": {
                "definitions": {},
                "formats": {}
            }
        }
        """
    }
}
