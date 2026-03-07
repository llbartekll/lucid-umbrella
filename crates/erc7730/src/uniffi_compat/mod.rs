use crate::{
    eip712::TypedData,
    error::Error,
    format_calldata, format_typed_data,
    token::{StaticTokenSource, TokenMeta},
    types::descriptor::Descriptor,
    DisplayModel,
};

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TokenMetaInput {
    pub chain_id: u64,
    pub address: String,
    pub symbol: String,
    pub decimals: u8,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Enum)]
pub enum FfiError {
    #[error("invalid descriptor JSON: {0}")]
    InvalidDescriptorJson(String),
    #[error("invalid typed data JSON: {0}")]
    InvalidTypedDataJson(String),
    #[error("invalid calldata hex: {0}")]
    InvalidCalldataHex(String),
    #[error("invalid value hex: {0}")]
    InvalidValueHex(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("descriptor error: {0}")]
    Descriptor(String),
    #[error("resolve error: {0}")]
    Resolve(String),
    #[error("token registry error: {0}")]
    TokenRegistry(String),
    #[error("render error: {0}")]
    Render(String),
}

impl From<Error> for FfiError {
    fn from(value: Error) -> Self {
        match value {
            Error::Decode(err) => Self::Decode(err.to_string()),
            Error::Descriptor(err) => Self::Descriptor(err),
            Error::Resolve(err) => Self::Resolve(err.to_string()),
            Error::TokenRegistry(err) => Self::TokenRegistry(err),
            Error::Render(err) => Self::Render(err),
        }
    }
}

#[uniffi::export]
pub fn erc7730_format_calldata(
    descriptor_json: String,
    chain_id: u64,
    to: String,
    calldata_hex: String,
    value_hex: Option<String>,
    tokens: Vec<TokenMetaInput>,
) -> Result<DisplayModel, FfiError> {
    let descriptor = Descriptor::from_json(&descriptor_json)
        .map_err(|err| FfiError::InvalidDescriptorJson(err.to_string()))?;
    let calldata = decode_hex(&calldata_hex, HexContext::Calldata)?;
    let value = match value_hex {
        Some(hex_value) => Some(decode_hex(&hex_value, HexContext::Value)?),
        None => None,
    };

    let token_source = build_token_source(&tokens);
    format_calldata(
        &descriptor,
        chain_id,
        &to,
        &calldata,
        value.as_deref(),
        &token_source,
    )
    .map_err(Into::into)
}

#[uniffi::export]
pub fn erc7730_format_typed_data(
    descriptor_json: String,
    typed_data_json: String,
    tokens: Vec<TokenMetaInput>,
) -> Result<DisplayModel, FfiError> {
    let descriptor = Descriptor::from_json(&descriptor_json)
        .map_err(|err| FfiError::InvalidDescriptorJson(err.to_string()))?;
    let typed_data: TypedData = serde_json::from_str(&typed_data_json)
        .map_err(|err| FfiError::InvalidTypedDataJson(err.to_string()))?;

    let token_source = build_token_source(&tokens);
    format_typed_data(&descriptor, &typed_data, &token_source).map_err(Into::into)
}

enum HexContext {
    Calldata,
    Value,
}

fn decode_hex(input: &str, context: HexContext) -> Result<Vec<u8>, FfiError> {
    let trimmed = input.trim();
    let normalized = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    hex::decode(normalized).map_err(|err| match context {
        HexContext::Calldata => FfiError::InvalidCalldataHex(err.to_string()),
        HexContext::Value => FfiError::InvalidValueHex(err.to_string()),
    })
}

fn build_token_source(tokens: &[TokenMetaInput]) -> StaticTokenSource {
    let mut source = StaticTokenSource::new();
    for token in tokens {
        source.insert(
            token.chain_id,
            &token.address,
            TokenMeta {
                symbol: token.symbol.clone(),
                decimals: token.decimals,
                name: token.name.clone(),
            },
        );
    }
    source
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DisplayEntry;

    fn calldata_descriptor_json() -> &'static str {
        r#"{
            "context": {
                "contract": {
                    "deployments": [
                        { "chainId": 1, "address": "0xdac17f958d2ee523a2206206994597c13d831ec7" }
                    ]
                }
            },
            "metadata": {
                "owner": "test",
                "contractName": "Tether USD",
                "enums": {},
                "constants": {},
                "addressBook": {},
                "maps": {}
            },
            "display": {
                "definitions": {},
                "formats": {
                    "transfer(address,uint256)": {
                        "intent": "Transfer tokens",
                        "fields": [
                            {
                                "path": "@.0",
                                "label": "To",
                                "format": "address"
                            },
                            {
                                "path": "@.1",
                                "label": "Amount",
                                "format": "number"
                            }
                        ]
                    }
                }
            }
        }"#
    }

    fn typed_descriptor_json() -> &'static str {
        r#"{
            "context": {
                "eip712": {
                    "deployments": [
                        { "chainId": 1, "address": "0x0000000000000000000000000000000000000001" }
                    ]
                }
            },
            "metadata": {
                "owner": "test",
                "enums": {},
                "constants": {},
                "addressBook": {},
                "maps": {}
            },
            "display": {
                "definitions": {},
                "formats": {
                    "Mail": {
                        "intent": "Sign mail",
                        "fields": [
                            {
                                "path": "@.from",
                                "label": "From",
                                "format": "address"
                            },
                            {
                                "path": "@.contents",
                                "label": "Contents",
                                "format": "raw"
                            }
                        ]
                    }
                }
            }
        }"#
    }

    fn typed_data_json() -> &'static str {
        r#"{
            "types": {
                "EIP712Domain": [
                    { "name": "chainId", "type": "uint256" },
                    { "name": "verifyingContract", "type": "address" }
                ],
                "Mail": [
                    { "name": "from", "type": "address" },
                    { "name": "contents", "type": "string" }
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "chainId": 1,
                "verifyingContract": "0x0000000000000000000000000000000000000001"
            },
            "message": {
                "from": "0x0000000000000000000000000000000000000002",
                "contents": "hello"
            }
        }"#
    }

    fn transfer_calldata_hex() -> &'static str {
        "a9059cbb000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000003e8"
    }

    #[test]
    fn format_calldata_success() {
        let result = erc7730_format_calldata(
            calldata_descriptor_json().to_string(),
            1,
            "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
            transfer_calldata_hex().to_string(),
            None,
            vec![],
        )
        .expect("calldata formatting should succeed");

        assert_eq!(result.intent, "Transfer tokens");
        assert_eq!(result.entries.len(), 2);

        match &result.entries[0] {
            DisplayEntry::Item(item) => {
                assert_eq!(item.label, "To");
            }
            DisplayEntry::Group { .. } => {
                panic!("expected item entry");
            }
        }
    }

    #[test]
    fn format_typed_success() {
        let result = erc7730_format_typed_data(
            typed_descriptor_json().to_string(),
            typed_data_json().to_string(),
            vec![],
        )
        .expect("typed formatting should succeed");

        assert_eq!(result.intent, "Sign mail");
        assert_eq!(result.entries.len(), 2);
    }

    #[test]
    fn format_calldata_invalid_descriptor_json() {
        let err = erc7730_format_calldata(
            "{".to_string(),
            1,
            "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
            transfer_calldata_hex().to_string(),
            None,
            vec![],
        )
        .expect_err("invalid descriptor should fail");

        assert!(matches!(err, FfiError::InvalidDescriptorJson(_)));
    }

    #[test]
    fn format_typed_invalid_typed_data_json() {
        let err =
            erc7730_format_typed_data(typed_descriptor_json().to_string(), "{".to_string(), vec![])
                .expect_err("invalid typed data should fail");

        assert!(matches!(err, FfiError::InvalidTypedDataJson(_)));
    }

    #[test]
    fn format_calldata_invalid_calldata_hex() {
        let err = erc7730_format_calldata(
            calldata_descriptor_json().to_string(),
            1,
            "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
            "zz".to_string(),
            None,
            vec![],
        )
        .expect_err("invalid calldata hex should fail");

        assert!(matches!(err, FfiError::InvalidCalldataHex(_)));
    }

    #[test]
    fn format_calldata_invalid_value_hex() {
        let err = erc7730_format_calldata(
            calldata_descriptor_json().to_string(),
            1,
            "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
            transfer_calldata_hex().to_string(),
            Some("zz".to_string()),
            vec![],
        )
        .expect_err("invalid value hex should fail");

        assert!(matches!(err, FfiError::InvalidValueHex(_)));
    }

    #[test]
    fn format_calldata_accepts_0x_prefix() {
        let no_prefix = erc7730_format_calldata(
            calldata_descriptor_json().to_string(),
            1,
            "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
            transfer_calldata_hex().to_string(),
            None,
            vec![],
        )
        .expect("no-prefix calldata should succeed");

        let with_prefix = erc7730_format_calldata(
            calldata_descriptor_json().to_string(),
            1,
            "0xdac17f958d2ee523a2206206994597c13d831ec7".to_string(),
            format!("0x{}", transfer_calldata_hex()),
            Some("0x00".to_string()),
            vec![],
        )
        .expect("prefixed calldata should succeed");

        assert_eq!(no_prefix.intent, with_prefix.intent);
        assert_eq!(no_prefix.entries.len(), with_prefix.entries.len());
    }
}
