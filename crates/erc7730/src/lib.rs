pub mod address_book;
pub mod decoder;
pub mod eip712;
pub mod engine;
pub mod error;
pub mod resolver;
pub mod token;
pub mod types;

use error::Error;

// Re-exports for convenience
pub use engine::{DisplayEntry, DisplayItem, DisplayModel};
pub use resolver::{DescriptorSource, ResolvedDescriptor};
pub use token::{TokenMeta, TokenSource};
pub use types::descriptor::Descriptor;

/// Format contract calldata for clear signing display.
///
/// This is the main entry point for calldata clear signing.
/// It parses the function signature from the descriptor's format keys,
/// decodes the calldata, and renders the display model.
pub fn format_calldata(
    descriptor: &Descriptor,
    chain_id: u64,
    to: &str,
    calldata: &[u8],
    value: Option<&[u8]>,
    token_source: &dyn TokenSource,
) -> Result<DisplayModel, Error> {
    if calldata.len() < 4 {
        return Err(Error::Decode(error::DecodeError::CalldataTooShort {
            expected: 4,
            actual: calldata.len(),
        }));
    }

    let actual_selector = &calldata[..4];

    // Find matching format key and parse its signature
    let (sig, _format_key) = find_matching_signature(descriptor, actual_selector)?;

    // Decode calldata using the parsed signature
    let decoded = decoder::decode_calldata(&sig, calldata)?;

    // Render the display model
    engine::format_calldata(descriptor, chain_id, to, &decoded, value, token_source)
}

/// Format EIP-712 typed data for clear signing display.
pub fn format_typed_data(
    descriptor: &Descriptor,
    data: &eip712::TypedData,
    token_source: &dyn TokenSource,
) -> Result<DisplayModel, Error> {
    eip712::format_typed_data(descriptor, data, token_source)
}

/// High-level convenience: resolve descriptor then format calldata.
pub fn format(
    chain_id: u64,
    to: &str,
    calldata: &[u8],
    value: Option<&[u8]>,
    source: &dyn DescriptorSource,
    tokens: &dyn TokenSource,
) -> Result<DisplayModel, Error> {
    let resolved = source.resolve_calldata(chain_id, to)?;
    format_calldata(&resolved.descriptor, chain_id, to, calldata, value, tokens)
}

/// Find a format key whose signature matches the calldata selector.
fn find_matching_signature(
    descriptor: &Descriptor,
    actual_selector: &[u8],
) -> Result<(decoder::FunctionSignature, String), Error> {
    for key in descriptor.display.formats.keys() {
        if key.contains('(') {
            match decoder::parse_signature(key) {
                Ok(sig) => {
                    if sig.selector[..] == actual_selector[..4] {
                        return Ok((sig, key.clone()));
                    }
                }
                Err(_) => continue,
            }
        }
    }

    Err(Error::Render(format!(
        "no matching format key for selector 0x{}",
        hex::encode(&actual_selector[..4])
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{EmptyTokenSource, StaticTokenSource};

    fn test_descriptor_json() -> &'static str {
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

    #[test]
    fn test_full_calldata_pipeline() {
        let descriptor = Descriptor::from_json(test_descriptor_json()).unwrap();
        let sig = decoder::parse_signature("transfer(address,uint256)").unwrap();

        // Build calldata: transfer(0x0000...0001, 1000)
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&sig.selector);
        let mut addr_word = [0u8; 32];
        addr_word[31] = 1;
        calldata.extend_from_slice(&addr_word);
        let mut amount_word = [0u8; 32];
        amount_word[30] = 0x03;
        amount_word[31] = 0xe8;
        calldata.extend_from_slice(&amount_word);

        let tokens = EmptyTokenSource;
        let result = format_calldata(
            &descriptor,
            1,
            "0xdac17f958d2ee523a2206206994597c13d831ec7",
            &calldata,
            None,
            &tokens,
        )
        .unwrap();

        assert_eq!(result.intent, "Transfer tokens");
        assert_eq!(result.entries.len(), 2);

        if let DisplayEntry::Item(ref item) = result.entries[0] {
            assert_eq!(item.label, "To");
            assert_eq!(item.value, "0x0000000000000000000000000000000000000001");
        } else {
            panic!("expected Item");
        }

        if let DisplayEntry::Item(ref item) = result.entries[1] {
            assert_eq!(item.label, "Amount");
            assert_eq!(item.value, "1000");
        } else {
            panic!("expected Item");
        }
    }

    #[test]
    fn test_full_pipeline_with_token_amount() {
        let json = r#"{
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
                        "interpolatedIntent": "Send ${@.1} to ${@.0}",
                        "fields": [
                            {
                                "path": "@.0",
                                "label": "To",
                                "format": "addressName"
                            },
                            {
                                "path": "@.1",
                                "label": "Amount",
                                "format": "tokenAmount",
                                "params": {
                                    "tokenPath": "@.0"
                                }
                            }
                        ]
                    }
                }
            }
        }"#;

        let descriptor = Descriptor::from_json(json).unwrap();
        let sig = decoder::parse_signature("transfer(address,uint256)").unwrap();

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&sig.selector);
        // token address
        let token_addr =
            hex::decode("000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7")
                .unwrap();
        calldata.extend_from_slice(&token_addr);
        // amount: 1_000_000 (1 USDT with 6 decimals)
        let mut amount_word = [0u8; 32];
        amount_word[29] = 0x0f;
        amount_word[30] = 0x42;
        amount_word[31] = 0x40;
        calldata.extend_from_slice(&amount_word);

        let mut tokens = StaticTokenSource::new();
        tokens.insert(
            1,
            "0xdac17f958d2ee523a2206206994597c13d831ec7",
            TokenMeta {
                symbol: "USDT".to_string(),
                decimals: 6,
                name: "Tether USD".to_string(),
            },
        );

        let result = format_calldata(
            &descriptor,
            1,
            "0xdac17f958d2ee523a2206206994597c13d831ec7",
            &calldata,
            None,
            &tokens,
        )
        .unwrap();

        assert_eq!(result.intent, "Transfer tokens");

        // The "To" field should resolve to "Tether USD" via address book (contractName)
        if let DisplayEntry::Item(ref item) = result.entries[0] {
            assert_eq!(item.label, "To");
            assert_eq!(item.value, "Tether USD");
        }

        // The amount should be formatted with token decimals
        if let DisplayEntry::Item(ref item) = result.entries[1] {
            assert_eq!(item.label, "Amount");
            assert_eq!(item.value, "1 USDT");
        }
    }

    #[test]
    fn test_visibility_rules() {
        let json = r#"{
            "context": {
                "contract": {
                    "deployments": [
                        { "chainId": 1, "address": "0xabc" }
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
                    "foo(uint256,uint256)": {
                        "intent": "Test visibility",
                        "fields": [
                            {
                                "path": "@.0",
                                "label": "Always visible",
                                "format": "number"
                            },
                            {
                                "path": "@.1",
                                "label": "Hidden",
                                "format": "number",
                                "visible": false
                            }
                        ]
                    }
                }
            }
        }"#;

        let descriptor = Descriptor::from_json(json).unwrap();
        let sig = decoder::parse_signature("foo(uint256,uint256)").unwrap();

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&sig.selector);
        calldata.extend_from_slice(&[0u8; 32]); // arg 0
        calldata.extend_from_slice(&[0u8; 32]); // arg 1

        let result =
            format_calldata(&descriptor, 1, "0xabc", &calldata, None, &EmptyTokenSource).unwrap();

        // Only 1 field should be visible (the second has visible: false)
        assert_eq!(result.entries.len(), 1);
        if let DisplayEntry::Item(ref item) = result.entries[0] {
            assert_eq!(item.label, "Always visible");
        }
    }

    #[test]
    fn test_field_group() {
        let json = r#"{
            "context": {
                "contract": {
                    "deployments": [
                        { "chainId": 1, "address": "0xabc" }
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
                    "foo(address,uint256)": {
                        "intent": "Test groups",
                        "fields": [
                            {
                                "fieldGroup": {
                                    "label": "Transfer Details",
                                    "fields": [
                                        {
                                            "path": "@.0",
                                            "label": "Recipient",
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
                        ]
                    }
                }
            }
        }"#;

        let descriptor = Descriptor::from_json(json).unwrap();
        let sig = decoder::parse_signature("foo(address,uint256)").unwrap();

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&sig.selector);
        let mut addr = [0u8; 32];
        addr[31] = 0x42;
        calldata.extend_from_slice(&addr);
        let mut amount = [0u8; 32];
        amount[31] = 100;
        calldata.extend_from_slice(&amount);

        let result =
            format_calldata(&descriptor, 1, "0xabc", &calldata, None, &EmptyTokenSource).unwrap();

        assert_eq!(result.entries.len(), 1);
        if let DisplayEntry::Group { label, items, .. } = &result.entries[0] {
            assert_eq!(label, "Transfer Details");
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].label, "Recipient");
            assert_eq!(items[1].label, "Amount");
            assert_eq!(items[1].value, "100");
        } else {
            panic!("expected Group");
        }
    }

    #[test]
    fn test_maps_lookup() {
        let json = r#"{
            "context": {
                "contract": {
                    "deployments": [
                        { "chainId": 1, "address": "0xabc" }
                    ]
                }
            },
            "metadata": {
                "owner": "test",
                "enums": {},
                "constants": {},
                "addressBook": {},
                "maps": {
                    "orderTypes": {
                        "entries": {
                            "0": "Market",
                            "1": "Limit",
                            "2": "Stop"
                        }
                    }
                }
            },
            "display": {
                "definitions": {},
                "formats": {
                    "placeOrder(uint256)": {
                        "intent": "Place order",
                        "fields": [
                            {
                                "path": "@.0",
                                "label": "Order Type",
                                "params": {
                                    "mapReference": "orderTypes"
                                }
                            }
                        ]
                    }
                }
            }
        }"#;

        let descriptor = Descriptor::from_json(json).unwrap();
        let sig = decoder::parse_signature("placeOrder(uint256)").unwrap();

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&sig.selector);
        let mut word = [0u8; 32];
        word[31] = 1; // value = 1 → "Limit"
        calldata.extend_from_slice(&word);

        let result =
            format_calldata(&descriptor, 1, "0xabc", &calldata, None, &EmptyTokenSource).unwrap();

        if let DisplayEntry::Item(ref item) = result.entries[0] {
            assert_eq!(item.label, "Order Type");
            assert_eq!(item.value, "Limit");
        } else {
            panic!("expected Item");
        }
    }

    #[test]
    fn test_high_level_format() {
        let descriptor = Descriptor::from_json(test_descriptor_json()).unwrap();
        let mut source = resolver::StaticSource::new();
        source.add_calldata(1, "0xdac17f958d2ee523a2206206994597c13d831ec7", descriptor);

        let sig = decoder::parse_signature("transfer(address,uint256)").unwrap();
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&sig.selector);
        calldata.extend_from_slice(&[0u8; 32]); // to
        calldata.extend_from_slice(&[0u8; 32]); // amount

        let result = format(
            1,
            "0xdac17f958d2ee523a2206206994597c13d831ec7",
            &calldata,
            None,
            &source,
            &EmptyTokenSource,
        )
        .unwrap();

        assert_eq!(result.intent, "Transfer tokens");
    }

    #[test]
    fn test_stakeweight_increase_unlock_time() {
        let json = r#"{
            "context": {
                "contract": {
                    "deployments": [
                        { "chainId": 10, "address": "0x521B4C065Bbdbe3E20B3727340730936912DfA46" }
                    ]
                }
            },
            "metadata": {
                "owner": "WalletConnect",
                "contractName": "StakeWeight",
                "enums": {},
                "constants": {},
                "addressBook": {},
                "maps": {}
            },
            "display": {
                "definitions": {},
                "formats": {
                    "increaseUnlockTime(uint256)": {
                        "intent": "Increase Unlock Time",
                        "interpolatedIntent": "Increase unlock time to ${@.0}",
                        "fields": [
                            {
                                "path": "@.0",
                                "label": "New Unlock Time",
                                "format": "date"
                            }
                        ]
                    }
                }
            }
        }"#;

        let descriptor = Descriptor::from_json(json).unwrap();
        // Real calldata from yttrium test
        let calldata =
            hex::decode("7c616fe6000000000000000000000000000000000000000000000000000000006945563d")
                .unwrap();

        let result = format_calldata(
            &descriptor,
            10,
            "0x521B4C065Bbdbe3E20B3727340730936912DfA46",
            &calldata,
            None,
            &EmptyTokenSource,
        )
        .unwrap();

        assert_eq!(result.intent, "Increase Unlock Time");
        assert_eq!(result.entries.len(), 1);
        if let DisplayEntry::Item(ref item) = result.entries[0] {
            assert_eq!(item.label, "New Unlock Time");
            assert_eq!(item.value, "2025-12-19 13:42:21 UTC");
        } else {
            panic!("expected Item");
        }
        assert_eq!(
            result.interpolated_intent.as_deref(),
            Some("Increase unlock time to 2025-12-19 13:42:21 UTC")
        );
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_eip712_format() {
        let json = r#"{
            "context": {
                "eip712": {
                    "deployments": [
                        { "chainId": 1, "address": "0xabc" }
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
                    "Permit": {
                        "intent": "Permit token spending",
                        "fields": [
                            {
                                "path": "spender",
                                "label": "Spender",
                                "format": "address"
                            },
                            {
                                "path": "value",
                                "label": "Amount",
                                "format": "number"
                            }
                        ]
                    }
                }
            }
        }"#;

        let descriptor = Descriptor::from_json(json).unwrap();
        let typed_data = eip712::TypedData {
            types: std::collections::HashMap::new(),
            primary_type: "Permit".to_string(),
            domain: eip712::TypedDataDomain {
                name: Some("USDT".to_string()),
                version: Some("1".to_string()),
                chain_id: Some(1),
                verifying_contract: Some("0xabc".to_string()),
            },
            message: serde_json::json!({
                "spender": "0x1234567890123456789012345678901234567890",
                "value": "1000000"
            }),
        };

        let result = format_typed_data(&descriptor, &typed_data, &EmptyTokenSource).unwrap();
        assert_eq!(result.intent, "Permit token spending");
        assert_eq!(result.entries.len(), 2);

        if let DisplayEntry::Item(ref item) = result.entries[0] {
            assert_eq!(item.label, "Spender");
            assert_eq!(item.value, "0x1234567890123456789012345678901234567890");
        }

        if let DisplayEntry::Item(ref item) = result.entries[1] {
            assert_eq!(item.label, "Amount");
            assert_eq!(item.value, "1000000");
        }
    }
}
