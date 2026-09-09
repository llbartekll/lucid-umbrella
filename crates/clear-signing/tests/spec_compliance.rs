//! Tests for ERC-7730 spec compliance gaps identified in the audit.

use clear_signing::decoder;
use clear_signing::eip712::TypedData;
use clear_signing::engine::{DisplayEntry, DisplayModel, GroupIteration};
use clear_signing::merge::merge_descriptor_values;
use clear_signing::provider::{DataProvider, EmptyDataProvider};
use clear_signing::token::{StaticTokenSource, TokenMeta};
use clear_signing::types::descriptor::Descriptor;
use clear_signing::{
    format_calldata, format_typed_data, merge_descriptors, FallbackReason, FormatOutcome,
    ResolvedDescriptor, TransactionContext,
};
use std::future::Future;
use std::pin::Pin;
use tiny_keccak::{Hasher, Keccak};

fn wrap_rd(descriptor: Descriptor, chain_id: u64, address: &str) -> Vec<ResolvedDescriptor> {
    vec![ResolvedDescriptor {
        descriptor,
        chain_id,
        address: address.to_lowercase(),
    }]
}

fn build_calldata(sig_str: &str, words: &[[u8; 32]]) -> Vec<u8> {
    let sig = decoder::parse_signature(sig_str).unwrap();
    let mut calldata = Vec::new();
    calldata.extend_from_slice(&sig.selector);
    for word in words {
        calldata.extend_from_slice(word);
    }
    calldata
}

fn build_single_bytes_calldata(sig_str: &str, bytes: &[u8]) -> Vec<u8> {
    let sig = decoder::parse_signature(sig_str).unwrap();
    let mut calldata = Vec::new();
    calldata.extend_from_slice(&sig.selector);

    let mut offset = [0u8; 32];
    offset[31] = 0x20;
    calldata.extend_from_slice(&offset);

    let mut len = [0u8; 32];
    len[24..32].copy_from_slice(&(bytes.len() as u64).to_be_bytes());
    calldata.extend_from_slice(&len);
    calldata.extend_from_slice(bytes);

    let padding = (32 - (bytes.len() % 32)) % 32;
    calldata.extend(std::iter::repeat_n(0u8, padding));
    calldata
}

fn uint_word(val: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&val.to_be_bytes());
    word
}

fn uint_hex_literal(val: u64) -> String {
    format!("0x{}", hex::encode(uint_word(val)))
}

fn addr_word(addr_hex: &str) -> [u8; 32] {
    let bytes = hex::decode(addr_hex.strip_prefix("0x").unwrap_or(addr_hex)).unwrap();
    let mut word = [0u8; 32];
    word[12..32].copy_from_slice(&bytes);
    word
}

fn dynamic_offset_word(offset: usize) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&(offset as u64).to_be_bytes());
    word
}

fn encode_address_array(addrs: &[&str]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&uint_word(addrs.len() as u64));
    for addr in addrs {
        encoded.extend_from_slice(&addr_word(addr));
    }
    encoded
}

fn encode_uint_array(values: &[u64]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&uint_word(values.len() as u64));
    for value in values {
        encoded.extend_from_slice(&uint_word(*value));
    }
    encoded
}

fn build_two_array_calldata(sig_str: &str, addrs: &[&str], values: &[u64]) -> Vec<u8> {
    let sig = decoder::parse_signature(sig_str).unwrap();
    let addresses_encoded = encode_address_array(addrs);
    let values_encoded = encode_uint_array(values);
    let addresses_offset = 64usize;
    let values_offset = addresses_offset + addresses_encoded.len();

    let mut calldata = Vec::new();
    calldata.extend_from_slice(&sig.selector);
    calldata.extend_from_slice(&dynamic_offset_word(addresses_offset));
    calldata.extend_from_slice(&dynamic_offset_word(values_offset));
    calldata.extend_from_slice(&addresses_encoded);
    calldata.extend_from_slice(&values_encoded);
    calldata
}

fn keccak256_test(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

fn address_word(addr_hex: &str) -> [u8; 32] {
    let bytes = hex::decode(addr_hex.strip_prefix("0x").unwrap_or(addr_hex)).unwrap();
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(&bytes);
    word
}

fn bytes32_word(hex_value: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_value.strip_prefix("0x").unwrap_or(hex_value)).unwrap();
    let mut word = [0u8; 32];
    word[..bytes.len()].copy_from_slice(&bytes);
    word
}

fn assert_interpolation_warning(result: &FormatOutcome, expected_detail: &str) {
    assert!(
        result.interpolated_intent.is_none(),
        "expected interpolated intent to be skipped"
    );
    assert!(
        result
            .diagnostics()
            .iter()
            .any(|warning| warning.code == "interpolated_intent_skipped"),
        "missing interpolation skip diagnostic code: {:?}",
        result.diagnostics()
    );
    assert!(
        result
            .diagnostics()
            .iter()
            .any(|warning| warning.message.contains("interpolated intent skipped")),
        "missing interpolation skip warning: {:?}",
        result.diagnostics()
    );
    assert!(
        result
            .diagnostics()
            .iter()
            .any(|warning| warning.message.contains(expected_detail)),
        "missing interpolation warning detail '{expected_detail}': {:?}",
        result.diagnostics()
    );
}

fn domain_separator_hex(
    type_signature: &str,
    name: &str,
    version: &str,
    chain_id: u64,
    verifying_contract: &str,
    extra_fields: &[([u8; 32], &str)],
) -> String {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&keccak256_test(type_signature.as_bytes()));
    encoded.extend_from_slice(&keccak256_test(name.as_bytes()));
    encoded.extend_from_slice(&keccak256_test(version.as_bytes()));
    encoded.extend_from_slice(&uint_word(chain_id));
    encoded.extend_from_slice(&address_word(verifying_contract));
    for (word, field_type) in extra_fields {
        if *field_type == "string" || *field_type == "bytes" {
            encoded.extend_from_slice(&keccak256_test(word));
        } else {
            encoded.extend_from_slice(word);
        }
    }
    format!("0x{}", hex::encode(keccak256_test(&encoded)))
}

struct BlockTimestampProvider(Option<u64>);

impl DataProvider for BlockTimestampProvider {
    fn resolve_block_timestamp(
        &self,
        _chain_id: u64,
        _block_number: u64,
    ) -> Pin<Box<dyn Future<Output = Option<u64>> + Send + '_>> {
        Box::pin(async move { self.0 })
    }
}

fn semantic_item_snapshot(entries: &[DisplayEntry]) -> Vec<(String, String)> {
    let mut snapshot = Vec::new();
    for entry in entries {
        match entry {
            DisplayEntry::Item(item) => {
                snapshot.push((item.label.clone(), item.value.clone()));
            }
            DisplayEntry::Group { items, .. } => {
                snapshot.extend(
                    items
                        .iter()
                        .map(|item| (item.label.clone(), item.value.clone())),
                );
            }
            DisplayEntry::Nested { label, intent, .. } => {
                snapshot.push((label.clone(), intent.clone()));
            }
        }
    }
    snapshot
}

/// `raw_encrypted_value` per rendered item, in order.
fn raw_encrypted_values(entries: &[DisplayEntry]) -> Vec<Option<String>> {
    entries
        .iter()
        .flat_map(|entry| match entry {
            DisplayEntry::Item(item) => vec![item.raw_encrypted_value.clone()],
            DisplayEntry::Group { items, .. } => items
                .iter()
                .map(|i| i.raw_encrypted_value.clone())
                .collect(),
            DisplayEntry::Nested { .. } => vec![None],
        })
        .collect()
}

fn assert_semantic_parity(calldata_model: &DisplayModel, typed_model: &DisplayModel) {
    assert_eq!(calldata_model.intent, typed_model.intent);
    assert_eq!(
        semantic_item_snapshot(&calldata_model.entries),
        semantic_item_snapshot(&typed_model.entries)
    );
}

async fn assert_invalid_typed_numeric_format_error(
    format_name: &str,
    params: Option<serde_json::Value>,
    bad_value: serde_json::Value,
    error_substr: &str,
) {
    let field = match params {
        Some(params) => serde_json::json!({
            "path": "value",
            "label": "Value",
            "format": format_name,
            "params": params
        }),
        None => serde_json::json!({
            "path": "value",
            "label": "Value",
            "format": format_name
        }),
    };

    let descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}]
                }
            },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": {
                "definitions": {},
                "formats": {
                    "Example(string value)": {
                        "intent": "Example",
                        "fields": [field]
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Example": [{ "name": "value", "type": "string" }]
        },
        "primaryType": "Example",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "value": bad_value }
    }))
    .unwrap();

    let err = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        err.contains(error_substr),
        "expected '{error_substr}' in error, got: {err}"
    );
}

// ─── #3: Duplicate selector rejection ───

#[tokio::test]
async fn test_duplicate_selector_rejected() {
    // Two format keys that resolve to the same selector
    let json = r#"{
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "transfer(address,uint256)": {
                    "intent": "Transfer 1",
                    "fields": [{"path": "@.0", "label": "To", "format": "address"}]
                },
                "transfer(address to,uint256 amount)": {
                    "intent": "Transfer 2",
                    "fields": [{"path": "to", "label": "To", "format": "address"}]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let calldata = build_calldata(
        "transfer(address,uint256)",
        &[
            addr_word("0x0000000000000000000000000000000000000001"),
            uint_word(100),
        ],
    );

    let descriptors = wrap_rd(descriptor, 1, "0xabc");
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let result = format_calldata(&descriptors, &tx, &EmptyDataProvider).await;
    // Should error due to duplicate selectors
    assert!(result.is_err(), "duplicate selectors should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("duplicate"),
        "error should mention duplicate: {err}"
    );
}

// ─── #1: EIP-712 Duration format ───

#[tokio::test]
async fn test_eip712_duration_format() {
    let json = r#"{
        "context": {
            "eip712": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "Lock(uint256 duration)": {
                    "intent": "Lock tokens",
                    "fields": [
                        {"path": "duration", "label": "Duration", "format": "duration"}
                    ]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {"EIP712Domain": [], "Lock": [{"name": "duration", "type": "uint256"}]},
        "primaryType": "Lock",
        "domain": {"chainId": 1, "verifyingContract": "0xabc"},
        "message": {"duration": 90061}
    }))
    .unwrap();

    let descriptors = wrap_rd(descriptor, 1, "0xabc");
    let result = format_typed_data(&descriptors, &typed_data, &EmptyDataProvider)
        .await
        .unwrap();
    if let DisplayEntry::Item(ref item) = result.entries[0] {
        assert_eq!(item.value, "25:01:01");
    } else {
        panic!("expected Item");
    }
}

// ─── #1: EIP-712 Unit format ───

#[tokio::test]
async fn test_eip712_unit_format() {
    let json = r#"{
        "context": {
            "eip712": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "SetRate(uint256 rate)": {
                    "intent": "Set rate",
                    "fields": [
                        {"path": "rate", "label": "Rate", "format": "unit", "params": {"base": "%", "decimals": 2}}
                    ]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {"EIP712Domain": [], "SetRate": [{"name": "rate", "type": "uint256"}]},
        "primaryType": "SetRate",
        "domain": {"chainId": 1, "verifyingContract": "0xabc"},
        "message": {"rate": 1250}
    }))
    .unwrap();

    let descriptors = wrap_rd(descriptor, 1, "0xabc");
    let result = format_typed_data(&descriptors, &typed_data, &EmptyDataProvider)
        .await
        .unwrap();
    if let DisplayEntry::Item(ref item) = result.entries[0] {
        assert_eq!(item.value, "12.5%");
    } else {
        panic!("expected Item");
    }
}

// ─── #1: EIP-712 NftName format ───

#[tokio::test]
async fn test_eip712_nft_name_format() {
    let json = r#"{
        "context": {
            "eip712": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "Transfer(uint256 tokenId)": {
                    "intent": "Transfer NFT",
                    "fields": [
                        {"path": "tokenId", "label": "Token", "format": "nftName", "params": {"collection": "0xdef"}}
                    ]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {"EIP712Domain": [], "Transfer": [{"name": "tokenId", "type": "uint256"}]},
        "primaryType": "Transfer",
        "domain": {"chainId": 1, "verifyingContract": "0xabc"},
        "message": {"tokenId": 42}
    }))
    .unwrap();

    let descriptors = wrap_rd(descriptor, 1, "0xabc");
    let result = format_typed_data(&descriptors, &typed_data, &EmptyDataProvider)
        .await
        .unwrap();
    if let DisplayEntry::Item(ref item) = result.entries[0] {
        // No collection resolver → fallback to "#42"
        assert_eq!(item.value, "#42");
    } else {
        panic!("expected Item");
    }
}

#[tokio::test]
async fn test_eip712_token_amount_rejects_invalid_numeric_string() {
    assert_invalid_typed_numeric_format_error(
        "tokenAmount",
        Some(serde_json::json!({
            "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        })),
        serde_json::json!("not-a-number"),
        "tokenAmount field must be an unsigned integer",
    )
    .await;
}

#[tokio::test]
async fn test_eip712_date_rejects_invalid_numeric_string() {
    assert_invalid_typed_numeric_format_error(
        "date",
        None,
        serde_json::json!("not-a-number"),
        "date field must be an integer",
    )
    .await;
}

#[tokio::test]
async fn test_eip712_chain_id_rejects_invalid_numeric_string() {
    assert_invalid_typed_numeric_format_error(
        "chainId",
        None,
        serde_json::json!("not-a-number"),
        "chainId field must be an unsigned integer",
    )
    .await;
}

#[tokio::test]
async fn test_eip712_duration_rejects_invalid_numeric_string() {
    assert_invalid_typed_numeric_format_error(
        "duration",
        None,
        serde_json::json!("not-a-number"),
        "duration field must be an unsigned integer",
    )
    .await;
}

#[tokio::test]
async fn test_eip712_unit_rejects_invalid_numeric_string() {
    assert_invalid_typed_numeric_format_error(
        "unit",
        Some(serde_json::json!({"base": "%", "decimals": 2})),
        serde_json::json!("not-a-number"),
        "unit field must be an unsigned integer",
    )
    .await;
}

// ─── #2: DisplayField with value (literal constant) ───

#[tokio::test]
async fn test_display_field_literal_value() {
    let json = r#"{
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "transfer(address,uint256)": {
                    "intent": "Transfer",
                    "fields": [
                        {"value": "ERC-20 Transfer", "label": "Type"},
                        {"path": "@.0", "label": "To", "format": "address"}
                    ]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let calldata = build_calldata(
        "transfer(address,uint256)",
        &[
            addr_word("0x0000000000000000000000000000000000000001"),
            uint_word(100),
        ],
    );

    let descriptors = wrap_rd(descriptor, 1, "0xabc");
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let result = format_calldata(&descriptors, &tx, &EmptyDataProvider)
        .await
        .unwrap();
    assert_eq!(result.entries.len(), 2);
    if let DisplayEntry::Item(ref item) = result.entries[0] {
        assert_eq!(item.label, "Type");
        assert_eq!(item.value, "ERC-20 Transfer");
    } else {
        panic!("expected Item");
    }
}

// ─── #4: Separator for array elements ───

#[tokio::test]
async fn test_separator_for_array_field() {
    // Test that the separator field is parsed (deserialization test)
    let field_json = r#"{
        "path": "items",
        "label": "Items",
        "format": "raw",
        "separator": " | "
    }"#;
    let field: clear_signing::types::display::DisplayField =
        serde_json::from_str(field_json).unwrap();
    if let clear_signing::types::display::DisplayField::Simple { separator, .. } = &field {
        assert_eq!(separator.as_deref(), Some(" | "));
    } else {
        panic!("expected Simple");
    }
}

// ─── #6: Signed integer handling ───

#[tokio::test]
async fn test_signed_integer_negative() {
    let json = r#"{
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "setDelta(int256)": {
                    "intent": "Set delta",
                    "fields": [
                        {"path": "@.0", "label": "Delta", "format": "number"}
                    ]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let sig = decoder::parse_signature("setDelta(int256)").unwrap();

    let mut calldata = Vec::new();
    calldata.extend_from_slice(&sig.selector);
    // -1 in two's complement (32 bytes of 0xFF)
    calldata.extend_from_slice(&[0xFF; 32]);

    let descriptors = wrap_rd(descriptor, 1, "0xabc");
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let result = format_calldata(&descriptors, &tx, &EmptyDataProvider)
        .await
        .unwrap();
    if let DisplayEntry::Item(ref item) = result.entries[0] {
        assert_eq!(item.value, "-1");
    } else {
        panic!("expected Item");
    }
}

#[tokio::test]
async fn test_signed_integer_negative_100() {
    let json = r#"{
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "setDelta(int256)": {
                    "intent": "Set delta",
                    "fields": [
                        {"path": "@.0", "label": "Delta", "format": "number"}
                    ]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let sig = decoder::parse_signature("setDelta(int256)").unwrap();

    let mut calldata = Vec::new();
    calldata.extend_from_slice(&sig.selector);
    // -100 in two's complement: 0xFFFFFFFF...FF9C
    let mut word = [0xFF; 32];
    word[31] = 0x9C; // 256 - 100 = 156 = 0x9C
    calldata.extend_from_slice(&word);

    let descriptors = wrap_rd(descriptor, 1, "0xabc");
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let result = format_calldata(&descriptors, &tx, &EmptyDataProvider)
        .await
        .unwrap();
    if let DisplayEntry::Item(ref item) = result.entries[0] {
        assert_eq!(item.value, "-100");
    } else {
        panic!("expected Item");
    }
}

// ─── #5: InteroperableAddressName stub ───

#[tokio::test]
async fn test_interoperable_address_name_deserialization() {
    let field_json = r#"{
        "path": "recipient",
        "label": "To",
        "format": "interoperableAddressName"
    }"#;
    let field: clear_signing::types::display::DisplayField =
        serde_json::from_str(field_json).unwrap();
    if let clear_signing::types::display::DisplayField::Simple { format, .. } = &field {
        assert!(matches!(
            format.as_ref(),
            Some(clear_signing::types::display::FieldFormat::InteroperableAddressName)
        ));
    } else {
        panic!("expected Simple");
    }
}

// ─── #7: Date with blockheight encoding ───

#[tokio::test]
async fn test_date_blockheight_encoding() {
    let json = r#"{
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "expireAt(uint256)": {
                    "intent": "Expire",
                    "fields": [
                        {"path": "@.0", "label": "Block", "format": "date", "params": {"encoding": "blockheight"}}
                    ]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let calldata = build_calldata("expireAt(uint256)", &[uint_word(19500000)]);

    let descriptors = wrap_rd(descriptor, 1, "0xabc");
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let result = format_calldata(
        &descriptors,
        &tx,
        &BlockTimestampProvider(Some(1_710_000_000)),
    )
    .await
    .unwrap();
    if let DisplayEntry::Item(ref item) = result.entries[0] {
        assert_eq!(item.value, "2024-03-09 16:00:00Z");
    } else {
        panic!("expected Item");
    }
}

#[tokio::test]
async fn test_date_blockheight_encoding_errors_without_provider_timestamp() {
    let json = r#"{
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "expireAt(uint256)": {
                    "intent": "Expire",
                    "fields": [
                        {"path": "@.0", "label": "Block", "format": "date", "params": {"encoding": "blockheight"}}
                    ]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let calldata = build_calldata("expireAt(uint256)", &[uint_word(19500000)]);

    let descriptors = wrap_rd(descriptor, 1, "0xabc");
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let err = format_calldata(&descriptors, &tx, &BlockTimestampProvider(None))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("approximate timestamp"));
}

// ─── #11: domainSeparator parsing ───

#[test]
fn test_domain_separator_parsing() {
    let json = r#"{
        "context": {
            "eip712": {
                "deployments": [{"chainId": 1, "address": "0xabc"}],
                "domainSeparator": "0x1234567890abcdef"
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {"definitions": {}, "formats": {}}
    }"#;
    let descriptor = Descriptor::from_json(json).unwrap();
    if let clear_signing::types::context::DescriptorContext::Eip712(ctx) = &descriptor.context {
        assert_eq!(
            ctx.eip712.domain_separator.as_deref(),
            Some("0x1234567890abcdef")
        );
    } else {
        panic!("expected Eip712 context");
    }
}

// ─── #12: Encryption fields parsing ───

#[test]
fn test_encryption_full_fields() {
    let json = r#"{
        "path": "secret",
        "label": "Secret",
        "params": {
            "encryption": {
                "scheme": "x25519-xsalsa20-poly1305",
                "plaintextType": "string",
                "fallbackLabel": "Encrypted content"
            }
        }
    }"#;
    let field: clear_signing::types::display::DisplayField = serde_json::from_str(json).unwrap();
    if let clear_signing::types::display::DisplayField::Simple { params, .. } = &field {
        let enc = params.as_ref().unwrap().encryption.as_ref().unwrap();
        assert_eq!(enc.scheme.as_deref(), Some("x25519-xsalsa20-poly1305"));
        assert_eq!(enc.plaintext_type.as_deref(), Some("string"));
        assert_eq!(enc.fallback_label.as_deref(), Some("Encrypted content"));
    } else {
        panic!("expected Simple");
    }
}

// ─── #10: Factory context parsing ───

#[test]
fn test_factory_context_parsing() {
    let json = r#"{
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}],
                "factory": {
                    "deployEvent": "ContractCreated(address)",
                    "deployments": [{"chainId": 1, "address": "0xfactory"}]
                }
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {"definitions": {}, "formats": {}}
    }"#;
    let descriptor = Descriptor::from_json(json).unwrap();
    if let clear_signing::types::context::DescriptorContext::Contract(ctx) = &descriptor.context {
        let factory = ctx.contract.factory.as_ref().unwrap();
        assert_eq!(
            factory.deploy_event.as_deref(),
            Some("ContractCreated(address)")
        );
        assert_eq!(factory.deployments.len(), 1);
        assert_eq!(factory.deployments[0].address, "0xfactory");
    } else {
        panic!("expected Contract context");
    }
}

// ─── #13: Array slice syntax ───

#[test]
fn test_eip712_array_slice_syntax() {
    let message = serde_json::json!({
        "items": ["a", "b", "c", "d", "e"]
    });

    // Test the resolve_typed_path function indirectly via TypedData
    let json = r#"{
        "context": {
            "eip712": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "Test": {
                    "intent": "Test",
                    "fields": [
                        {"path": "items[1:3]", "label": "Slice"}
                    ]
                }
            }
        }
    }"#;
    let _descriptor = Descriptor::from_json(json).unwrap();
    // The path parsing is tested through integration — here we just verify it parses
    let _ = message;
}

// ─── #14: Unit SI prefix ───

#[tokio::test]
async fn test_unit_si_prefix() {
    let json = r#"{
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "setGas(uint256)": {
                    "intent": "Set gas",
                    "fields": [
                        {"path": "@.0", "label": "Gas", "format": "unit", "params": {"base": "wei", "prefix": true}}
                    ]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let calldata = build_calldata("setGas(uint256)", &[uint_word(1_500_000)]);

    let descriptors = wrap_rd(descriptor, 1, "0xabc");
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let result = format_calldata(&descriptors, &tx, &EmptyDataProvider)
        .await
        .unwrap();
    if let DisplayEntry::Item(ref item) = result.entries[0] {
        assert_eq!(item.value, "1.5Mwei");
    } else {
        panic!("expected Item");
    }
}

// ─── #15: Maps keyPath ───

#[tokio::test]
async fn test_maps_key_path() {
    let json = r#"{
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {
            "owner": "test",
            "enums": {},
            "constants": {},
            "maps": {
                "orderTypes": {
                    "keyPath": "@.0",
                    "entries": {"0": "Market", "1": "Limit", "2": "Stop"}
                }
            }
        },
        "display": {
            "definitions": {},
            "formats": {
                "placeOrder(uint256,uint256)": {
                    "intent": "Place order",
                    "fields": [
                        {"path": "@.1", "label": "Order Type", "params": {"mapReference": "orderTypes"}}
                    ]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    // arg 0 = 1 (the key), arg 1 = 999 (the field value, not used as key)
    let calldata = build_calldata(
        "placeOrder(uint256,uint256)",
        &[uint_word(1), uint_word(999)],
    );

    let descriptors = wrap_rd(descriptor, 1, "0xabc");
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let result = format_calldata(&descriptors, &tx, &EmptyDataProvider)
        .await
        .unwrap();
    if let DisplayEntry::Item(ref item) = result.entries[0] {
        assert_eq!(item.label, "Order Type");
        assert_eq!(item.value, "Limit");
    } else {
        panic!("expected Item");
    }
}

#[tokio::test]
async fn test_eip712_maps_key_path_matches_calldata() {
    let metadata = serde_json::json!({
        "owner": "test",
        "enums": {},
        "constants": {},
        "maps": {
            "orderTypes": {
                "keyPath": "kind",
                "entries": {"0": "Market", "1": "Limit", "2": "Stop"}
            }
        }
    });
    let fields = serde_json::json!([
        {"path": "value", "label": "Order Type", "params": {"mapReference": "orderTypes"}}
    ]);

    let calldata_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": {
                "contract": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}]
                }
            },
            "metadata": metadata.clone(),
            "display": {
                "definitions": {},
                "formats": {
                    "placeOrder(uint256 kind,uint256 value)": {
                        "intent": "Place order",
                        "fields": fields.clone()
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let typed_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}]
                }
            },
            "metadata": metadata,
            "display": {
                "definitions": {},
                "formats": {
                    "PlaceOrder(uint256 kind,uint256 value)": {
                        "intent": "Place order",
                        "fields": fields
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let calldata = build_calldata(
        "placeOrder(uint256,uint256)",
        &[uint_word(1), uint_word(999)],
    );
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let calldata_result = format_calldata(
        &wrap_rd(calldata_descriptor, 1, "0xabc"),
        &tx,
        &EmptyDataProvider,
    )
    .await
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "PlaceOrder": [
                { "name": "kind", "type": "uint256" },
                { "name": "value", "type": "uint256" }
            ]
        },
        "primaryType": "PlaceOrder",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "kind": 1, "value": 999 }
    }))
    .unwrap();
    let typed_result = format_typed_data(
        &wrap_rd(typed_descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();

    assert_semantic_parity(&calldata_result, &typed_result);
}

// ─── #19: Intent as object ───

#[test]
fn test_intent_as_object() {
    let json = r#"{
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "transfer(address,uint256)": {
                    "intent": {"Action": "Transfer tokens", "Asset": "USDC"},
                    "fields": []
                }
            }
        }
    }"#;
    let descriptor = Descriptor::from_json(json).unwrap();
    let format = descriptor
        .display
        .formats
        .get("transfer(address,uint256)")
        .unwrap();
    let intent_str =
        clear_signing::types::display::intent_as_string(format.intent.as_ref().unwrap());
    assert_eq!(intent_str, "Action: Transfer tokens, Asset: USDC");
}

#[test]
fn test_invalid_nested_intent_object_is_rejected() {
    let json = r#"{
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "transfer(address,uint256)": {
                    "intent": {"Action": {"nested": "bad"}},
                    "fields": []
                }
            }
        }
    }"#;

    assert!(Descriptor::from_json(json).is_err());
}

#[tokio::test]
async fn test_direct_group_without_label_flattens_into_parent_entries() {
    let json = r#"{
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "foo(address,uint256)": {
                    "intent": "Grouped",
                    "fields": [{
                        "fields": [
                            {"path": "@.0", "label": "Recipient", "format": "address"},
                            {"path": "@.1", "label": "Amount", "format": "number"}
                        ]
                    }]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let calldata = build_calldata(
        "foo(address,uint256)",
        &[
            addr_word("0x0000000000000000000000000000000000000001"),
            uint_word(100),
        ],
    );

    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let result = format_calldata(&wrap_rd(descriptor, 1, "0xabc"), &tx, &EmptyDataProvider)
        .await
        .unwrap();

    assert_eq!(result.entries.len(), 2);
    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.label, "Recipient"),
        _ => panic!("expected flattened item"),
    }
}

#[tokio::test]
async fn test_calldata_bundled_group_zips_array_items() {
    let json = r#"{
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "batch(address[] recipients,uint256[] amounts)": {
                    "intent": "Batch",
                    "fields": [{
                        "label": "Transfers",
                        "iteration": "bundled",
                        "fields": [
                            {"path": "recipients.[]", "label": "Recipient", "format": "address"},
                            {"path": "amounts.[]", "label": "Amount", "format": "number"}
                        ]
                    }]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let calldata = build_two_array_calldata(
        "batch(address[],uint256[])",
        &[
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        ],
        &[100, 200],
    );
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };

    let result = format_calldata(&wrap_rd(descriptor, 1, "0xabc"), &tx, &EmptyDataProvider)
        .await
        .unwrap();
    match &result.entries[0] {
        DisplayEntry::Group {
            label,
            iteration,
            items,
        } => {
            assert_eq!(label, "Transfers");
            assert!(matches!(iteration, GroupIteration::Bundled));
            assert_eq!(items.len(), 4);
            assert_eq!(items[0].label, "Recipient");
            assert_eq!(items[1].label, "Amount");
            assert_eq!(items[2].label, "Recipient");
            assert_eq!(items[3].label, "Amount");
        }
        _ => panic!("expected bundled group"),
    }
}

#[tokio::test]
async fn test_eip712_bundled_group_zips_array_items() {
    let descriptor = Descriptor::from_json(
        r##"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Batch(address[] recipients,uint256[] amounts)": {
                        "intent": "Batch",
                        "fields": [{
                            "label": "Transfers",
                            "iteration": "bundled",
                            "fields": [
                                { "path": "recipients.[]", "label": "Recipient", "format": "address" },
                                { "path": "amounts.[]", "label": "Amount", "format": "number" }
                            ]
                        }]
                    }
                }
            }
        }"##,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Batch": [
                { "name": "recipients", "type": "address[]" },
                { "name": "amounts", "type": "uint256[]" }
            ]
        },
        "primaryType": "Batch",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": {
            "recipients": [
                "0x0000000000000000000000000000000000000001",
                "0x0000000000000000000000000000000000000002"
            ],
            "amounts": [100, 200]
        }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    match &result.entries[0] {
        DisplayEntry::Group {
            iteration, items, ..
        } => {
            assert!(matches!(iteration, GroupIteration::Bundled));
            assert_eq!(items.len(), 4);
        }
        _ => panic!("expected bundled group"),
    }
}

#[tokio::test]
async fn test_eip712_bundled_group_mixed_scalar_child_errors() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Batch(address[] recipients,uint256 deadline)": {
                        "intent": "Batch",
                        "fields": [{
                            "iteration": "bundled",
                            "fields": [
                                { "path": "recipients.[]", "label": "Recipient", "format": "address" },
                                { "path": "deadline", "label": "Deadline", "format": "number" }
                            ]
                        }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Batch": [
                { "name": "recipients", "type": "address[]" },
                { "name": "deadline", "type": "uint256" }
            ]
        },
        "primaryType": "Batch",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": {
            "recipients": ["0x0000000000000000000000000000000000000001"],
            "deadline": 123
        }
    }))
    .unwrap();

    let err = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("bundled groups cannot mix"));
}

#[tokio::test]
async fn test_eip712_grouped_array_token_path_is_scoped_like_calldata() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xpermit2"}] } },
            "metadata": { "owner": "Uniswap", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,ExclusiveDutchOrder witness)DutchOutput(address token,uint256 startAmount,uint256 endAmount,address recipient)ExclusiveDutchOrder(OrderInfo info,uint256 decayStartTime,uint256 decayEndTime,address exclusiveFiller,uint256 exclusivityOverrideBps,address inputToken,uint256 inputStartAmount,uint256 inputEndAmount,DutchOutput[] outputs)OrderInfo(address reactor,address swapper,uint256 nonce,uint256 deadline,address additionalValidationContract,bytes additionalValidationData)TokenPermissions(address token,uint256 amount)": {
                        "intent": "UniswapX Exclusive Dutch Order",
                        "fields": [
                            {
                                "path": "witness.outputs.[]",
                                "fields": [
                                    { "path": "endAmount", "label": "Minimum amounts to receive", "format": "tokenAmount", "params": { "tokenPath": "token" } },
                                    { "path": "recipient", "label": "On Address", "format": "raw" }
                                ]
                            }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "TokenPermissions": [
                { "name": "token", "type": "address" },
                { "name": "amount", "type": "uint256" }
            ],
            "DutchOutput": [
                { "name": "token", "type": "address" },
                { "name": "startAmount", "type": "uint256" },
                { "name": "endAmount", "type": "uint256" },
                { "name": "recipient", "type": "address" }
            ],
            "OrderInfo": [
                { "name": "reactor", "type": "address" },
                { "name": "swapper", "type": "address" },
                { "name": "nonce", "type": "uint256" },
                { "name": "deadline", "type": "uint256" },
                { "name": "additionalValidationContract", "type": "address" },
                { "name": "additionalValidationData", "type": "bytes" }
            ],
            "ExclusiveDutchOrder": [
                { "name": "info", "type": "OrderInfo" },
                { "name": "decayStartTime", "type": "uint256" },
                { "name": "decayEndTime", "type": "uint256" },
                { "name": "exclusiveFiller", "type": "address" },
                { "name": "exclusivityOverrideBps", "type": "uint256" },
                { "name": "inputToken", "type": "address" },
                { "name": "inputStartAmount", "type": "uint256" },
                { "name": "inputEndAmount", "type": "uint256" },
                { "name": "outputs", "type": "DutchOutput[]" }
            ],
            "PermitWitnessTransferFrom": [
                { "name": "permitted", "type": "TokenPermissions" },
                { "name": "spender", "type": "address" },
                { "name": "nonce", "type": "uint256" },
                { "name": "deadline", "type": "uint256" },
                { "name": "witness", "type": "ExclusiveDutchOrder" }
            ]
        },
        "primaryType": "PermitWitnessTransferFrom",
        "domain": { "chainId": 1, "verifyingContract": "0xpermit2" },
        "message": {
            "permitted": { "token": "0x0000000000000000000000000000000000000001", "amount": "1" },
            "spender": "0x0000000000000000000000000000000000000002",
            "nonce": "1",
            "deadline": "1774866877",
            "witness": {
                "info": {
                    "reactor": "0x0000000000000000000000000000000000000003",
                    "swapper": "0x0000000000000000000000000000000000000004",
                    "nonce": "1",
                    "deadline": "1774866877",
                    "additionalValidationContract": "0x0000000000000000000000000000000000000000",
                    "additionalValidationData": "0x"
                },
                "decayStartTime": "1774780477",
                "decayEndTime": "1774780477",
                "exclusiveFiller": "0x0000000000000000000000000000000000000000",
                "exclusivityOverrideBps": "0",
                "inputToken": "0x0000000000000000000000000000000000000005",
                "inputStartAmount": "100000000000000",
                "inputEndAmount": "100000000000000",
                "outputs": [
                    {
                        "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                        "startAmount": "199179",
                        "endAmount": "200297",
                        "recipient": "0xbf01daf454dce008d3e2bfd47d5e186f71477253"
                    }
                ]
            }
        }
    }))
    .unwrap();

    let mut tokens = StaticTokenSource::new();
    tokens.insert(
        1,
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        TokenMeta {
            symbol: "USDC".to_string(),
            decimals: 6,
            name: "USD Coin".to_string(),
        },
    );

    let result = format_typed_data(&wrap_rd(descriptor, 1, "0xpermit2"), &typed_data, &tokens)
        .await
        .unwrap();

    match &result.entries[0] {
        DisplayEntry::Item(item) => {
            assert_eq!(item.label, "Minimum amounts to receive");
            assert_eq!(item.value, "0.200297 USDC");
        }
        _ => panic!("expected item output"),
    }
}

#[tokio::test]
async fn test_eip712_grouped_array_absolute_token_path_is_not_rewritten() {
    let descriptor = Descriptor::from_json(
        r##"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Batch(address[] recipients,uint256[] amounts,address token)": {
                        "intent": "Batch",
                        "fields": [{
                            "label": "Transfers",
                            "iteration": "bundled",
                            "fields": [
                                { "path": "recipients.[]", "label": "Recipient", "format": "address" },
                                { "path": "amounts.[]", "label": "Amount", "format": "tokenAmount", "params": { "tokenPath": "#.token" } }
                            ]
                        }]
                    }
                }
            }
        }"##,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Batch": [
                { "name": "recipients", "type": "address[]" },
                { "name": "amounts", "type": "uint256[]" },
                { "name": "token", "type": "address" }
            ]
        },
        "primaryType": "Batch",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": {
            "recipients": [
                "0x0000000000000000000000000000000000000001"
            ],
            "amounts": ["200297"],
            "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        }
    }))
    .unwrap();

    let mut tokens = StaticTokenSource::new();
    tokens.insert(
        1,
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        TokenMeta {
            symbol: "USDC".to_string(),
            decimals: 6,
            name: "USD Coin".to_string(),
        },
    );

    let result = format_typed_data(&wrap_rd(descriptor, 1, "0xabc"), &typed_data, &tokens)
        .await
        .unwrap();

    match &result.entries[0] {
        DisplayEntry::Group { items, .. } => {
            assert_eq!(items[0].label, "Recipient");
            assert_eq!(items[1].label, "Amount");
            assert_eq!(items[1].value, "0.200297 USDC");
        }
        _ => panic!("expected bundled group"),
    }
}

// ─── Array-element tokenPath parity (Permit2 PermitBatch shape) ───

/// A field iterating an array of structs (`details.[].amount`) with an
/// element-relative `tokenPath` (`details.[].token`) must resolve each
/// element's own token, not resolve the path once against the root. Calldata
/// and EIP-712 must agree. Mirrors Uniswap Permit2 `PermitBatch`.
#[tokio::test]
async fn test_array_element_token_path_resolves_per_element_calldata_eip712_parity() {
    const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    const WETH: &str = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";

    let fields = serde_json::json!([
        {
            "path": "details.[].amount",
            "label": "Amount allowance",
            "format": "tokenAmount",
            "params": { "tokenPath": "details.[].token" }
        }
    ]);

    let calldata_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "swap((address token,uint256 amount)[] details)": {
                        "intent": "Authorize spending of tokens",
                        "fields": fields.clone()
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let typed_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Swap(PermitDetails[] details)PermitDetails(address token,uint256 amount)": {
                        "intent": "Authorize spending of tokens",
                        "fields": fields
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let calldata = build_calldata(
        "swap((address token,uint256 amount)[] details)",
        &[
            uint_word(0x20),                    // offset to details array
            uint_word(2),                       // details.length
            address_word(USDC),                 // details[0].token
            uint_word(2_500_000_000),           // details[0].amount -> 2500 USDC (6dp)
            address_word(WETH),                 // details[1].token
            uint_word(750_000_000_000_000_000), // details[1].amount -> 0.75 WETH (18dp)
        ],
    );
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };

    let mut tokens = StaticTokenSource::new();
    tokens.insert(
        1,
        USDC,
        TokenMeta {
            symbol: "USDC".to_string(),
            decimals: 6,
            name: "USD Coin".to_string(),
        },
    );
    tokens.insert(
        1,
        WETH,
        TokenMeta {
            symbol: "WETH".to_string(),
            decimals: 18,
            name: "Wrapped Ether".to_string(),
        },
    );

    let calldata_result = format_calldata(&wrap_rd(calldata_descriptor, 1, "0xabc"), &tx, &tokens)
        .await
        .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "PermitDetails": [
                { "name": "token", "type": "address" },
                { "name": "amount", "type": "uint256" }
            ],
            "Swap": [
                { "name": "details", "type": "PermitDetails[]" }
            ]
        },
        "primaryType": "Swap",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": {
            "details": [
                { "token": USDC, "amount": "2500000000" },
                { "token": WETH, "amount": "750000000000000000" }
            ]
        }
    }))
    .unwrap();
    let typed_result =
        format_typed_data(&wrap_rd(typed_descriptor, 1, "0xabc"), &typed_data, &tokens)
            .await
            .unwrap();

    assert_eq!(
        semantic_item_snapshot(&calldata_result.entries),
        vec![
            ("Amount allowance".to_string(), "2500 USDC".to_string()),
            ("Amount allowance".to_string(), "0.75 WETH".to_string()),
        ]
    );
    assert_semantic_parity(&calldata_result, &typed_result);
}

// ─── #20: EIP-712 domain completeness ───

#[test]
fn test_eip712_domain_full_fields() {
    let json = r#"{
        "context": {
            "eip712": {
                "deployments": [{"chainId": 1, "address": "0xabc"}],
                "domain": {
                    "name": "My App",
                    "version": "2",
                    "chainId": 1,
                    "verifyingContract": "0xabc",
                    "salt": "0xdeadbeef"
                }
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {"definitions": {}, "formats": {}}
    }"#;
    let descriptor = Descriptor::from_json(json).unwrap();
    if let clear_signing::types::context::DescriptorContext::Eip712(ctx) = &descriptor.context {
        let domain = ctx.eip712.domain.as_ref().unwrap();
        assert_eq!(domain.name.as_deref(), Some("My App"));
        assert_eq!(domain.version.as_deref(), Some("2"));
        assert_eq!(domain.chain_id, Some(1));
        assert_eq!(domain.verifying_contract.as_deref(), Some("0xabc"));
        assert_eq!(domain.salt.as_deref(), Some("0xdeadbeef"));
    } else {
        panic!("expected Eip712 context");
    }
}

// ─── #22: Escape sequences in interpolation ───

#[tokio::test]
async fn test_interpolation_escape_sequences() {
    let json = r#"{
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "foo(uint256)": {
                    "intent": "Test",
                    "interpolatedIntent": "Value is {{literal}} and ${@.0}",
                    "fields": [
                        {"path": "@.0", "label": "Val", "format": "number"}
                    ]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let calldata = build_calldata("foo(uint256)", &[uint_word(42)]);

    let descriptors = wrap_rd(descriptor, 1, "0xabc");
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let result = format_calldata(&descriptors, &tx, &EmptyDataProvider)
        .await
        .unwrap();
    assert_eq!(
        result.interpolated_intent.as_deref(),
        Some("Value is {literal} and 42")
    );
}

// ─── Array-iteration interpolatedIntent (calldata ≡ EIP-712) ───

#[tokio::test]
async fn test_array_iteration_interpolated_intent_joins_with_and() {
    // A placeholder over an array-element path (`{amounts.[]}`) must format each
    // element and join with " and ", not drop the whole interpolatedIntent (a
    // scalar path resolve returns nothing for `.[]`). Shared calldata/EIP-712.
    let calldata_descriptor = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": {
                "definitions": {},
                "formats": {
                    "withdraw(uint256[] amounts)": {
                        "intent": "Withdraw",
                        "interpolatedIntent": "Withdraw {amounts.[]}",
                        "fields": [
                            {"path": "amounts.[]", "label": "Amount", "format": "number"}
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let mut calldata = build_calldata("withdraw(uint256[])", &[dynamic_offset_word(32)]);
    calldata.extend_from_slice(&encode_uint_array(&[10, 20]));
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let calldata_result = format_calldata(
        &wrap_rd(calldata_descriptor, 1, "0xabc"),
        &tx,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(
        calldata_result.interpolated_intent.as_deref(),
        Some("Withdraw 10 and 20")
    );

    let typed_descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": {
                "definitions": {},
                "formats": {
                    "Withdraw(uint256[] amounts)": {
                        "intent": "Withdraw",
                        "interpolatedIntent": "Withdraw {amounts.[]}",
                        "fields": [
                            {"path": "amounts.[]", "label": "Amount", "format": "number"}
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();
    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Withdraw": [{ "name": "amounts", "type": "uint256[]" }]
        },
        "primaryType": "Withdraw",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "amounts": ["10", "20"] }
    }))
    .unwrap();
    let typed_result = format_typed_data(
        &wrap_rd(typed_descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(
        typed_result.interpolated_intent.as_deref(),
        Some("Withdraw 10 and 20")
    );

    assert_semantic_parity(&calldata_result, &typed_result);
}

#[tokio::test]
async fn test_scoped_array_interpolated_intent_resolves_item_token() {
    // A scoped array-element field with an item-relative `tokenPath` must resolve
    // the per-element token in interpolatedIntent (parity with rendering), not
    // fall back to the raw integer.
    let descriptor = Descriptor::from_json(
        r##"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Order(Output[] outputs)Output(uint256 endAmount,address token)": {
                        "intent": "Order",
                        "interpolatedIntent": "Receive {outputs.[].endAmount}",
                        "fields": [{
                            "label": "Receive",
                            "iteration": "bundled",
                            "fields": [
                                { "path": "outputs.[].endAmount", "label": "Amount", "format": "tokenAmount", "params": { "tokenPath": "outputs.[].token" } }
                            ]
                        }]
                    }
                }
            }
        }"##,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Order": [{ "name": "outputs", "type": "Output[]" }],
            "Output": [
                { "name": "endAmount", "type": "uint256" },
                { "name": "token", "type": "address" }
            ]
        },
        "primaryType": "Order",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": {
            "outputs": [
                { "endAmount": "200297", "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" },
                { "endAmount": "500000", "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" }
            ]
        }
    }))
    .unwrap();

    let mut tokens = StaticTokenSource::new();
    tokens.insert(
        1,
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        TokenMeta {
            symbol: "USDC".to_string(),
            decimals: 6,
            name: "USD Coin".to_string(),
        },
    );

    let result = format_typed_data(&wrap_rd(descriptor, 1, "0xabc"), &typed_data, &tokens)
        .await
        .unwrap();
    assert_eq!(
        result.interpolated_intent.as_deref(),
        Some("Receive 0.200297 USDC and 0.5 USDC")
    );
}

/// `interpolatedIntent` over an array-element field with an element-relative
/// `tokenPath` must resolve each element's own token — in BOTH calldata and
/// EIP-712 (the calldata interpolation path previously left the path unscoped,
/// rendering raw integers while EIP-712 resolved per element).
#[tokio::test]
async fn test_array_interpolated_intent_item_token_calldata_eip712_parity() {
    const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    const WETH: &str = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";

    let mut tokens = StaticTokenSource::new();
    tokens.insert(
        1,
        USDC,
        TokenMeta {
            symbol: "USDC".to_string(),
            decimals: 6,
            name: "USD Coin".to_string(),
        },
    );
    tokens.insert(
        1,
        WETH,
        TokenMeta {
            symbol: "WETH".to_string(),
            decimals: 18,
            name: "Wrapped Ether".to_string(),
        },
    );

    let fields = serde_json::json!([
        { "path": "outputs.[].endAmount", "label": "Amount", "format": "tokenAmount", "params": { "tokenPath": "outputs.[].token" } }
    ]);

    let calldata_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "fill((uint256 endAmount,address token)[] outputs)": {
                        "intent": "Order",
                        "interpolatedIntent": "Receive {outputs.[].endAmount}",
                        "fields": fields.clone()
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let calldata = build_calldata(
        "fill((uint256 endAmount,address token)[] outputs)",
        &[
            uint_word(0x20),                    // offset to outputs array
            uint_word(2),                       // outputs.length
            uint_word(2_500_000_000),           // outputs[0].endAmount -> 2500 USDC
            address_word(USDC),                 // outputs[0].token
            uint_word(750_000_000_000_000_000), // outputs[1].endAmount -> 0.75 WETH
            address_word(WETH),                 // outputs[1].token
        ],
    );
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let calldata_result = format_calldata(&wrap_rd(calldata_descriptor, 1, "0xabc"), &tx, &tokens)
        .await
        .unwrap();

    let typed_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Order(Output[] outputs)Output(uint256 endAmount,address token)": {
                        "intent": "Order",
                        "interpolatedIntent": "Receive {outputs.[].endAmount}",
                        "fields": fields
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();
    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Order": [{ "name": "outputs", "type": "Output[]" }],
            "Output": [
                { "name": "endAmount", "type": "uint256" },
                { "name": "token", "type": "address" }
            ]
        },
        "primaryType": "Order",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": {
            "outputs": [
                { "endAmount": "2500000000", "token": USDC },
                { "endAmount": "750000000000000000", "token": WETH }
            ]
        }
    }))
    .unwrap();
    let typed_result =
        format_typed_data(&wrap_rd(typed_descriptor, 1, "0xabc"), &typed_data, &tokens)
            .await
            .unwrap();

    assert_eq!(
        calldata_result.interpolated_intent.as_deref(),
        Some("Receive 2500 USDC and 0.75 WETH")
    );
    assert_eq!(
        typed_result.interpolated_intent.as_deref(),
        Some("Receive 2500 USDC and 0.75 WETH")
    );
    assert_semantic_parity(&calldata_result, &typed_result);
}

/// A bare (non-`.[]`) `tokenPath` on a simple array-element field is ROOT-relative
/// and must keep resolving against the message root, not the scalar array element.
/// Guards against rebasing element-relative scoping onto bare root paths. Both
/// calldata and EIP-712.
#[tokio::test]
async fn test_array_bare_root_token_path_resolves_at_root_calldata_eip712_parity() {
    const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

    let mut tokens = StaticTokenSource::new();
    tokens.insert(
        1,
        USDC,
        TokenMeta {
            symbol: "USDC".to_string(),
            decimals: 6,
            name: "USD Coin".to_string(),
        },
    );

    let fields = serde_json::json!([
        { "path": "amounts.[]", "label": "Amount", "format": "tokenAmount", "params": { "tokenPath": "token" } }
    ]);

    let calldata_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "pay(uint256[] amounts,address token)": {
                        "intent": "Pay",
                        "fields": fields.clone()
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    // f(uint256[] amounts, address token): head is [offset-to-amounts, token].
    let calldata = build_calldata(
        "pay(uint256[] amounts,address token)",
        &[
            uint_word(0x40),          // offset to amounts (after the 2-word head)
            address_word(USDC),       // token (root, shared by all elements)
            uint_word(2),             // amounts.length
            uint_word(2_500_000_000), // amounts[0] -> 2500 USDC
            uint_word(1_000_000),     // amounts[1] -> 1 USDC
        ],
    );
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let calldata_result = format_calldata(&wrap_rd(calldata_descriptor, 1, "0xabc"), &tx, &tokens)
        .await
        .unwrap();

    let typed_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Pay(uint256[] amounts,address token)": {
                        "intent": "Pay",
                        "fields": fields
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();
    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Pay": [
                { "name": "amounts", "type": "uint256[]" },
                { "name": "token", "type": "address" }
            ]
        },
        "primaryType": "Pay",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "amounts": ["2500000000", "1000000"], "token": USDC }
    }))
    .unwrap();
    let typed_result =
        format_typed_data(&wrap_rd(typed_descriptor, 1, "0xabc"), &typed_data, &tokens)
            .await
            .unwrap();

    let expected = vec![
        ("Amount".to_string(), "2500 USDC".to_string()),
        ("Amount".to_string(), "1 USDC".to_string()),
    ];
    assert_eq!(semantic_item_snapshot(&calldata_result.entries), expected);
    assert_semantic_parity(&calldata_result, &typed_result);
}

// ─── #16: EIP-712 AddressName with senderAddress ───

#[tokio::test]
async fn test_eip712_address_name_sender() {
    let json = r#"{
        "context": {
            "eip712": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "Transfer(address to)": {
                    "intent": "Transfer",
                    "fields": [
                        {
                            "path": "to",
                            "label": "Recipient",
                            "format": "addressName",
                            "params": {
                                "senderAddress": "0x1234567890123456789012345678901234567890"
                            }
                        }
                    ]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {"EIP712Domain": [], "Transfer": [{"name": "to", "type": "address"}]},
        "primaryType": "Transfer",
        "domain": {"chainId": 1, "verifyingContract": "0xabc"},
        "message": {"to": "0x1234567890123456789012345678901234567890"}
    }))
    .unwrap();

    let descriptors = wrap_rd(descriptor, 1, "0xabc");
    let result = format_typed_data(&descriptors, &typed_data, &EmptyDataProvider)
        .await
        .unwrap();
    if let DisplayEntry::Item(ref item) = result.entries[0] {
        assert_eq!(item.value, "Sender");
    } else {
        panic!("expected Item");
    }
}

#[tokio::test]
async fn test_sender_address_constant_reference_renders_sender() {
    // A `senderAddress` given as a `$.metadata.constants.*` reference must be
    // resolved before the comparison: an address field equal to that constant
    // renders "Sender". Shared calldata/EIP-712 (paraswap `addressAsNull`).
    let calldata_descriptor = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": {
                "owner": "test", "enums": {}, "maps": {},
                "constants": {"addressAsNull": "0x0000000000000000000000000000000000000000"}
            },
            "display": {
                "definitions": {},
                "formats": {
                    "transfer(address beneficiary)": {
                        "intent": "Transfer",
                        "fields": [
                            {
                                "path": "beneficiary",
                                "label": "Beneficiary",
                                "format": "addressName",
                                "params": {"senderAddress": "$.metadata.constants.addressAsNull"}
                            }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let calldata = build_calldata(
        "transfer(address)",
        &[addr_word("0x0000000000000000000000000000000000000000")],
    );
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let calldata_result = format_calldata(
        &wrap_rd(calldata_descriptor, 1, "0xabc"),
        &tx,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(
        semantic_item_snapshot(&calldata_result.entries),
        vec![("Beneficiary".to_string(), "Sender".to_string())]
    );

    let typed_descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": {
                "owner": "test", "enums": {}, "maps": {},
                "constants": {"addressAsNull": "0x0000000000000000000000000000000000000000"}
            },
            "display": {
                "definitions": {},
                "formats": {
                    "Transfer(address beneficiary)": {
                        "intent": "Transfer",
                        "fields": [
                            {
                                "path": "beneficiary",
                                "label": "Beneficiary",
                                "format": "addressName",
                                "params": {"senderAddress": "$.metadata.constants.addressAsNull"}
                            }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();
    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Transfer": [{ "name": "beneficiary", "type": "address" }]
        },
        "primaryType": "Transfer",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "beneficiary": "0x0000000000000000000000000000000000000000" }
    }))
    .unwrap();
    let typed_result = format_typed_data(
        &wrap_rd(typed_descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(
        semantic_item_snapshot(&typed_result.entries),
        vec![("Beneficiary".to_string(), "Sender".to_string())]
    );

    assert_semantic_parity(&calldata_result, &typed_result);
}

// ─── #8: selectorPath parsing ───

#[test]
fn test_selector_path_parsing() {
    let json = r#"{
        "path": "data",
        "label": "Inner call",
        "format": "calldata",
        "params": {
            "calleePath": "to",
            "selectorPath": "selector"
        }
    }"#;
    let field: clear_signing::types::display::DisplayField = serde_json::from_str(json).unwrap();
    if let clear_signing::types::display::DisplayField::Simple { params, .. } = &field {
        let p = params.as_ref().unwrap();
        assert_eq!(p.selector_path.as_deref(), Some("selector"));
        assert_eq!(p.callee_path.as_deref(), Some("to"));
    } else {
        panic!("expected Simple");
    }
}

// ─── #2: EIP-712 with literal value field ───

#[tokio::test]
async fn test_eip712_literal_value_field() {
    let json = r#"{
        "context": {
            "eip712": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "Permit(address spender)": {
                    "intent": "Permit",
                    "fields": [
                        {"value": "Token Approval", "label": "Action"},
                        {"path": "spender", "label": "Spender", "format": "address"}
                    ]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {"EIP712Domain": [], "Permit": [{"name": "spender", "type": "address"}]},
        "primaryType": "Permit",
        "domain": {"chainId": 1, "verifyingContract": "0xabc"},
        "message": {"spender": "0x1234567890123456789012345678901234567890"}
    }))
    .unwrap();

    let descriptors = wrap_rd(descriptor, 1, "0xabc");
    let result = format_typed_data(&descriptors, &typed_data, &EmptyDataProvider)
        .await
        .unwrap();
    assert_eq!(result.entries.len(), 2);
    if let DisplayEntry::Item(ref item) = result.entries[0] {
        assert_eq!(item.label, "Action");
        assert_eq!(item.value, "Token Approval");
    } else {
        panic!("expected Item");
    }
}

// ─── #21: Excluded paths ───

#[tokio::test]
async fn test_excluded_paths() {
    let json = r#"{
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "foo(uint256,uint256)": {
                    "intent": "Test excluded",
                    "excluded": ["@.1"],
                    "fields": [
                        {"path": "@.0", "label": "Visible", "format": "number"},
                        {"path": "@.1", "label": "Excluded", "format": "number"}
                    ]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let calldata = build_calldata("foo(uint256,uint256)", &[uint_word(42), uint_word(99)]);

    let descriptors = wrap_rd(descriptor, 1, "0xabc");
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let result = format_calldata(&descriptors, &tx, &EmptyDataProvider)
        .await
        .unwrap();
    assert_eq!(result.entries.len(), 1);
    if let DisplayEntry::Item(ref item) = result.entries[0] {
        assert_eq!(item.label, "Visible");
        assert_eq!(item.value, "42");
    } else {
        panic!("expected Item");
    }
}

#[tokio::test]
async fn test_eip712_excluded_paths_match_calldata() {
    let fields = serde_json::json!([
        {"path": "visible", "label": "Visible", "format": "number"},
        {"path": "hidden", "label": "Hidden", "format": "number"}
    ]);

    let calldata_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": {
                "contract": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}]
                }
            },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": {
                "definitions": {},
                "formats": {
                    "show(uint256 visible,uint256 hidden)": {
                        "intent": "Show",
                        "excluded": ["hidden"],
                        "fields": fields.clone()
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let typed_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}]
                }
            },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": {
                "definitions": {},
                "formats": {
                    "Show(uint256 visible,uint256 hidden)": {
                        "intent": "Show",
                        "excluded": ["hidden"],
                        "fields": fields
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let calldata = build_calldata("show(uint256,uint256)", &[uint_word(42), uint_word(99)]);
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let calldata_result = format_calldata(
        &wrap_rd(calldata_descriptor, 1, "0xabc"),
        &tx,
        &EmptyDataProvider,
    )
    .await
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Show": [
                { "name": "visible", "type": "uint256" },
                { "name": "hidden", "type": "uint256" }
            ]
        },
        "primaryType": "Show",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "visible": 42, "hidden": 99 }
    }))
    .unwrap();
    let typed_result = format_typed_data(
        &wrap_rd(typed_descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();

    assert_semantic_parity(&calldata_result, &typed_result);
}

#[tokio::test]
async fn test_eip712_token_amount_threshold_matches_calldata() {
    let token = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    let fields = serde_json::json!([
        {
            "path": "value",
            "label": "Amount",
            "format": "tokenAmount",
            "params": {
                "token": token,
                "threshold": "0x100",
                "message": "All"
            }
        }
    ]);

    let calldata_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": {
                "contract": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}]
                }
            },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": {
                "definitions": {},
                "formats": {
                    "withdraw(uint256 value)": {
                        "intent": "Withdraw",
                        "fields": fields.clone()
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let typed_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}]
                }
            },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": {
                "definitions": {},
                "formats": {
                    "Withdraw(uint256 value)": {
                        "intent": "Withdraw",
                        "fields": fields
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let calldata = build_calldata("withdraw(uint256)", &[uint_word(256)]);
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };

    let mut tokens = StaticTokenSource::new();
    tokens.insert(
        1,
        token,
        TokenMeta {
            symbol: "USDC".to_string(),
            decimals: 6,
            name: "USD Coin".to_string(),
        },
    );

    let calldata_result = format_calldata(&wrap_rd(calldata_descriptor, 1, "0xabc"), &tx, &tokens)
        .await
        .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Withdraw": [{ "name": "value", "type": "uint256" }]
        },
        "primaryType": "Withdraw",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "value": "256" }
    }))
    .unwrap();
    let typed_result =
        format_typed_data(&wrap_rd(typed_descriptor, 1, "0xabc"), &typed_data, &tokens)
            .await
            .unwrap();

    assert_semantic_parity(&calldata_result, &typed_result);
}

#[tokio::test]
async fn test_eip712_token_amount_native_currency_matches_calldata() {
    let native = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let fields = serde_json::json!([
        {
            "path": "value",
            "label": "Amount",
            "format": "tokenAmount",
            "params": {
                "tokenPath": "token",
                "nativeCurrencyAddress": native
            }
        }
    ]);

    let calldata_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": {
                "contract": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}]
                }
            },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": {
                "definitions": {},
                "formats": {
                    "swap(address token,uint256 value)": {
                        "intent": "Swap",
                        "fields": fields.clone()
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let typed_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}]
                }
            },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": {
                "definitions": {},
                "formats": {
                    "Swap(address token,uint256 value)": {
                        "intent": "Swap",
                        "fields": fields
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let calldata = build_calldata(
        "swap(address,uint256)",
        &[addr_word(native), uint_word(1_000_000_000_000_000_000)],
    );
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let calldata_result = format_calldata(
        &wrap_rd(calldata_descriptor, 1, "0xabc"),
        &tx,
        &EmptyDataProvider,
    )
    .await
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Swap": [
                { "name": "token", "type": "address" },
                { "name": "value", "type": "uint256" }
            ]
        },
        "primaryType": "Swap",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": {
            "token": native,
            "value": "1000000000000000000"
        }
    }))
    .unwrap();
    let typed_result = format_typed_data(
        &wrap_rd(typed_descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();

    assert_semantic_parity(&calldata_result, &typed_result);
}

#[tokio::test]
async fn test_eip712_sliced_numeric_formats_match_calldata() {
    let calldata_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": {
                "contract": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}]
                }
            },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": {
                "definitions": {},
                "formats": {
                    "slice(bytes32,bytes32)": {
                        "intent": "Slice",
                        "fields": [
                            {"path": "@.1.[-2:]", "label": "Token Amount", "format": "tokenAmount", "params": {"tokenPath": "@.0.[-20:]"}},
                            {"path": "@.1.[-2:]", "label": "Number", "format": "number"},
                            {"path": "@.1.[-2:]", "label": "Amount", "format": "amount"},
                            {"path": "@.1.[-2:]", "label": "Unit", "format": "unit", "params": {"base": "bps"}}
                        ]
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();
    let typed_descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}]
                }
            },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": {
                "definitions": {},
                "formats": {
                    "SliceTest(bytes32 tokenWord,bytes32 amountWord)": {
                        "intent": "Slice",
                        "fields": [
                            {"path": "amountWord.[-2:]", "label": "Token Amount", "format": "tokenAmount", "params": {"tokenPath": "tokenWord.[-20:]"}},
                            {"path": "amountWord.[-2:]", "label": "Number", "format": "number"},
                            {"path": "amountWord.[-2:]", "label": "Amount", "format": "amount"},
                            {"path": "amountWord.[-2:]", "label": "Unit", "format": "unit", "params": {"base": "bps"}}
                        ]
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let calldata = build_calldata(
        "slice(bytes32,bytes32)",
        &[
            addr_word("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
            uint_word(500),
        ],
    );
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "SliceTest": [
                {"name": "tokenWord", "type": "bytes32"},
                {"name": "amountWord", "type": "bytes32"}
            ]
        },
        "primaryType": "SliceTest",
        "domain": {"chainId": 1, "verifyingContract": "0xabc"},
        "message": {
            "tokenWord": "0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "amountWord": "0x00000000000000000000000000000000000000000000000000000000000001f4"
        }
    }))
    .unwrap();

    let mut tokens = StaticTokenSource::new();
    tokens.insert(
        1,
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        TokenMeta {
            symbol: "USDC".to_string(),
            decimals: 6,
            name: "USD Coin".to_string(),
        },
    );

    let calldata_result = format_calldata(&wrap_rd(calldata_descriptor, 1, "0xabc"), &tx, &tokens)
        .await
        .unwrap();
    let typed_result =
        format_typed_data(&wrap_rd(typed_descriptor, 1, "0xabc"), &typed_data, &tokens)
            .await
            .unwrap();

    assert_semantic_parity(&calldata_result, &typed_result);
}

// ─── #17: Includes mechanism ───

#[test]
fn test_merge_fields_by_path() {
    let included = serde_json::json!({
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "generic", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "approve(address spender,uint256 value)": {
                    "intent": "Approve",
                    "fields": [
                        {"path": "spender", "label": "Spender", "format": "addressName"},
                        {"path": "value", "label": "Amount", "format": "tokenAmount",
                         "params": {"tokenPath": "@.to", "threshold": "0x800"}}
                    ]
                }
            }
        }
    });

    let including = serde_json::json!({
        "includes": "./erc20.json",
        "display": {
            "formats": {
                "approve(address spender,uint256 value)": {
                    "fields": [
                        {"path": "value", "params": {"threshold": "0xFFF"}}
                    ]
                }
            }
        }
    });

    let merged = merge_descriptor_values(&including, &included);
    let fields = merged["display"]["formats"]["approve(address spender,uint256 value)"]["fields"]
        .as_array()
        .unwrap();
    assert_eq!(fields.len(), 2);
    // Spender field preserved from included
    assert_eq!(fields[0]["path"], "spender");
    assert_eq!(fields[0]["label"], "Spender");
    // Amount field: threshold overridden, tokenPath preserved
    assert_eq!(fields[1]["path"], "value");
    assert_eq!(fields[1]["label"], "Amount");
    assert_eq!(fields[1]["params"]["threshold"], "0xFFF");
    assert_eq!(fields[1]["params"]["tokenPath"], "@.to");
}

#[test]
fn test_merge_including_wins_metadata() {
    let included = serde_json::json!({
        "metadata": {"owner": "Generic", "contractName": "ERC20"}
    });
    let including = serde_json::json!({
        "metadata": {"owner": "Tether", "contractName": "USDT"}
    });
    let merged = merge_descriptor_values(&including, &included);
    assert_eq!(merged["metadata"]["owner"], "Tether");
    assert_eq!(merged["metadata"]["contractName"], "USDT");
}

#[test]
fn test_merge_format_keys() {
    let included = serde_json::json!({
        "display": {
            "definitions": {},
            "formats": {
                "transfer(address,uint256)": {
                    "intent": "Transfer",
                    "fields": [{"path": "@.0", "label": "To"}]
                },
                "approve(address,uint256)": {
                    "intent": "Approve",
                    "fields": [{"path": "@.0", "label": "Spender"}]
                }
            }
        }
    });
    let including = serde_json::json!({
        "display": {
            "formats": {
                "transfer(address,uint256)": {
                    "intent": "Send tokens"
                }
            }
        }
    });
    let merged = merge_descriptor_values(&including, &included);
    // transfer intent overridden
    assert_eq!(
        merged["display"]["formats"]["transfer(address,uint256)"]["intent"],
        "Send tokens"
    );
    // transfer fields preserved from base
    assert!(
        merged["display"]["formats"]["transfer(address,uint256)"]["fields"]
            .as_array()
            .unwrap()
            .len()
            == 1
    );
    // approve format preserved from base
    assert_eq!(
        merged["display"]["formats"]["approve(address,uint256)"]["intent"],
        "Approve"
    );
}

#[test]
fn test_merge_appends_new_fields() {
    let included = serde_json::json!({
        "display": {
            "definitions": {},
            "formats": {
                "foo(uint256)": {
                    "intent": "Foo",
                    "fields": [{"path": "@.0", "label": "Existing"}]
                }
            }
        }
    });
    let including = serde_json::json!({
        "display": {
            "formats": {
                "foo(uint256)": {
                    "fields": [{"path": "@.1", "label": "New"}]
                }
            }
        }
    });
    let merged = merge_descriptor_values(&including, &included);
    let fields = merged["display"]["formats"]["foo(uint256)"]["fields"]
        .as_array()
        .unwrap();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0]["path"], "@.0");
    assert_eq!(fields[1]["path"], "@.1");
}

#[test]
fn test_merge_context_from_including() {
    let included = serde_json::json!({
        "context": {
            "contract": {"abi": ["function transfer(address,uint256)"]}
        }
    });
    let including = serde_json::json!({
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xdAC17"}]
            }
        }
    });
    let merged = merge_descriptor_values(&including, &included);
    // Both abi and deployments present via deep merge
    assert!(merged["context"]["contract"]["abi"].is_array());
    assert!(merged["context"]["contract"]["deployments"].is_array());
}

#[test]
fn test_merge_preserves_included_fields() {
    let included = serde_json::json!({
        "display": {
            "definitions": {},
            "formats": {
                "foo(address,uint256)": {
                    "intent": "Foo",
                    "fields": [
                        {"path": "@.0", "label": "Recipient", "format": "address"},
                        {"path": "@.1", "label": "Amount", "format": "number"}
                    ]
                }
            }
        }
    });
    // Including file doesn't touch these fields at all
    let including = serde_json::json!({
        "metadata": {"owner": "Override"}
    });
    let merged = merge_descriptor_values(&including, &included);
    let fields = merged["display"]["formats"]["foo(address,uint256)"]["fields"]
        .as_array()
        .unwrap();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0]["label"], "Recipient");
    assert_eq!(fields[1]["label"], "Amount");
}

#[test]
fn test_merge_nested_params() {
    let included = serde_json::json!({
        "display": {
            "definitions": {},
            "formats": {
                "foo(uint256)": {
                    "intent": "Foo",
                    "fields": [{
                        "path": "@.0", "label": "Amount", "format": "tokenAmount",
                        "params": {"tokenPath": "@.to", "threshold": "0x100", "nativeCurrencyAddress": "0xEEE"}
                    }]
                }
            }
        }
    });
    let including = serde_json::json!({
        "display": {
            "formats": {
                "foo(uint256)": {
                    "fields": [{
                        "path": "@.0",
                        "params": {"threshold": "0xFFF"}
                    }]
                }
            }
        }
    });
    let merged = merge_descriptor_values(&including, &included);
    let field = &merged["display"]["formats"]["foo(uint256)"]["fields"][0];
    assert_eq!(field["params"]["threshold"], "0xFFF");
    assert_eq!(field["params"]["tokenPath"], "@.to");
    assert_eq!(field["params"]["nativeCurrencyAddress"], "0xEEE");
}

#[test]
fn test_includes_deserialization() {
    let json = r#"{
        "includes": "./base.json",
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xabc"}]
            }
        },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {}
        }
    }"#;
    let descriptor = Descriptor::from_json(json).unwrap();
    assert_eq!(descriptor.includes.as_deref(), Some("./base.json"));
}

#[test]
fn test_merge_strips_includes() {
    let including = serde_json::json!({
        "includes": "./base.json",
        "metadata": {"owner": "Override"}
    });
    let included = serde_json::json!({
        "metadata": {"owner": "Base"}
    });
    let merged = merge_descriptor_values(&including, &included);
    assert!(merged.get("includes").is_none());
}

#[tokio::test]
async fn test_merge_produces_valid_descriptor() {
    // Full end-to-end: merge two partial descriptors, then use the result for formatting
    let included_json = r#"{
        "display": {
            "definitions": {},
            "formats": {
                "transfer(address to,uint256 amount)": {
                    "intent": "Transfer",
                    "fields": [
                        {"path": "to", "label": "Recipient", "format": "address"},
                        {"path": "amount", "label": "Amount", "format": "number"}
                    ]
                }
            }
        }
    }"#;

    let including_json = r#"{
        "includes": "./erc20.json",
        "context": {
            "contract": {
                "deployments": [{"chainId": 1, "address": "0xdac17f958d2ee523a2206206994597c13d831ec7"}]
            }
        },
        "metadata": {"owner": "Tether", "contractName": "USDT", "enums": {}, "constants": {}, "maps": {}}
    }"#;

    let merged_json = merge_descriptors(including_json, included_json).unwrap();
    let descriptor = Descriptor::from_json(&merged_json).unwrap();

    let calldata = build_calldata(
        "transfer(address,uint256)",
        &[
            addr_word("0x0000000000000000000000000000000000000001"),
            uint_word(1000),
        ],
    );

    let descriptors = wrap_rd(descriptor, 1, "0xdac17f958d2ee523a2206206994597c13d831ec7");
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xdac17f958d2ee523a2206206994597c13d831ec7",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let result = format_calldata(&descriptors, &tx, &EmptyDataProvider)
        .await
        .unwrap();
    assert_eq!(result.intent, "Transfer");
    assert_eq!(result.entries.len(), 2);
    if let DisplayEntry::Item(ref item) = result.entries[0] {
        assert_eq!(item.label, "Recipient");
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

// ─── EIP-712 encodeType format key matching ───

#[tokio::test]
async fn test_eip712_encode_type_format_key() {
    // Real Velora/Portikus DeltaV2 descriptor — format key is the full encodeType string
    let descriptor_json = r#"{
        "context": {
            "eip712": {
                "deployments": [
                    { "chainId": 10, "address": "0x0000000000bbf5c5fd284e657f01bd000933c96d" }
                ],
                "domain": { "name": "Portikus", "version": "2.0.0" }
            }
        },
        "metadata": { "owner": "Velora" },
        "display": {
            "formats": {
                "Order(address owner,address beneficiary,address srcToken,address destToken,uint256 srcAmount,uint256 destAmount,uint256 expectedAmount,uint256 deadline,uint8 kind,uint256 nonce,uint256 partnerAndFee,bytes permit,bytes metadata,Bridge bridge)Bridge(bytes4 protocolSelector,uint256 destinationChainId,address outputToken,int8 scalingFactor,bytes protocolData)": {
                    "intent": "Swap order",
                    "fields": [
                        { "path": "srcAmount", "label": "Amount to send", "format": "tokenAmount", "params": { "tokenPath": "srcToken" } },
                        { "path": "destAmount", "label": "Minimum to receive", "format": "tokenAmount", "params": { "tokenPath": "destToken" } },
                        { "path": "bridge.destinationChainId", "label": "Destination chain ID", "format": "raw" },
                        { "path": "beneficiary", "label": "Beneficiary", "format": "raw" },
                        { "path": "deadline", "label": "Expiration time", "format": "date", "params": { "encoding": "timestamp" } }
                    ]
                }
            }
        }
    }"#;

    // Real typed data from wallet — primaryType is "Order", not the full encodeType key
    let typed_data_json = r#"{
        "domain": {
            "chainId": 10,
            "name": "Portikus",
            "version": "2.0.0",
            "verifyingContract": "0x0000000000bbf5c5fd284e657f01bd000933c96d"
        },
        "message": {
            "owner": "0xbf01daf454dce008d3e2bfd47d5e186f71477253",
            "beneficiary": "0xbf01daf454dce008d3e2bfd47d5e186f71477253",
            "srcToken": "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58",
            "destToken": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "srcAmount": "38627265",
            "destAmount": "18816200237962656",
            "expectedAmount": "18910754008002670",
            "deadline": 1774257465,
            "nonce": "1774257068031",
            "permit": "0x",
            "partnerAndFee": "90631063861114836560958097440945986548822432573276877133894239693005947666959",
            "bridge": {
                "protocolSelector": "0x00000000",
                "destinationChainId": 0,
                "outputToken": "0x0000000000000000000000000000000000000000",
                "scalingFactor": 0,
                "protocolData": "0x"
            },
            "kind": 0,
            "metadata": "0x"
        },
        "primaryType": "Order",
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "Order": [
                { "name": "owner", "type": "address" },
                { "name": "beneficiary", "type": "address" },
                { "name": "srcToken", "type": "address" },
                { "name": "destToken", "type": "address" },
                { "name": "srcAmount", "type": "uint256" },
                { "name": "destAmount", "type": "uint256" },
                { "name": "expectedAmount", "type": "uint256" },
                { "name": "deadline", "type": "uint256" },
                { "name": "kind", "type": "uint8" },
                { "name": "nonce", "type": "uint256" },
                { "name": "partnerAndFee", "type": "uint256" },
                { "name": "permit", "type": "bytes" },
                { "name": "metadata", "type": "bytes" },
                { "name": "bridge", "type": "Bridge" }
            ],
            "Bridge": [
                { "name": "protocolSelector", "type": "bytes4" },
                { "name": "destinationChainId", "type": "uint256" },
                { "name": "outputToken", "type": "address" },
                { "name": "scalingFactor", "type": "int8" },
                { "name": "protocolData", "type": "bytes" }
            ]
        }
    }"#;

    let descriptor = Descriptor::from_json(descriptor_json).unwrap();
    let typed_data: TypedData = serde_json::from_str(typed_data_json).unwrap();
    let descriptors = wrap_rd(descriptor, 10, "0x0000000000bbf5c5fd284e657f01bd000933c96d");

    let result = format_typed_data(&descriptors, &typed_data, &EmptyDataProvider)
        .await
        .unwrap();

    // Must match the descriptor format, not fall back to raw
    assert_eq!(result.intent, "Swap order");
    assert!(
        result.diagnostics().is_empty(),
        "unexpected diagnostics: {:?}",
        result.diagnostics()
    );
    assert_eq!(result.entries.len(), 5);

    if let DisplayEntry::Item(ref item) = result.entries[0] {
        assert_eq!(item.label, "Amount to send");
    } else {
        panic!("expected Item for Amount to send");
    }
    if let DisplayEntry::Item(ref item) = result.entries[1] {
        assert_eq!(item.label, "Minimum to receive");
    } else {
        panic!("expected Item for Minimum to receive");
    }
    if let DisplayEntry::Item(ref item) = result.entries[2] {
        assert_eq!(item.label, "Destination chain ID");
        assert_eq!(item.value, "0");
    } else {
        panic!("expected Item for Destination chain ID");
    }
    if let DisplayEntry::Item(ref item) = result.entries[3] {
        assert_eq!(item.label, "Beneficiary");
        assert_eq!(item.value, "0xBf01daF454dce008d3E2bfD47d5e186F71477253");
    } else {
        panic!("expected Item for Beneficiary");
    }
    if let DisplayEntry::Item(ref item) = result.entries[4] {
        assert_eq!(item.label, "Expiration time");
    } else {
        panic!("expected Item for Expiration time");
    }
}

#[tokio::test]
async fn test_eip712_bare_primary_type_key_rejected() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Permit": {
                        "intent": "Permit",
                        "fields": [{ "path": "spender", "label": "Spender", "format": "address" }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(
        result.fallback_reason(),
        Some(&FallbackReason::FormatNotFound)
    );
    assert!(
        result
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.message.contains("no descriptor format matched")),
        "expected format-miss diagnostic, got {:?}",
        result.diagnostics()
    );
}

#[tokio::test]
async fn test_eip712_real_world_receive_with_authorization_canonical_key_formats() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 42161, "address": "0xaf88d065e77c8cc2239327c5edb3a432268e5831"}] } },
            "metadata": { "owner": "Circle", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)": {
                        "intent": "Authorize USDC transfer",
                        "fields": [
                            { "path": "from", "label": "From", "format": "addressName" },
                            { "path": "to", "label": "To", "format": "addressName" },
                            { "path": "value", "label": "Amount", "format": "tokenAmount", "params": { "tokenPath": "@.to" } }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "ReceiveWithAuthorization": [
                { "name": "from", "type": "address" },
                { "name": "to", "type": "address" },
                { "name": "value", "type": "uint256" },
                { "name": "validAfter", "type": "uint256" },
                { "name": "validBefore", "type": "uint256" },
                { "name": "nonce", "type": "bytes32" }
            ]
        },
        "primaryType": "ReceiveWithAuthorization",
        "domain": { "chainId": 42161, "verifyingContract": "0xaf88d065e77c8cc2239327c5edb3a432268e5831" },
        "message": {
            "from": "0xbf01daf454dce008d3e2bfd47d5e186f71477253",
            "to": "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
            "value": "6050000",
            "validAfter": 1774607678,
            "validBefore": 1774611338,
            "nonce": "0x073a2d085bbb11c3d51a9ce8ed3105ed0892dbaa516b8f2d2853fd4d6e0054d4"
        }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(
            descriptor,
            42161,
            "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
        ),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(result.intent, "Authorize USDC transfer");
}

#[tokio::test]
async fn test_eip712_prefix_only_format_key_rejected() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Permit(address spender,uint256 extra)": {
                        "intent": "Permit",
                        "fields": [{ "path": "spender", "label": "Spender", "format": "address" }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(
        result.fallback_reason(),
        Some(&FallbackReason::FormatNotFound)
    );
    assert!(
        result
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.message.contains("no descriptor format matched")),
        "expected format-miss diagnostic, got {:?}",
        result.diagnostics()
    );
}

#[tokio::test]
async fn test_eip712_canonical_key_wins_over_legacy_primary_type_key() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Permit": {
                        "intent": "Legacy Permit",
                        "fields": [{ "path": "spender", "label": "Legacy", "format": "address" }]
                    },
                    "Permit(address spender)": {
                        "intent": "Canonical Permit",
                        "fields": [{ "path": "spender", "label": "Canonical", "format": "address" }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(result.intent, "Canonical Permit");
    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.label, "Canonical"),
        _ => panic!("expected Item"),
    }
}

#[tokio::test]
async fn test_eip712_missing_chain_id_rejected_with_descriptors() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Permit(address spender)": {
                        "intent": "Permit",
                        "fields": [{ "path": "spender", "label": "Spender", "format": "address" }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": { "verifyingContract": "0xabc" },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(
        result.fallback_reason(),
        Some(&FallbackReason::InsufficientContext)
    );
    assert!(
        result
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.message.contains("domain.chainId is required")),
        "expected insufficient-context diagnostic, got {:?}",
        result.diagnostics()
    );
}

#[tokio::test]
async fn test_eip712_missing_verifying_contract_rejected_with_descriptors() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Permit(address spender)": {
                        "intent": "Permit",
                        "fields": [{ "path": "spender", "label": "Spender", "format": "address" }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": { "chainId": 1 },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(
        result.fallback_reason(),
        Some(&FallbackReason::InsufficientContext)
    );
    assert!(
        result.diagnostics().iter().any(|diagnostic| diagnostic
            .message
            .contains("domain.verifyingContract is required")),
        "expected insufficient-context diagnostic, got {:?}",
        result.diagnostics()
    );
}

/// A format may omit `intent` (optional per spec). The descriptor must still
/// parse rather than being rejected with "missing field `intent`".
#[tokio::test]
async fn test_format_without_intent_parses_and_renders() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "burn(uint256 amount)": {
                        "fields": [{ "label": "Amount", "path": "amount", "format": "number" }]
                    }
                }
            }
        }"#,
    )
    .expect("a format without intent must parse");

    assert!(descriptor
        .display
        .formats
        .get("burn(uint256 amount)")
        .expect("format present")
        .intent
        .is_none());

    let calldata = build_calldata("burn(uint256)", &[uint_word(5)]);
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let result = format_calldata(&wrap_rd(descriptor, 1, "0xabc"), &tx, &EmptyDataProvider)
        .await
        .unwrap();
    assert_eq!(
        semantic_item_snapshot(&result.entries),
        vec![("Amount".to_string(), "5".to_string())]
    );
}

#[tokio::test]
async fn test_eip712_outer_descriptor_match_is_required() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xdef"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Permit(address spender)": {
                        "intent": "Permit",
                        "fields": [{ "path": "spender", "label": "Spender", "format": "address" }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let err = format_typed_data(
        &wrap_rd(descriptor, 1, "0xdef"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("no EIP-712 descriptor found"));
}

#[tokio::test]
async fn test_eip712_descriptor_domain_name_match_succeeds() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}],
                    "domain": { "name": "Permit2" }
                }
            },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Permit(address spender)": {
                        "intent": "Permit",
                        "fields": [{ "path": "spender", "label": "Spender", "format": "address" }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": {
            "name": "Permit2",
            "chainId": 1,
            "verifyingContract": "0xabc"
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();

    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.label, "Spender"),
        _ => panic!("expected Item"),
    }
}

#[tokio::test]
async fn test_eip712_descriptor_domain_name_mismatch_rejects() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}],
                    "domain": { "name": "Permit2" }
                }
            },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": { "definitions": {}, "formats": { "Permit(address spender)": { "intent": "Permit", "fields": [] } } }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": {
            "name": "Other",
            "chainId": 1,
            "verifyingContract": "0xabc"
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let err = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();

    assert!(err.contains("descriptor eip712.domain.name mismatch"));
}

#[tokio::test]
async fn test_eip712_descriptor_domain_version_mismatch_rejects() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}],
                    "domain": { "version": "1" }
                }
            },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": { "definitions": {}, "formats": { "Permit(address spender)": { "intent": "Permit", "fields": [] } } }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": {
            "version": "2",
            "chainId": 1,
            "verifyingContract": "0xabc"
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let err = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();

    assert!(err.contains("descriptor eip712.domain.version mismatch"));
}

#[tokio::test]
async fn test_eip712_descriptor_domain_chain_id_mismatch_rejects_after_deployment_match() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}],
                    "domain": { "chainId": 10 }
                }
            },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": { "definitions": {}, "formats": { "Permit(address spender)": { "intent": "Permit", "fields": [] } } }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": {
            "chainId": 1,
            "verifyingContract": "0xabc"
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let err = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();

    assert!(err.contains("descriptor eip712.domain.chainId mismatch"));
}

#[tokio::test]
async fn test_eip712_descriptor_domain_verifying_contract_match_is_case_insensitive() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xaBc"}],
                    "domain": { "verifyingContract": "0xaBc" }
                }
            },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Permit(address spender)": {
                        "intent": "Permit",
                        "fields": [{ "path": "spender", "label": "Spender", "format": "address" }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": {
            "chainId": 1,
            "verifyingContract": "0xAbC"
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xaBc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();

    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.label, "Spender"),
        _ => panic!("expected Item"),
    }
}

#[tokio::test]
async fn test_eip712_descriptor_domain_salt_match_succeeds() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}],
                    "domain": { "salt": "0xdeadbeef" }
                }
            },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Permit(address spender)": {
                        "intent": "Permit",
                        "fields": [{ "path": "spender", "label": "Spender", "format": "address" }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": {
            "chainId": 1,
            "verifyingContract": "0xabc",
            "salt": "0Xdeadbeef"
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();

    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.label, "Spender"),
        _ => panic!("expected Item"),
    }
}

#[tokio::test]
async fn test_eip712_descriptor_domain_salt_mismatch_rejects() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}],
                    "domain": { "salt": "0xdeadbeef" }
                }
            },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": { "definitions": {}, "formats": { "Permit(address spender)": { "intent": "Permit", "fields": [] } } }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": {
            "chainId": 1,
            "verifyingContract": "0xabc",
            "salt": "0xbeefdead"
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let err = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();

    assert!(err.contains("descriptor eip712.domain.salt mismatch"));
}

#[tokio::test]
async fn test_eip712_descriptor_domain_salt_missing_rejects() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}],
                    "domain": { "salt": "0xdeadbeef" }
                }
            },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": { "definitions": {}, "formats": { "Permit(address spender)": { "intent": "Permit", "fields": [] } } }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": {
            "chainId": 1,
            "verifyingContract": "0xabc"
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let err = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();

    assert!(err.contains(
        "descriptor eip712.domain.salt is required by descriptor but missing from typed data"
    ));
}

#[tokio::test]
async fn test_eip712_descriptor_domain_omitted_field_is_not_enforced() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}],
                    "domain": { "name": "Permit2" }
                }
            },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Permit(address spender)": {
                        "intent": "Permit",
                        "fields": [{ "path": "spender", "label": "Spender", "format": "address" }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": {
            "name": "Permit2",
            "version": "7",
            "chainId": 1,
            "verifyingContract": "0xabc",
            "salt": "0x1234"
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();

    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.label, "Spender"),
        _ => panic!("expected Item"),
    }
}

#[tokio::test]
async fn test_eip712_domain_binding_selects_correct_descriptor() {
    let descriptor_a = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}],
                    "domain": { "name": "Permit2" }
                }
            },
            "metadata": { "owner": "a", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Permit(address spender)": {
                        "intent": "Permit A",
                        "fields": [{ "path": "spender", "label": "Spender A", "format": "address" }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let descriptor_b = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}],
                    "domain": { "name": "AllowanceTransfer" }
                }
            },
            "metadata": { "owner": "b", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Permit(address spender)": {
                        "intent": "Permit B",
                        "fields": [{ "path": "spender", "label": "Spender B", "format": "address" }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": {
            "name": "AllowanceTransfer",
            "chainId": 1,
            "verifyingContract": "0xabc"
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let descriptors = vec![
        wrap_rd(descriptor_a, 1, "0xabc")
            .into_iter()
            .next()
            .unwrap(),
        wrap_rd(descriptor_b, 1, "0xabc")
            .into_iter()
            .next()
            .unwrap(),
    ];

    let result = format_typed_data(&descriptors, &typed_data, &EmptyDataProvider)
        .await
        .unwrap();

    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.label, "Spender B"),
        _ => panic!("expected Item"),
    }
    assert_eq!(result.owner.as_deref(), Some("b"));
}

#[tokio::test]
async fn test_eip712_domain_binding_ambiguity_errors() {
    let descriptor_a = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}],
                    "domain": { "name": "Permit2" }
                }
            },
            "metadata": { "owner": "a", "enums": {}, "constants": {}, "maps": {} },
            "display": { "definitions": {}, "formats": { "Permit(address spender)": { "intent": "Permit A", "fields": [] } } }
        }"#,
    )
    .unwrap();

    let descriptor_b = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0xabc"}],
                    "domain": { "name": "Permit2" }
                }
            },
            "metadata": { "owner": "b", "enums": {}, "constants": {}, "maps": {} },
            "display": { "definitions": {}, "formats": { "Permit(address spender)": { "intent": "Permit B", "fields": [] } } }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Permit": [{ "name": "spender", "type": "address" }] },
        "primaryType": "Permit",
        "domain": {
            "name": "Permit2",
            "chainId": 1,
            "verifyingContract": "0xabc"
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let descriptors = vec![
        wrap_rd(descriptor_a, 1, "0xabc")
            .into_iter()
            .next()
            .unwrap(),
        wrap_rd(descriptor_b, 1, "0xabc")
            .into_iter()
            .next()
            .unwrap(),
    ];

    let err = format_typed_data(&descriptors, &typed_data, &EmptyDataProvider)
        .await
        .unwrap_err()
        .to_string();

    assert!(err.contains("multiple EIP-712 descriptors match"));
}

#[tokio::test]
async fn test_eip712_domain_separator_exact_match_succeeds() {
    let verifying_contract = "0x0000000000000000000000000000000000000abc";
    let separator = domain_separator_hex(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        "Permit2",
        "1",
        1,
        verifying_contract,
        &[],
    );

    let descriptor = Descriptor::from_json(&format!(
        r#"{{
            "context": {{
                "eip712": {{
                    "deployments": [{{"chainId": 1, "address": "{verifying_contract}"}}],
                    "domainSeparator": "{separator}"
                }}
            }},
            "metadata": {{"owner": "test", "enums": {{}}, "constants": {{}}, "maps": {{}}}},
            "display": {{
                "definitions": {{}},
                "formats": {{
                    "Permit(address spender)": {{
                        "intent": "Permit",
                        "fields": [{{ "path": "spender", "label": "Spender", "format": "address" }}]
                    }}
                }}
            }}
        }}"#
    ))
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "Permit": [{ "name": "spender", "type": "address" }]
        },
        "primaryType": "Permit",
        "domain": {
            "name": "Permit2",
            "version": "1",
            "chainId": 1,
            "verifyingContract": verifying_contract
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, verifying_contract),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();

    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.label, "Spender"),
        _ => panic!("expected Item"),
    }
}

#[tokio::test]
async fn test_eip712_domain_separator_mismatch_rejects() {
    let verifying_contract = "0x0000000000000000000000000000000000000abc";

    let descriptor = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0x0000000000000000000000000000000000000abc"}],
                    "domainSeparator": "0x1111111111111111111111111111111111111111111111111111111111111111"
                }
            },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": { "definitions": {}, "formats": { "Permit(address spender)": { "intent": "Permit", "fields": [] } } }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "Permit": [{ "name": "spender", "type": "address" }]
        },
        "primaryType": "Permit",
        "domain": {
            "name": "Permit2",
            "version": "1",
            "chainId": 1,
            "verifyingContract": verifying_contract
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let err = format_typed_data(
        &wrap_rd(descriptor, 1, verifying_contract),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();

    assert!(err.contains("descriptor eip712.domainSeparator mismatch"));
}

#[tokio::test]
async fn test_eip712_domain_separator_uppercase_prefix_validates() {
    let verifying_contract = "0x0000000000000000000000000000000000000abc";
    let separator = domain_separator_hex(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        "Permit2",
        "1",
        1,
        verifying_contract,
        &[],
    );
    let separator = format!("0X{}", separator.trim_start_matches("0x"));

    let descriptor = Descriptor::from_json(&format!(
        r#"{{
            "context": {{
                "eip712": {{
                    "deployments": [{{"chainId": 1, "address": "{verifying_contract}"}}],
                    "domainSeparator": "{separator}"
                }}
            }},
            "metadata": {{"owner": "test", "enums": {{}}, "constants": {{}}, "maps": {{}}}},
            "display": {{ "definitions": {{}}, "formats": {{ "Permit(address spender)": {{ "intent": "Permit", "fields": [] }} }} }}
        }}"#
    ))
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "Permit": [{ "name": "spender", "type": "address" }]
        },
        "primaryType": "Permit",
        "domain": {
            "name": "Permit2",
            "version": "1",
            "chainId": 1,
            "verifyingContract": verifying_contract
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    format_typed_data(
        &wrap_rd(descriptor, 1, verifying_contract),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_eip712_domain_separator_missing_type_rejects() {
    let verifying_contract = "0x0000000000000000000000000000000000000abc";

    let descriptor = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0x0000000000000000000000000000000000000abc"}],
                    "domainSeparator": "0x1111111111111111111111111111111111111111111111111111111111111111"
                }
            },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": { "definitions": {}, "formats": { "Permit(address spender)": { "intent": "Permit", "fields": [] } } }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "Permit": [{ "name": "spender", "type": "address" }]
        },
        "primaryType": "Permit",
        "domain": {
            "name": "Permit2",
            "version": "1",
            "chainId": 1,
            "verifyingContract": verifying_contract
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let err = format_typed_data(
        &wrap_rd(descriptor, 1, verifying_contract),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();

    assert!(err.contains("descriptor eip712.domainSeparator requires types.EIP712Domain"));
}

#[tokio::test]
async fn test_eip712_domain_separator_malformed_descriptor_hex_rejects() {
    let verifying_contract = "0x0000000000000000000000000000000000000abc";

    let descriptor = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0x0000000000000000000000000000000000000abc"}],
                    "domainSeparator": "0x1234"
                }
            },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": { "definitions": {}, "formats": { "Permit(address spender)": { "intent": "Permit", "fields": [] } } }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Permit": [{ "name": "spender", "type": "address" }]
        },
        "primaryType": "Permit",
        "domain": {
            "chainId": 1,
            "verifyingContract": verifying_contract
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let err = format_typed_data(
        &wrap_rd(descriptor, 1, verifying_contract),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();

    assert!(err.contains("descriptor eip712.domainSeparator must be 32-byte hex"));
}

#[tokio::test]
async fn test_eip712_domain_separator_missing_domain_field_rejects() {
    let verifying_contract = "0x0000000000000000000000000000000000000abc";
    let separator = domain_separator_hex(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        "Permit2",
        "1",
        1,
        verifying_contract,
        &[],
    );

    let descriptor = Descriptor::from_json(&format!(
        r#"{{
            "context": {{
                "eip712": {{
                    "deployments": [{{"chainId": 1, "address": "{verifying_contract}"}}],
                    "domainSeparator": "{separator}"
                }}
            }},
            "metadata": {{"owner": "test", "enums": {{}}, "constants": {{}}, "maps": {{}}}},
            "display": {{ "definitions": {{}}, "formats": {{ "Permit(address spender)": {{ "intent": "Permit", "fields": [] }} }} }}
        }}"#
    ))
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "Permit": [{ "name": "spender", "type": "address" }]
        },
        "primaryType": "Permit",
        "domain": {
            "name": "Permit2",
            "chainId": 1,
            "verifyingContract": verifying_contract
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let err = format_typed_data(
        &wrap_rd(descriptor, 1, verifying_contract),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();

    assert!(err.contains("descriptor eip712.domainSeparator requires domain field 'version'"));
}

#[tokio::test]
async fn test_eip712_domain_separator_extension_field_participates_in_hashing() {
    let verifying_contract = "0x0000000000000000000000000000000000000abc";
    let sub_account = "0x1111111111111111111111111111111111111111111111111111111111111111";
    let separator = domain_separator_hex(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 subAccount)",
        "Permit2",
        "1",
        1,
        verifying_contract,
        &[(bytes32_word(sub_account), "bytes32")],
    );

    let descriptor = Descriptor::from_json(&format!(
        r#"{{
            "context": {{
                "eip712": {{
                    "deployments": [{{"chainId": 1, "address": "{verifying_contract}"}}],
                    "domainSeparator": "{separator}"
                }}
            }},
            "metadata": {{"owner": "test", "enums": {{}}, "constants": {{}}, "maps": {{}}}},
            "display": {{ "definitions": {{}}, "formats": {{ "Permit(address spender)": {{ "intent": "Permit", "fields": [] }} }} }}
        }}"#
    ))
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" },
                { "name": "subAccount", "type": "bytes32" }
            ],
            "Permit": [{ "name": "spender", "type": "address" }]
        },
        "primaryType": "Permit",
        "domain": {
            "name": "Permit2",
            "version": "1",
            "chainId": 1,
            "verifyingContract": verifying_contract,
            "subAccount": sub_account
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    format_typed_data(
        &wrap_rd(descriptor, 1, verifying_contract),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn test_eip712_domain_separator_selects_correct_descriptor() {
    let verifying_contract = "0x0000000000000000000000000000000000000abc";
    let correct_separator = domain_separator_hex(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        "Permit2",
        "1",
        1,
        verifying_contract,
        &[],
    );

    let descriptor_a = Descriptor::from_json(
        r#"{
            "context": {
                "eip712": {
                    "deployments": [{"chainId": 1, "address": "0x0000000000000000000000000000000000000abc"}],
                    "domainSeparator": "0x1111111111111111111111111111111111111111111111111111111111111111"
                }
            },
            "metadata": {"owner": "a", "enums": {}, "constants": {}, "maps": {}},
            "display": { "definitions": {}, "formats": { "Permit(address spender)": { "intent": "A", "fields": [{ "path": "spender", "label": "Spender A", "format": "address" }] } } }
        }"#,
    )
    .unwrap();

    let descriptor_b = Descriptor::from_json(&format!(
        r#"{{
            "context": {{
                "eip712": {{
                    "deployments": [{{"chainId": 1, "address": "{verifying_contract}"}}],
                    "domainSeparator": "{correct_separator}"
                }}
            }},
            "metadata": {{"owner": "b", "enums": {{}}, "constants": {{}}, "maps": {{}}}},
            "display": {{ "definitions": {{}}, "formats": {{ "Permit(address spender)": {{ "intent": "B", "fields": [{{ "path": "spender", "label": "Spender B", "format": "address" }}] }} }} }}
        }}"#
    ))
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "Permit": [{ "name": "spender", "type": "address" }]
        },
        "primaryType": "Permit",
        "domain": {
            "name": "Permit2",
            "version": "1",
            "chainId": 1,
            "verifyingContract": verifying_contract
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let descriptors = vec![
        wrap_rd(descriptor_a, 1, verifying_contract)
            .into_iter()
            .next()
            .unwrap(),
        wrap_rd(descriptor_b, 1, verifying_contract)
            .into_iter()
            .next()
            .unwrap(),
    ];

    let result = format_typed_data(&descriptors, &typed_data, &EmptyDataProvider)
        .await
        .unwrap();

    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.label, "Spender B"),
        _ => panic!("expected Item"),
    }
    assert_eq!(result.owner.as_deref(), Some("b"));
}

#[tokio::test]
async fn test_eip712_domain_separator_ambiguity_errors() {
    let verifying_contract = "0x0000000000000000000000000000000000000abc";
    let separator = domain_separator_hex(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        "Permit2",
        "1",
        1,
        verifying_contract,
        &[],
    );

    let descriptor_a = Descriptor::from_json(&format!(
        r#"{{
            "context": {{
                "eip712": {{
                    "deployments": [{{"chainId": 1, "address": "{verifying_contract}"}}],
                    "domainSeparator": "{separator}"
                }}
            }},
            "metadata": {{"owner": "a", "enums": {{}}, "constants": {{}}, "maps": {{}}}},
            "display": {{ "definitions": {{}}, "formats": {{ "Permit(address spender)": {{ "intent": "A", "fields": [] }} }} }}
        }}"#
    ))
    .unwrap();

    let descriptor_b = Descriptor::from_json(&format!(
        r#"{{
            "context": {{
                "eip712": {{
                    "deployments": [{{"chainId": 1, "address": "{verifying_contract}"}}],
                    "domainSeparator": "{separator}"
                }}
            }},
            "metadata": {{"owner": "b", "enums": {{}}, "constants": {{}}, "maps": {{}}}},
            "display": {{ "definitions": {{}}, "formats": {{ "Permit(address spender)": {{ "intent": "B", "fields": [] }} }} }}
        }}"#
    ))
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "Permit": [{ "name": "spender", "type": "address" }]
        },
        "primaryType": "Permit",
        "domain": {
            "name": "Permit2",
            "version": "1",
            "chainId": 1,
            "verifyingContract": verifying_contract
        },
        "message": { "spender": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let descriptors = vec![
        wrap_rd(descriptor_a, 1, verifying_contract)
            .into_iter()
            .next()
            .unwrap(),
        wrap_rd(descriptor_b, 1, verifying_contract)
            .into_iter()
            .next()
            .unwrap(),
    ];

    let err = format_typed_data(&descriptors, &typed_data, &EmptyDataProvider)
        .await
        .unwrap_err()
        .to_string();

    assert!(err.contains("multiple EIP-712 descriptors match"));
}

#[tokio::test]
async fn test_eip712_sender_address_uses_container_from() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Transfer(address to)": {
                        "intent": "Transfer",
                        "fields": [{
                            "path": "to",
                            "label": "Recipient",
                            "format": "addressName",
                            "params": { "senderAddress": "@.from" }
                        }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Transfer": [{ "name": "to", "type": "address" }] },
        "primaryType": "Transfer",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "container": { "from": "0x1234567890123456789012345678901234567890" },
        "message": { "to": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.value, "Sender"),
        _ => panic!("expected Item"),
    }
}

#[tokio::test]
async fn test_eip712_sender_address_missing_container_from_errors() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Transfer(address to)": {
                        "intent": "Transfer",
                        "fields": [{
                            "path": "to",
                            "label": "Recipient",
                            "format": "addressName",
                            "params": { "senderAddress": "@.from" }
                        }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Transfer": [{ "name": "to", "type": "address" }] },
        "primaryType": "Transfer",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "to": "0x1234567890123456789012345678901234567890" }
    }))
    .unwrap();

    let err = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("@.from is required"));
}

#[tokio::test]
async fn test_calldata_interpolation_placeholder_without_field_spec_errors() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "foo(uint256)": {
                        "intent": "Foo",
                        "interpolatedIntent": "Missing {missing}",
                        "fields": [{ "path": "@.0", "label": "Value", "format": "number" }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let calldata = build_calldata("foo(uint256)", &[uint_word(42)]);
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };

    let result = format_calldata(&wrap_rd(descriptor, 1, "0xabc"), &tx, &EmptyDataProvider)
        .await
        .unwrap();
    assert_eq!(result.intent, "Foo");
    assert_interpolation_warning(&result, "does not match any display field");
}

#[tokio::test]
async fn test_calldata_interpolation_excluded_field_skips_interpolated_intent() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "foo(uint256)": {
                        "intent": "Foo",
                        "interpolatedIntent": "Value {value}",
                        "excluded": ["value"],
                        "fields": [{ "path": "value", "label": "Value", "format": "number" }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let calldata = build_calldata("foo(uint256)", &[uint_word(42)]);
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };

    let result = format_calldata(&wrap_rd(descriptor, 1, "0xabc"), &tx, &EmptyDataProvider)
        .await
        .unwrap();
    assert_eq!(result.intent, "Foo");
    assert_interpolation_warning(&result, "refers to an excluded field");
}

#[tokio::test]
async fn test_calldata_interpolation_unresolved_value_skips_interpolated_intent() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "foo(uint256)": {
                        "intent": "Foo",
                        "interpolatedIntent": "Missing {missing}",
                        "fields": [{ "path": "missing", "label": "Missing", "format": "number", "visible": "never" }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let calldata = build_calldata("foo(uint256)", &[uint_word(42)]);
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };

    let result = format_calldata(&wrap_rd(descriptor, 1, "0xabc"), &tx, &EmptyDataProvider)
        .await
        .unwrap();
    assert_eq!(result.intent, "Foo");
    assert_interpolation_warning(&result, "could not be resolved from calldata");
}

#[tokio::test]
async fn test_eip712_interpolation_placeholder_for_calldata_field_errors() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Relay(address to,bytes data)": {
                        "intent": "Relay",
                        "interpolatedIntent": "Relay {data}",
                        "fields": [
                            { "path": "to", "label": "To", "visible": "never" },
                            { "path": "data", "label": "Call", "format": "calldata", "params": { "calleePath": "to" } }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Relay": [
                { "name": "to", "type": "address" },
                { "name": "data", "type": "bytes" }
            ]
        },
        "primaryType": "Relay",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": {
            "to": "0x1234567890123456789012345678901234567890",
            "data": "0x12345678"
        }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(result.intent, "Relay");
    assert_interpolation_warning(&result, "non-stringable calldata field");
}

#[tokio::test]
async fn test_eip712_group_only_interpolation_path_errors() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Quote(Details details)Details(uint256 amount)": {
                        "intent": "Quote",
                        "interpolatedIntent": "Quote {details}",
                        "fields": [{
                            "path": "details",
                            "fields": [
                                { "path": "amount", "label": "Amount", "format": "number" }
                            ]
                        }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Quote": [{ "name": "details", "type": "Details" }],
            "Details": [{ "name": "amount", "type": "uint256" }]
        },
        "primaryType": "Quote",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "details": { "amount": 1250 } }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(result.intent, "Quote");
    assert_interpolation_warning(&result, "does not match any display field");
}

#[tokio::test]
async fn test_eip712_interpolation_unresolved_value_skips_interpolated_intent() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Quote(uint256 amount)": {
                        "intent": "Quote",
                        "interpolatedIntent": "Quote {missing}",
                        "fields": [
                            { "path": "missing", "label": "Missing", "format": "number", "visible": "never" }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Quote": [{ "name": "amount", "type": "uint256" }]
        },
        "primaryType": "Quote",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "amount": 1250 }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(result.intent, "Quote");
    assert_interpolation_warning(&result, "could not be resolved from typed data");
}

#[tokio::test]
async fn test_eip712_scoped_field_interpolation_matches_rendering() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Quote(Details details)Details(uint256 amount)": {
                        "intent": "Quote",
                        "interpolatedIntent": "Quote {details.amount}",
                        "fields": [{
                            "path": "details",
                            "fields": [
                                { "path": "amount", "label": "Amount", "format": "unit", "params": { "base": "%", "decimals": 2 } }
                            ]
                        }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Quote": [{ "name": "details", "type": "Details" }],
            "Details": [{ "name": "amount", "type": "uint256" }]
        },
        "primaryType": "Quote",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "details": { "amount": 1250 } }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.value, "12.5%"),
        _ => panic!("expected Item"),
    }
    assert_eq!(result.interpolated_intent.as_deref(), Some("Quote 12.5%"));
}

#[tokio::test]
async fn test_eip712_ref_field_interpolation_matches_rendering() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {
                    "rateField": {
                        "label": "Rate",
                        "format": "unit",
                        "params": { "base": "%", "decimals": 2 }
                    }
                },
                "formats": {
                    "SetRate(uint256 rate)": {
                        "intent": "Set rate",
                        "interpolatedIntent": "Rate {rate}",
                        "fields": [
                            { "$ref": "$.display.definitions.rateField", "path": "rate" }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "SetRate": [{ "name": "rate", "type": "uint256" }] },
        "primaryType": "SetRate",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "rate": 1250 }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.value, "12.5%"),
        _ => panic!("expected Item"),
    }
    assert_eq!(result.interpolated_intent.as_deref(), Some("Rate 12.5%"));
}

#[tokio::test]
async fn test_eip712_interpolation_uses_same_formatting_as_fields() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": {
                "owner": "test",
                "enums": { "kind": { "2": "Variable" } },
                "constants": {},
                "maps": {}
            },
            "display": {
                "definitions": {},
                "formats": {
                    "Order(address to,uint256 amount,uint256 deadline,uint8 kind)": {
                        "intent": "Order",
                        "interpolatedIntent": "Send {amount} to {to} as {kind} before {deadline}",
                        "fields": [
                            { "path": "to", "label": "To", "format": "addressName", "params": { "senderAddress": "0x1234567890123456789012345678901234567890" } },
                            { "path": "amount", "label": "Amount", "format": "tokenAmount", "params": { "token": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" } },
                            { "path": "kind", "label": "Kind", "format": "enum", "params": { "enumPath": "kind" } },
                            { "path": "deadline", "label": "Deadline", "format": "date", "params": { "encoding": "timestamp" } }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Order": [
                { "name": "to", "type": "address" },
                { "name": "amount", "type": "uint256" },
                { "name": "deadline", "type": "uint256" },
                { "name": "kind", "type": "uint8" }
            ]
        },
        "primaryType": "Order",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": {
            "to": "0x1234567890123456789012345678901234567890",
            "amount": "1500000",
            "deadline": 1700000000,
            "kind": 2
        }
    }))
    .unwrap();

    let mut tokens = StaticTokenSource::new();
    tokens.insert(
        1,
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        TokenMeta {
            symbol: "USDC".to_string(),
            decimals: 6,
            name: "USD Coin".to_string(),
        },
    );

    let result = format_typed_data(&wrap_rd(descriptor, 1, "0xabc"), &typed_data, &tokens)
        .await
        .unwrap();
    assert_eq!(
        result.interpolated_intent.as_deref(),
        Some("Send 1.5 USDC to Sender as Variable before 2023-11-14 22:13:20Z")
    );
}

#[tokio::test]
async fn test_visible_optional_displays_by_default() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "show(uint256 value)": {
                        "intent": "Show",
                        "fields": [
                            { "path": "value", "label": "Value", "format": "number", "visible": "optional" }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let calldata = build_calldata("show(uint256)", &[uint_word(7)]);
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };

    let result = format_calldata(&wrap_rd(descriptor, 1, "0xabc"), &tx, &EmptyDataProvider)
        .await
        .unwrap();
    assert_eq!(result.entries.len(), 1);
    match &result.entries[0] {
        DisplayEntry::Item(item) => {
            assert_eq!(item.label, "Value");
            assert_eq!(item.value, "7");
        }
        _ => panic!("expected Item"),
    }
}

#[test]
fn test_unknown_visibility_string_is_rejected() {
    assert!(Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "show(uint256 value)": {
                        "intent": "Show",
                        "fields": [
                            { "path": "value", "label": "Value", "visible": "sometimes" }
                        ]
                    }
                }
            }
        }"#,
    )
    .is_err());
}

#[tokio::test]
async fn test_visible_if_not_in_hides_matching_value_and_shows_non_matching() {
    let descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "show(uint256 value)": {
                        "intent": "Show",
                        "fields": [
                            {
                                "path": "value",
                                "label": "Value",
                                "format": "number",
                                "visible": { "ifNotIn": [uint_hex_literal(0)] }
                            }
                        ]
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let hidden = build_calldata("show(uint256)", &[uint_word(0)]);
    let hidden_tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &hidden,
        value: None,
        from: None,
        implementation_address: None,
    };
    let hidden_result = format_calldata(
        &wrap_rd(descriptor.clone(), 1, "0xabc"),
        &hidden_tx,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert!(hidden_result.entries.is_empty());

    let shown = build_calldata("show(uint256)", &[uint_word(9)]);
    let shown_tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &shown,
        value: None,
        from: None,
        implementation_address: None,
    };
    let shown_result = format_calldata(
        &wrap_rd(descriptor, 1, "0xabc"),
        &shown_tx,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(shown_result.entries.len(), 1);
}

#[tokio::test]
async fn test_visible_must_match_hides_matching_value_and_errors_on_mismatch() {
    let descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "show(uint256 guard,uint256 value)": {
                        "intent": "Show",
                        "fields": [
                            {
                                "path": "guard",
                                "label": "Guard",
                                "format": "number",
                                "visible": { "mustMatch": [uint_hex_literal(1)] }
                            },
                            { "path": "value", "label": "Value", "format": "number" }
                        ]
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let matching = build_calldata("show(uint256,uint256)", &[uint_word(1), uint_word(5)]);
    let matching_tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &matching,
        value: None,
        from: None,
        implementation_address: None,
    };
    let matching_result = format_calldata(
        &wrap_rd(descriptor.clone(), 1, "0xabc"),
        &matching_tx,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(matching_result.entries.len(), 1);
    match &matching_result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.label, "Value"),
        _ => panic!("expected Item"),
    }

    let mismatching = build_calldata("show(uint256,uint256)", &[uint_word(2), uint_word(5)]);
    let mismatching_tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &mismatching,
        value: None,
        from: None,
        implementation_address: None,
    };
    let err = format_calldata(
        &wrap_rd(descriptor, 1, "0xabc"),
        &mismatching_tx,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("visible.mustMatch"));
}

#[tokio::test]
async fn test_typed_visibility_alias_must_be_behaves_like_must_match() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Permit(uint256 flag,uint256 value)": {
                        "intent": "Permit",
                        "fields": [
                            { "path": "flag", "label": "Flag", "format": "number", "visible": { "mustBe": [1] } },
                            { "path": "value", "label": "Value", "format": "number" }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Permit": [
                { "name": "flag", "type": "uint256" },
                { "name": "value", "type": "uint256" }
            ]
        },
        "primaryType": "Permit",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "flag": 1, "value": 9 }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(result.entries.len(), 1);
    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.label, "Value"),
        _ => panic!("expected Item"),
    }
}

#[tokio::test]
async fn test_typed_visibility_must_match_errors_when_value_missing() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Permit(uint256 value)": {
                        "intent": "Permit",
                        "fields": [
                            { "path": "missing", "label": "Missing", "format": "number", "visible": { "mustMatch": [1] } }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Permit": [{ "name": "value", "type": "uint256" }]
        },
        "primaryType": "Permit",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "value": 9 }
    }))
    .unwrap();

    let err = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("visible.mustMatch"));
}

#[test]
fn test_nested_calldata_constant_params_parse() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "outer(bytes data)": {
                        "intent": "Outer",
                        "fields": [{
                            "path": "data",
                            "label": "Inner",
                            "format": "calldata",
                            "params": {
                                "callee": "0x1000000000000000000000000000000000000001",
                                "selector": "0x12345678",
                                "chainId": 10,
                                "amount": "42",
                                "spender": "0x2000000000000000000000000000000000000002"
                            }
                        }]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let field = descriptor.display.formats["outer(bytes data)"].fields[0].clone();
    if let clear_signing::types::display::DisplayField::Simple { params, .. } = field {
        let params = params.unwrap();
        assert_eq!(
            params.callee.as_deref(),
            Some("0x1000000000000000000000000000000000000001")
        );
        assert_eq!(params.selector.as_deref(), Some("0x12345678"));
        assert_eq!(params.chain_id, Some(10));
        assert_eq!(
            params.spender.as_deref(),
            Some("0x2000000000000000000000000000000000000002")
        );
        assert_eq!(
            params.amount.unwrap().to_biguint().unwrap().to_string(),
            "42"
        );
    } else {
        panic!("expected Simple field");
    }
}

#[tokio::test]
async fn test_calldata_nested_calldata_constant_params_render() {
    let inner_sig = decoder::parse_signature("consume()").unwrap();
    let inner_selector = format!("0x{}", hex::encode(inner_sig.selector));
    let inner_addr = "0x1000000000000000000000000000000000000001";
    let spender = "0x2000000000000000000000000000000000000002";

    let outer_json = format!(
        r#"{{
            "context": {{ "contract": {{ "deployments": [{{"chainId": 1, "address": "0xabc"}}] }} }},
            "metadata": {{ "owner": "test", "enums": {{}}, "constants": {{}}, "maps": {{}} }},
            "display": {{
                "definitions": {{}},
                "formats": {{
                    "outer(bytes data)": {{
                        "intent": "Outer",
                        "fields": [{{
                            "path": "data",
                            "label": "Inner",
                            "format": "calldata",
                            "params": {{
                                "callee": "{inner_addr}",
                                "selector": "{inner_selector}",
                                "chainId": 10,
                                "amount": "7",
                                "spender": "{spender}"
                            }}
                        }}]
                    }}
                }}
            }}
        }}"#
    );
    let outer = Descriptor::from_json(&outer_json).unwrap();
    let inner = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 10, "address": "0x1000000000000000000000000000000000000001"}] } },
            "metadata": { "owner": "inner", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "consume()": {
                        "intent": "Consume",
                        "fields": [
                            { "path": "@.from", "label": "Spender", "format": "address" },
                            { "path": "@.value", "label": "Amount", "format": "number" }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let calldata = build_single_bytes_calldata("outer(bytes)", &[]);
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };

    let descriptors = vec![
        wrap_rd(outer, 1, "0xabc").into_iter().next().unwrap(),
        wrap_rd(inner, 10, inner_addr).into_iter().next().unwrap(),
    ];
    let result = format_calldata(&descriptors, &tx, &EmptyDataProvider)
        .await
        .unwrap();

    match &result.entries[0] {
        DisplayEntry::Nested {
            intent, entries, ..
        } => {
            assert_eq!(intent, "Consume");
            assert!(entries.iter().any(|entry| matches!(
                entry,
                DisplayEntry::Item(item) if item.label == "Spender" && item.value == "0x2000000000000000000000000000000000000002"
            )));
            assert!(entries.iter().any(|entry| matches!(
                entry,
                DisplayEntry::Item(item) if item.label == "Amount" && item.value == "7"
            )));
        }
        _ => panic!("expected Nested entry"),
    }
}

#[tokio::test]
async fn test_typed_nested_calldata_selector_path_and_chain_id_path_render() {
    let inner_sig = decoder::parse_signature("consume()").unwrap();
    let inner_selector = format!("0x{}", hex::encode(inner_sig.selector));
    let inner_addr = "0x1000000000000000000000000000000000000001";

    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Relay(address target,uint256 targetChainId,bytes4 selector,bytes data)": {
                        "intent": "Relay",
                        "fields": [{
                            "path": "data",
                            "label": "Inner",
                            "format": "calldata",
                            "params": {
                                "calleePath": "target",
                                "chainIdPath": "targetChainId",
                                "selectorPath": "selector"
                            }
                        }]
                    }
                }
            }
        }"#,
    )
    .unwrap();
    let inner = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 10, "address": "0x1000000000000000000000000000000000000001"}] } },
            "metadata": { "owner": "inner", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "consume()": {
                        "intent": "Consume",
                        "fields": []
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Relay": [
                { "name": "target", "type": "address" },
                { "name": "targetChainId", "type": "uint256" },
                { "name": "selector", "type": "bytes4" },
                { "name": "data", "type": "bytes" }
            ]
        },
        "primaryType": "Relay",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": {
            "target": inner_addr,
            "targetChainId": 10,
            "selector": inner_selector,
            "data": "0x"
        }
    }))
    .unwrap();

    let descriptors = vec![
        wrap_rd(descriptor, 1, "0xabc").into_iter().next().unwrap(),
        wrap_rd(inner, 10, inner_addr).into_iter().next().unwrap(),
    ];
    let result = format_typed_data(&descriptors, &typed_data, &EmptyDataProvider)
        .await
        .unwrap();

    match &result.entries[0] {
        DisplayEntry::Nested { intent, .. } => assert_eq!(intent, "Consume"),
        _ => panic!("expected Nested entry"),
    }
}

#[tokio::test]
async fn test_typed_nested_calldata_constant_params_render() {
    let inner_sig = decoder::parse_signature("consume()").unwrap();
    let inner_selector = format!("0x{}", hex::encode(inner_sig.selector));
    let inner_addr = "0x1000000000000000000000000000000000000001";
    let spender = "0x2000000000000000000000000000000000000002";

    let descriptor = Descriptor::from_json(&format!(
        r#"{{
            "context": {{ "eip712": {{ "deployments": [{{"chainId": 1, "address": "0xabc"}}] }} }},
            "metadata": {{ "owner": "test", "enums": {{}}, "constants": {{}}, "maps": {{}} }},
            "display": {{
                "definitions": {{}},
                "formats": {{
                    "Relay(bytes data)": {{
                        "intent": "Relay",
                        "fields": [{{
                            "path": "data",
                            "label": "Inner",
                            "format": "calldata",
                            "params": {{
                                "callee": "{inner_addr}",
                                "chainId": 10,
                                "selector": "{inner_selector}",
                                "amount": "9",
                                "spender": "{spender}"
                            }}
                        }}]
                    }}
                }}
            }}
        }}"#
    ))
    .unwrap();
    let inner = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 10, "address": "0x1000000000000000000000000000000000000001"}] } },
            "metadata": { "owner": "inner", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "consume()": {
                        "intent": "Consume",
                        "fields": [
                            { "path": "@.from", "label": "Spender", "format": "address" },
                            { "path": "@.value", "label": "Amount", "format": "number" }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Relay": [{ "name": "data", "type": "bytes" }]
        },
        "primaryType": "Relay",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "data": "0x" }
    }))
    .unwrap();

    let descriptors = vec![
        wrap_rd(descriptor, 1, "0xabc").into_iter().next().unwrap(),
        wrap_rd(inner, 10, inner_addr).into_iter().next().unwrap(),
    ];
    let result = format_typed_data(&descriptors, &typed_data, &EmptyDataProvider)
        .await
        .unwrap();

    match &result.entries[0] {
        DisplayEntry::Nested { entries, .. } => {
            assert!(entries.iter().any(|entry| matches!(
                entry,
                DisplayEntry::Item(item) if item.label == "Spender" && item.value == spender
            )));
            assert!(entries.iter().any(|entry| matches!(
                entry,
                DisplayEntry::Item(item) if item.label == "Amount" && item.value == "9"
            )));
        }
        _ => panic!("expected Nested entry"),
    }
}

#[tokio::test]
async fn test_nested_calldata_conflicting_constant_and_path_params_error() {
    let selector = format!(
        "0x{}",
        hex::encode(decoder::parse_signature("consume()").unwrap().selector)
    );
    let descriptor = Descriptor::from_json(&format!(
        r#"{{
            "context": {{ "contract": {{ "deployments": [{{"chainId": 1, "address": "0xabc"}}] }} }},
            "metadata": {{ "owner": "test", "enums": {{}}, "constants": {{}}, "maps": {{}} }},
            "display": {{
                "definitions": {{}},
                "formats": {{
                    "outer(bytes data)": {{
                        "intent": "Outer",
                        "fields": [{{
                            "path": "data",
                            "label": "Inner",
                            "format": "calldata",
                            "params": {{
                                "callee": "0x1000000000000000000000000000000000000001",
                                "calleePath": "missing",
                                "selector": "{selector}"
                            }}
                        }}]
                    }}
                }}
            }}
        }}"#
    ))
    .unwrap();
    let calldata = build_single_bytes_calldata("outer(bytes)", &[]);
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };

    let err = format_calldata(&wrap_rd(descriptor, 1, "0xabc"), &tx, &EmptyDataProvider)
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("both constant and path forms"));
}

#[tokio::test]
async fn test_nested_calldata_malformed_constant_params_error() {
    let calldata = build_single_bytes_calldata("outer(bytes)", &[]);
    let cases = [
        (r#""callee": "0x1234", "selector": "0x12345678""#, "callee"),
        (
            r#""callee": "0x1000000000000000000000000000000000000001", "selector": "0x1234""#,
            "selector",
        ),
        (
            r#""callee": "0x1000000000000000000000000000000000000001", "selector": "0x12345678", "amount": "not-a-number""#,
            "amount",
        ),
    ];

    for (params_body, expected_param) in cases {
        let descriptor = Descriptor::from_json(&format!(
            r#"{{
                "context": {{ "contract": {{ "deployments": [{{"chainId": 1, "address": "0xabc"}}] }} }},
                "metadata": {{ "owner": "test", "enums": {{}}, "constants": {{}}, "maps": {{}} }},
                "display": {{
                    "definitions": {{}},
                    "formats": {{
                        "outer(bytes data)": {{
                            "intent": "Outer",
                            "fields": [{{
                                "path": "data",
                                "label": "Inner",
                                "format": "calldata",
                                "params": {{ {params_body} }}
                            }}]
                        }}
                    }}
                }}
            }}"#
        ))
        .unwrap();

        let tx = TransactionContext {
            chain_id: 1,
            to: "0xabc",
            calldata: &calldata,
            value: None,
            from: None,
            implementation_address: None,
        };
        let err = format_calldata(&wrap_rd(descriptor, 1, "0xabc"), &tx, &EmptyDataProvider)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(expected_param), "{err}");
    }
}

#[tokio::test]
async fn test_unresolved_nested_callee_renders_scalar_hex() {
    let selector = format!(
        "0x{}",
        hex::encode(decoder::parse_signature("consume()").unwrap().selector)
    );
    let descriptor = Descriptor::from_json(&format!(
        r#"{{
            "context": {{ "contract": {{ "deployments": [{{"chainId": 1, "address": "0xabc"}}] }} }},
            "metadata": {{ "owner": "test", "enums": {{}}, "constants": {{}}, "maps": {{}} }},
            "display": {{
                "definitions": {{}},
                "formats": {{
                    "outer(bytes data)": {{
                        "intent": "Outer",
                        "fields": [{{
                            "path": "data",
                            "label": "Inner",
                            "format": "calldata",
                            "params": {{
                                "calleePath": "missing",
                                "selector": "{selector}"
                            }}
                        }}]
                    }}
                }}
            }}
        }}"#
    ))
    .unwrap();

    let calldata = build_single_bytes_calldata("outer(bytes)", &[]);
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let result = format_calldata(&wrap_rd(descriptor, 1, "0xabc"), &tx, &EmptyDataProvider)
        .await
        .unwrap();

    // Unresolvable callee → the calldata field degrades to a scalar hex value
    // (empty inner data here), not a degraded Nested entry.
    assert_eq!(
        result.fallback_reason(),
        Some(&FallbackReason::NestedCallNotClearSigned)
    );
    match &result.entries[0] {
        DisplayEntry::Item(item) => {
            assert_eq!(item.label, "Inner");
            assert_eq!(item.value, "0x");
        }
        _ => panic!("expected scalar Item entry"),
    }
}

#[tokio::test]
async fn test_degraded_nested_calldata_renders_scalar() {
    // A calldata field whose callee can't be resolved degrades to a scalar hex
    // value (not a degraded Nested entry) — identically on calldata and EIP-712 —
    // and the outer model still reports the nested-call fallback.
    let inner = hex::decode("1234567890").unwrap();
    let inner_hex = format!("0x{}", hex::encode(&inner));

    let calldata_descriptor = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": {
                "definitions": {},
                "formats": {
                    "outer(bytes data)": {
                        "intent": "Outer",
                        "fields": [
                            {"path": "data", "label": "Inner", "format": "calldata", "params": {"calleePath": "missing"}}
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();
    let calldata = build_single_bytes_calldata("outer(bytes)", &inner);
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let calldata_result = format_calldata(
        &wrap_rd(calldata_descriptor, 1, "0xabc"),
        &tx,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(
        calldata_result.fallback_reason(),
        Some(&FallbackReason::NestedCallNotClearSigned)
    );
    match &calldata_result.entries[0] {
        DisplayEntry::Item(item) => {
            assert_eq!(item.label, "Inner");
            assert_eq!(item.value, inner_hex);
        }
        _ => panic!("expected scalar Item on calldata path"),
    }

    let typed_descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
            "display": {
                "definitions": {},
                "formats": {
                    "Outer(bytes data)": {
                        "intent": "Outer",
                        "fields": [
                            {"path": "data", "label": "Inner", "format": "calldata", "params": {"calleePath": "missing"}}
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();
    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": { "EIP712Domain": [], "Outer": [{ "name": "data", "type": "bytes" }] },
        "primaryType": "Outer",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": { "data": inner_hex }
    }))
    .unwrap();
    let typed_result = format_typed_data(
        &wrap_rd(typed_descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(
        typed_result.fallback_reason(),
        Some(&FallbackReason::NestedCallNotClearSigned)
    );

    assert_semantic_parity(&calldata_result, &typed_result);
}

#[tokio::test]
async fn test_resolver_finds_nested_descriptor_with_constant_callee_and_chain_id() {
    let inner_sig = decoder::parse_signature("consume()").unwrap();
    let selector = format!("0x{}", hex::encode(inner_sig.selector));
    let outer = Descriptor::from_json(&format!(
        r#"{{
            "context": {{ "contract": {{ "deployments": [{{"chainId": 1, "address": "0xabc"}}] }} }},
            "metadata": {{ "owner": "test", "enums": {{}}, "constants": {{}}, "maps": {{}} }},
            "display": {{
                "definitions": {{}},
                "formats": {{
                    "outer(bytes data)": {{
                        "intent": "Outer",
                        "fields": [{{
                            "path": "data",
                            "label": "Inner",
                            "format": "calldata",
                            "params": {{
                                "callee": "0x1000000000000000000000000000000000000001",
                                "chainId": 10,
                                "selector": "{selector}"
                            }}
                        }}]
                    }}
                }}
            }}
        }}"#
    ))
    .unwrap();
    let inner = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 10, "address": "0x1000000000000000000000000000000000000001"}] } },
            "metadata": { "owner": "inner", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": { "consume()": { "intent": "Consume", "fields": [] } }
            }
        }"#,
    )
    .unwrap();

    let mut source = clear_signing::resolver::StaticSource::new();
    source.add_calldata(1, "0xabc", outer);
    source.add_calldata(10, "0x1000000000000000000000000000000000000001", inner);

    let calldata = build_single_bytes_calldata("outer(bytes)", &[]);
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let descriptors = clear_signing::resolve_descriptors_for_tx(&tx, &source, None)
        .await
        .unwrap();
    assert_eq!(descriptors.len(), 2);
    assert_eq!(
        descriptors[1].address,
        "0x1000000000000000000000000000000000000001"
    );
    assert_eq!(descriptors[1].chain_id, 10);
}

// ─── ERC-7730 `encryption`: calldata / EIP-712 parity ───

/// The handle both containers carry for the encrypted amount.
const ENCRYPTED_HANDLE: &str = "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const CONFIDENTIAL_TOKEN: &str = "0x00000000000000000000000000000000000000c1";
/// The wrapper contract, i.e. calldata's `@.to` and the typed domain's
/// `verifyingContract` — the container the wallet checks access against.
const ENCRYPTION_CONTRACT: &str = "0x0000000000000000000000000000000000000abc";

/// Wallet that can decrypt the handle above and knows the token, recording the
/// container it was handed so both flows can be compared.
struct DecryptingProvider {
    calls: std::sync::Mutex<Vec<(u64, Option<String>)>>,
}

impl DecryptingProvider {
    fn new() -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl clear_signing::DataProvider for DecryptingProvider {
    fn resolve_token(
        &self,
        chain_id: u64,
        address: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Option<clear_signing::TokenMeta>> + Send + '_>,
    > {
        let hit = chain_id == 1 && address.eq_ignore_ascii_case(CONFIDENTIAL_TOKEN);
        Box::pin(async move {
            hit.then(|| clear_signing::TokenMeta {
                symbol: "cUSDC".to_string(),
                decimals: 6,
                name: "Confidential USDC".to_string(),
            })
        })
    }

    fn resolve_decrypted_value(
        &self,
        chain_id: u64,
        encrypted_value: &str,
        scheme: &str,
        contract_address: Option<&str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send + '_>> {
        // Recorded verbatim: both containers must hand the wallet the same
        // chain and the same EIP-55 checksummed contract, not merely the same
        // address in some casing.
        self.calls
            .lock()
            .unwrap()
            .push((chain_id, contract_address.map(str::to_string)));
        let hit = scheme == "fhevm" && encrypted_value.eq_ignore_ascii_case(ENCRYPTED_HANDLE);
        Box::pin(async move { hit.then(|| format!("0x{:016x}", 1_000_000u64)) })
    }
}

fn encrypted_amount_fields() -> serde_json::Value {
    serde_json::json!([
        {
            "path": "amount",
            "label": "Amount",
            "format": "tokenAmount",
            "params": { "token": CONFIDENTIAL_TOKEN },
            "encryption": {
                "scheme": "fhevm",
                "plaintextType": "uint64",
                "fallbackLabel": "[Encrypted Amount]"
            }
        }
    ])
}

fn encrypted_calldata_descriptor() -> Vec<ResolvedDescriptor> {
    let descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": { "contract": { "deployments": [{"chainId": 1, "address": ENCRYPTION_CONTRACT}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "confidentialTransfer(bytes32 amount)": {
                        "intent": "Confidential transfer",
                        "fields": encrypted_amount_fields()
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();
    wrap_rd(descriptor, 1, ENCRYPTION_CONTRACT)
}

fn encrypted_typed_descriptor() -> Vec<ResolvedDescriptor> {
    let descriptor = Descriptor::from_json(
        &serde_json::json!({
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": ENCRYPTION_CONTRACT}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "ConfidentialTransfer(bytes32 amount)": {
                        "intent": "Confidential transfer",
                        "fields": encrypted_amount_fields()
                    }
                }
            }
        })
        .to_string(),
    )
    .unwrap();
    wrap_rd(descriptor, 1, ENCRYPTION_CONTRACT)
}

fn encrypted_typed_data() -> TypedData {
    serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "ConfidentialTransfer": [{ "name": "amount", "type": "bytes32" }]
        },
        "primaryType": "ConfidentialTransfer",
        "domain": { "chainId": 1, "verifyingContract": ENCRYPTION_CONTRACT },
        "message": { "amount": ENCRYPTED_HANDLE }
    }))
    .unwrap()
}

fn encrypted_calldata() -> Vec<u8> {
    let mut handle = [0u8; 32];
    handle.copy_from_slice(&hex::decode(ENCRYPTED_HANDLE.trim_start_matches("0x")).unwrap());
    build_calldata("confidentialTransfer(bytes32)", &[handle])
}

#[tokio::test]
async fn test_eip712_encryption_decrypts_like_calldata() {
    // Typed data must reach the wallet's decryptor exactly as calldata does,
    // using the domain's chainId and verifyingContract as the container.
    let calldata = encrypted_calldata();
    let tx = TransactionContext {
        chain_id: 1,
        to: ENCRYPTION_CONTRACT,
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };

    let calldata_provider = DecryptingProvider::new();
    let calldata_result =
        format_calldata(&encrypted_calldata_descriptor(), &tx, &calldata_provider)
            .await
            .unwrap();

    let typed_provider = DecryptingProvider::new();
    let typed_result = format_typed_data(
        &encrypted_typed_descriptor(),
        &encrypted_typed_data(),
        &typed_provider,
    )
    .await
    .unwrap();

    assert_eq!(
        semantic_item_snapshot(&calldata_result.entries),
        vec![("Amount".to_string(), "1 cUSDC".to_string())]
    );
    assert_semantic_parity(&calldata_result, &typed_result);
    assert!(calldata_result.diagnostics().is_empty());
    assert!(typed_result.diagnostics().is_empty());

    // Both containers report the handle beside the plaintext.
    for result in [&calldata_result, &typed_result] {
        assert_eq!(
            raw_encrypted_values(&result.entries),
            vec![Some(ENCRYPTED_HANDLE.to_string())]
        );
    }

    // Both flows hand the wallet the same chain and the same container contract,
    // compared verbatim — typed data must EIP-55 checksum it exactly as calldata
    // does rather than passing the domain string through as authored.
    let calldata_calls = calldata_provider.calls.lock().unwrap().clone();
    let typed_calls = typed_provider.calls.lock().unwrap().clone();
    assert_eq!(calldata_calls, typed_calls);
    assert_eq!(calldata_calls.len(), 1);
    let (chain_id, contract) = &calldata_calls[0];
    assert_eq!(*chain_id, 1);
    assert!(contract
        .as_deref()
        .is_some_and(|c| c.eq_ignore_ascii_case(ENCRYPTION_CONTRACT)));
}

#[tokio::test]
async fn test_eip712_encryption_falls_back_like_calldata() {
    // No decryptor: both containers render the descriptor's fallbackLabel and
    // report `decryption_failed`, and neither leaks the handle.
    let calldata = encrypted_calldata();
    let tx = TransactionContext {
        chain_id: 1,
        to: ENCRYPTION_CONTRACT,
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let calldata_result =
        format_calldata(&encrypted_calldata_descriptor(), &tx, &EmptyDataProvider)
            .await
            .unwrap();
    let typed_result = format_typed_data(
        &encrypted_typed_descriptor(),
        &encrypted_typed_data(),
        &EmptyDataProvider,
    )
    .await
    .unwrap();

    assert_eq!(
        semantic_item_snapshot(&typed_result.entries),
        vec![("Amount".to_string(), "[Encrypted Amount]".to_string())]
    );
    assert_semantic_parity(&calldata_result, &typed_result);
    for result in [&calldata_result, &typed_result] {
        assert!(result
            .diagnostics()
            .iter()
            .any(|d| d.code == "decryption_failed"));
        // The fallback label hides the value, so the handle is what lets a wallet
        // show that something real was withheld.
        assert_eq!(
            raw_encrypted_values(&result.entries),
            vec![Some(ENCRYPTED_HANDLE.to_string())]
        );
    }
}

#[tokio::test]
async fn test_visible_must_match_compares_decimal_and_checksummed_address() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "show(uint8 kind,address zone,uint256 value)": {
                        "intent": "Show",
                        "fields": [
                            { "path": "kind", "label": "Kind", "format": "raw", "visible": { "mustMatch": ["2", "3"] } },
                            { "path": "zone", "label": "Zone", "format": "address", "visible": { "mustMatch": ["0xAbCdEf0000000000000000000000000000000001"] } },
                            { "path": "value", "label": "Value", "format": "number" }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let calldata = build_calldata(
        "show(uint8,address,uint256)",
        &[
            uint_word(2),
            addr_word("0xabcdef0000000000000000000000000000000001"),
            uint_word(5),
        ],
    );
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let result = format_calldata(
        &wrap_rd(descriptor.clone(), 1, "0xabc"),
        &tx,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(result.entries.len(), 1);
    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.label, "Value"),
        _ => panic!("expected Item"),
    }

    let mismatching = build_calldata(
        "show(uint8,address,uint256)",
        &[
            uint_word(4),
            addr_word("0xabcdef0000000000000000000000000000000001"),
            uint_word(5),
        ],
    );
    let mismatching_tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &mismatching,
        value: None,
        from: None,
        implementation_address: None,
    };
    let err = format_calldata(
        &wrap_rd(descriptor, 1, "0xabc"),
        &mismatching_tx,
        &EmptyDataProvider,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("visible.mustMatch"));
}

#[tokio::test]
async fn test_visible_if_not_in_compares_json_number_with_decoded_uint() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "show(uint256 value)": {
                        "intent": "Show",
                        "fields": [
                            { "path": "value", "label": "Value", "format": "number", "visible": { "ifNotIn": [0] } }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let hidden = build_calldata("show(uint256)", &[uint_word(0)]);
    let hidden_tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &hidden,
        value: None,
        from: None,
        implementation_address: None,
    };
    let hidden_result = format_calldata(
        &wrap_rd(descriptor.clone(), 1, "0xabc"),
        &hidden_tx,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert!(hidden_result.entries.is_empty());

    let shown = build_calldata("show(uint256)", &[uint_word(7)]);
    let shown_tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &shown,
        value: None,
        from: None,
        implementation_address: None,
    };
    let shown_result = format_calldata(
        &wrap_rd(descriptor, 1, "0xabc"),
        &shown_tx,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(shown_result.entries.len(), 1);
}

#[tokio::test]
async fn test_visible_must_match_compares_signed_int_as_decimal() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "show(int256 delta,int256 mask,uint256 value)": {
                        "intent": "Show",
                        "fields": [
                            { "path": "delta", "label": "Delta", "format": "number", "visible": { "mustMatch": ["-1"] } },
                            { "path": "mask", "label": "Mask", "format": "number", "visible": { "mustMatch": ["0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"] } },
                            { "path": "value", "label": "Value", "format": "number" }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let calldata = build_calldata(
        "show(int256,int256,uint256)",
        &[[0xffu8; 32], [0xffu8; 32], uint_word(5)],
    );
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };
    let result = format_calldata(&wrap_rd(descriptor, 1, "0xabc"), &tx, &EmptyDataProvider)
        .await
        .unwrap();
    assert_eq!(result.entries.len(), 1);
    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.label, "Value"),
        _ => panic!("expected Item"),
    }
}

#[tokio::test]
async fn test_typed_visibility_must_match_compares_string_and_number() {
    let descriptor = Descriptor::from_json(
        r#"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Permit(uint8 kind,address zone,uint256 value)": {
                        "intent": "Permit",
                        "fields": [
                            { "path": "kind", "label": "Kind", "format": "raw", "visible": { "mustMatch": [1, "0x02"] } },
                            { "path": "zone", "label": "Zone", "format": "address", "visible": { "mustMatch": ["0xAbCdEf0000000000000000000000000000000001"] } },
                            { "path": "value", "label": "Value", "format": "number" }
                        ]
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Permit": [
                { "name": "kind", "type": "uint8" },
                { "name": "zone", "type": "address" },
                { "name": "value", "type": "uint256" }
            ]
        },
        "primaryType": "Permit",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": {
            "kind": "2",
            "zone": "0xabcdef0000000000000000000000000000000001",
            "value": "9"
        }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    assert_eq!(result.entries.len(), 1);
    match &result.entries[0] {
        DisplayEntry::Item(item) => assert_eq!(item.label, "Value"),
        _ => panic!("expected Item"),
    }
}

#[tokio::test]
async fn test_calldata_bundled_group_keeps_hidden_array_elements_aligned() {
    let json = r#"{
        "context": { "contract": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
        "metadata": {"owner": "test", "enums": {}, "constants": {}, "maps": {}},
        "display": {
            "definitions": {},
            "formats": {
                "batch(address[] recipients,uint256[] amounts)": {
                    "intent": "Batch",
                    "fields": [{
                        "label": "Transfers",
                        "iteration": "bundled",
                        "fields": [
                            {
                                "path": "recipients.[]",
                                "label": "Recipient",
                                "format": "address",
                                "visible": { "mustMatch": ["0x0000000000000000000000000000000000000001", "0x0000000000000000000000000000000000000002"] }
                            },
                            {"path": "amounts.[]", "label": "Hidden amount", "format": "number", "visible": "never"},
                            {"path": "amounts.[]", "label": "Amount", "format": "number"}
                        ]
                    }]
                }
            }
        }
    }"#;

    let descriptor = Descriptor::from_json(json).unwrap();
    let calldata = build_two_array_calldata(
        "batch(address[],uint256[])",
        &[
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
        ],
        &[100, 200],
    );
    let tx = TransactionContext {
        chain_id: 1,
        to: "0xabc",
        calldata: &calldata,
        value: None,
        from: None,
        implementation_address: None,
    };

    let result = format_calldata(&wrap_rd(descriptor, 1, "0xabc"), &tx, &EmptyDataProvider)
        .await
        .unwrap();
    match &result.entries[0] {
        DisplayEntry::Group {
            iteration, items, ..
        } => {
            assert!(matches!(iteration, GroupIteration::Bundled));
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].label, "Amount");
            assert_eq!(items[0].value, "100");
            assert_eq!(items[1].label, "Amount");
            assert_eq!(items[1].value, "200");
        }
        _ => panic!("expected bundled group"),
    }
}

#[tokio::test]
async fn test_eip712_bundled_group_keeps_hidden_array_elements_aligned() {
    let descriptor = Descriptor::from_json(
        r##"{
            "context": { "eip712": { "deployments": [{"chainId": 1, "address": "0xabc"}] } },
            "metadata": { "owner": "test", "enums": {}, "constants": {}, "maps": {} },
            "display": {
                "definitions": {},
                "formats": {
                    "Batch(Tip[] tips)Tip(uint8 itemType,address token,uint256 amount,address recipient)": {
                        "intent": "Batch",
                        "fields": [{
                            "label": "Tips",
                            "iteration": "bundled",
                            "fields": [
                                { "path": "tips.[].itemType", "label": "Tip type", "format": "raw", "visible": { "mustMatch": ["1", "2"] } },
                                { "path": "tips.[].token", "label": "Tip token", "format": "address", "visible": "never" },
                                { "path": "tips.[].amount", "label": "Tip amount", "format": "number" },
                                { "path": "tips.[].recipient", "label": "Tip to", "format": "address" }
                            ]
                        }]
                    }
                }
            }
        }"##,
    )
    .unwrap();

    let typed_data: TypedData = serde_json::from_value(serde_json::json!({
        "types": {
            "EIP712Domain": [],
            "Batch": [{ "name": "tips", "type": "Tip[]" }],
            "Tip": [
                { "name": "itemType", "type": "uint8" },
                { "name": "token", "type": "address" },
                { "name": "amount", "type": "uint256" },
                { "name": "recipient", "type": "address" }
            ]
        },
        "primaryType": "Batch",
        "domain": { "chainId": 1, "verifyingContract": "0xabc" },
        "message": {
            "tips": [{
                "itemType": "1",
                "token": "0x0000000000000000000000000000000000000001",
                "amount": "100",
                "recipient": "0x0000000000000000000000000000000000000002"
            }]
        }
    }))
    .unwrap();

    let result = format_typed_data(
        &wrap_rd(descriptor, 1, "0xabc"),
        &typed_data,
        &EmptyDataProvider,
    )
    .await
    .unwrap();
    match &result.entries[0] {
        DisplayEntry::Group {
            label,
            iteration,
            items,
        } => {
            assert_eq!(label, "Tips");
            assert!(matches!(iteration, GroupIteration::Bundled));
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].label, "Tip amount");
            assert_eq!(items[1].label, "Tip to");
        }
        _ => panic!("expected bundled group"),
    }
}
