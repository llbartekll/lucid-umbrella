use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::address_book::AddressBook;
use crate::engine::{DisplayEntry, DisplayItem, DisplayModel, GroupIteration};
use crate::error::Error;
use crate::token::{TokenLookupKey, TokenSource};
use crate::types::descriptor::Descriptor;
use crate::types::display::{
    DisplayField, FieldFormat, FieldGroup, FormatParams, Iteration, VisibleRule,
};

/// EIP-712 typed data as received for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedData {
    pub types: HashMap<String, Vec<TypedDataField>>,

    #[serde(rename = "primaryType")]
    pub primary_type: String,

    pub domain: TypedDataDomain,

    pub message: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedDataField {
    pub name: String,

    #[serde(rename = "type")]
    pub field_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedDataDomain {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    #[serde(rename = "chainId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,

    #[serde(rename = "verifyingContract")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifying_contract: Option<String>,
}

/// Format EIP-712 typed data into a display model.
pub fn format_typed_data(
    descriptor: &Descriptor,
    data: &TypedData,
    token_source: &dyn TokenSource,
) -> Result<DisplayModel, Error> {
    let address_book = AddressBook::from_descriptor(&descriptor.context, &descriptor.metadata);
    let chain_id = data.domain.chain_id.unwrap_or(1);

    // Find format by primary type name
    let format = descriptor
        .display
        .formats
        .get(&data.primary_type)
        .ok_or_else(|| {
            Error::Render(format!(
                "no display format found for primary type '{}'",
                data.primary_type
            ))
        })?;

    let mut warnings = Vec::new();
    let entries = render_typed_fields(
        descriptor,
        &data.message,
        &format.fields,
        chain_id,
        token_source,
        &address_book,
        &mut warnings,
    )?;

    Ok(DisplayModel {
        intent: format
            .intent
            .clone()
            .unwrap_or_else(|| data.primary_type.clone()),
        interpolated_intent: format
            .interpolated_intent
            .as_ref()
            .map(|template| interpolate_typed_intent(template, &data.message)),
        entries,
        warnings,
    })
}

/// Render typed data fields recursively.
fn render_typed_fields(
    descriptor: &Descriptor,
    message: &serde_json::Value,
    fields: &[DisplayField],
    chain_id: u64,
    token_source: &dyn TokenSource,
    address_book: &AddressBook,
    warnings: &mut Vec<String>,
) -> Result<Vec<DisplayEntry>, Error> {
    let mut entries = Vec::new();

    for field in fields {
        match field {
            DisplayField::Reference { reference } => {
                let key = reference
                    .strip_prefix("#/definitions/")
                    .unwrap_or(reference);
                if let Some(resolved) = descriptor.display.definitions.get(key) {
                    let mut sub = render_typed_fields(
                        descriptor,
                        message,
                        std::slice::from_ref(resolved),
                        chain_id,
                        token_source,
                        address_book,
                        warnings,
                    )?;
                    entries.append(&mut sub);
                } else {
                    warnings.push(format!("unresolved reference: {reference}"));
                }
            }
            DisplayField::Group { field_group } => {
                if let Some(entry) = render_typed_field_group(
                    descriptor,
                    message,
                    field_group,
                    chain_id,
                    token_source,
                    address_book,
                    warnings,
                )? {
                    entries.push(entry);
                }
            }
            DisplayField::Simple {
                path,
                label,
                format,
                params,
                visible,
            } => {
                let value = resolve_typed_path(message, path);

                // Check visibility
                if !check_typed_visibility(visible, &value) {
                    continue;
                }

                let formatted = format_typed_value(
                    descriptor,
                    &value,
                    format.as_ref(),
                    params.as_ref(),
                    chain_id,
                    message,
                    token_source,
                    address_book,
                    warnings,
                )?;

                entries.push(DisplayEntry::Item(DisplayItem {
                    label: label.clone(),
                    value: formatted,
                }));
            }
        }
    }

    Ok(entries)
}

fn render_typed_field_group(
    descriptor: &Descriptor,
    message: &serde_json::Value,
    group: &FieldGroup,
    chain_id: u64,
    token_source: &dyn TokenSource,
    address_book: &AddressBook,
    warnings: &mut Vec<String>,
) -> Result<Option<DisplayEntry>, Error> {
    let sub = render_typed_fields(
        descriptor,
        message,
        &group.fields,
        chain_id,
        token_source,
        address_book,
        warnings,
    )?;

    let items: Vec<DisplayItem> = sub
        .into_iter()
        .flat_map(|e| match e {
            DisplayEntry::Item(i) => vec![i],
            DisplayEntry::Group { items, .. } => items,
        })
        .collect();

    if items.is_empty() {
        return Ok(None);
    }

    let iteration = match group.iteration {
        Iteration::Sequential => GroupIteration::Sequential,
        Iteration::Bundled => GroupIteration::Bundled,
    };

    Ok(Some(DisplayEntry::Group {
        label: group.label.clone(),
        iteration,
        items,
    }))
}

/// Resolve a path in EIP-712 message JSON (e.g., "recipient" or "details.amount").
fn resolve_typed_path(message: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
    let path = path.strip_prefix("@.").unwrap_or(path);
    let mut current = message;

    for segment in path.split('.') {
        // Handle array index: "items[0]"
        if let Some(bracket) = segment.find('[') {
            let key = &segment[..bracket];
            let idx_str = &segment[bracket + 1..segment.len() - 1];

            current = current.get(key)?;
            if let Ok(idx) = idx_str.parse::<usize>() {
                current = current.get(idx)?;
            } else {
                return None;
            }
        } else {
            current = current.get(segment)?;
        }
    }

    Some(current.clone())
}

fn check_typed_visibility(rule: &VisibleRule, value: &Option<serde_json::Value>) -> bool {
    match rule {
        VisibleRule::Always => true,
        VisibleRule::Bool(b) => *b,
        VisibleRule::Named(s) => s != "never",
        VisibleRule::Condition(cond) => {
            if let Some(val) = value {
                cond.evaluate(val)
            } else {
                true
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn format_typed_value(
    descriptor: &Descriptor,
    value: &Option<serde_json::Value>,
    format: Option<&FieldFormat>,
    params: Option<&FormatParams>,
    chain_id: u64,
    message: &serde_json::Value,
    token_source: &dyn TokenSource,
    address_book: &AddressBook,
    warnings: &mut Vec<String>,
) -> Result<String, Error> {
    let Some(val) = value else {
        return Ok("<unresolved>".to_string());
    };

    // Check encryption fallback
    if let Some(params) = params {
        if let Some(ref enc) = params.encryption {
            if let Some(ref fallback) = enc.fallback_label {
                return Ok(fallback.clone());
            }
        }
    }

    // Map reference
    if let Some(params) = params {
        if let Some(ref map_ref) = params.map_reference {
            let raw = json_value_to_string(val);
            if let Some(map_def) = descriptor.metadata.maps.get(map_ref) {
                if let Some(mapped) = map_def.entries.get(&raw) {
                    return Ok(mapped.clone());
                }
            }
        }
    }

    let Some(fmt) = format else {
        return Ok(json_value_to_string(val));
    };

    match fmt {
        FieldFormat::Address => Ok(json_value_to_string(val)),
        FieldFormat::AddressName => {
            let addr = json_value_to_string(val);
            if let Some(label) = address_book.resolve(&addr) {
                Ok(label.to_string())
            } else {
                Ok(addr)
            }
        }
        FieldFormat::TokenAmount => {
            let amount_str = json_value_to_string(val);
            let amount: num_bigint::BigUint = amount_str
                .parse()
                .unwrap_or_else(|_| num_bigint::BigUint::from(0u64));

            let lookup_chain = resolve_typed_chain_id(params, chain_id, message);

            let token_meta = if let Some(params) = params {
                if let Some(ref token_path) = params.token_path {
                    let token_addr = resolve_typed_path(message, token_path);
                    if let Some(serde_json::Value::String(addr)) = token_addr {
                        let key = TokenLookupKey::new(lookup_chain, &addr);
                        token_source.lookup(&key)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(meta) = token_meta {
                let formatted = crate::engine::format_with_decimals(&amount, meta.decimals);
                Ok(format!("{formatted} {}", meta.symbol))
            } else {
                Ok(amount.to_string())
            }
        }
        FieldFormat::Date => {
            let ts: i64 = match val {
                serde_json::Value::Number(n) => n.as_i64().unwrap_or(0),
                serde_json::Value::String(s) => s.parse().unwrap_or(0),
                _ => 0,
            };
            let dt = time::OffsetDateTime::from_unix_timestamp(ts)
                .map_err(|e| Error::Render(format!("invalid timestamp: {e}")))?;
            let format = time::format_description::parse(
                "[year]-[month]-[day] [hour]:[minute]:[second] UTC",
            )
            .map_err(|e| Error::Render(format!("format error: {e}")))?;
            Ok(dt
                .format(&format)
                .map_err(|e| Error::Render(format!("format error: {e}")))?)
        }
        FieldFormat::Enum => {
            let raw = json_value_to_string(val);
            if let Some(params) = params {
                if let Some(ref enum_path) = params.enum_path {
                    if let Some(enum_def) = descriptor.metadata.enums.get(enum_path) {
                        if let Some(label) = enum_def.get(&raw) {
                            return Ok(label.clone());
                        }
                    }
                }
            }
            Ok(raw)
        }
        FieldFormat::Number => Ok(json_value_to_string(val)),
        FieldFormat::TokenTicker => {
            let lookup_chain = resolve_typed_chain_id(params, chain_id, message);
            let addr = json_value_to_string(val);
            let key = TokenLookupKey::new(lookup_chain, &addr);
            if let Some(meta) = token_source.lookup(&key) {
                Ok(meta.symbol)
            } else {
                warnings.push("token ticker not found".to_string());
                Ok(addr)
            }
        }
        FieldFormat::ChainId => {
            let cid: u64 = match val {
                serde_json::Value::Number(n) => n.as_u64().unwrap_or(0),
                serde_json::Value::String(s) => s.parse().unwrap_or(0),
                _ => 0,
            };
            Ok(crate::engine::chain_name_public(cid))
        }
        _ => {
            warnings.push(format!("format {fmt:?} not yet implemented for EIP-712"));
            Ok(json_value_to_string(val))
        }
    }
}

fn resolve_typed_chain_id(
    params: Option<&FormatParams>,
    default_chain: u64,
    message: &serde_json::Value,
) -> u64 {
    if let Some(params) = params {
        if let Some(cid) = params.chain_id {
            return cid;
        }
        if let Some(ref path) = params.chain_id_path {
            if let Some(val) = resolve_typed_path(message, path) {
                if let Some(n) = val.as_u64() {
                    return n;
                }
            }
        }
    }
    default_chain
}

fn json_value_to_string(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

fn interpolate_typed_intent(template: &str, message: &serde_json::Value) -> String {
    let mut result = template.to_string();
    while let Some(start) = result.find("${") {
        let end = match result[start..].find('}') {
            Some(e) => start + e,
            None => break,
        };
        let path = &result[start + 2..end];
        let replacement = resolve_typed_path(message, path)
            .map(|v| json_value_to_string(&v))
            .unwrap_or_else(|| "<?>".to_string());
        result.replace_range(start..=end, &replacement);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_typed_path() {
        let message = serde_json::json!({
            "recipient": "0xabc",
            "details": {
                "amount": "1000",
                "token": "0xdef"
            }
        });

        assert_eq!(
            resolve_typed_path(&message, "recipient"),
            Some(serde_json::json!("0xabc"))
        );
        assert_eq!(
            resolve_typed_path(&message, "details.amount"),
            Some(serde_json::json!("1000"))
        );
        assert_eq!(resolve_typed_path(&message, "nonexistent"), None);
    }

    #[test]
    fn test_json_value_to_string() {
        assert_eq!(json_value_to_string(&serde_json::json!("hello")), "hello");
        assert_eq!(json_value_to_string(&serde_json::json!(42)), "42");
        assert_eq!(json_value_to_string(&serde_json::json!(true)), "true");
    }
}
