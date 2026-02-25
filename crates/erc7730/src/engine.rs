use num_bigint::BigUint;

use crate::address_book::AddressBook;
use crate::decoder::{ArgumentValue, DecodedArguments};
use crate::error::Error;
use crate::token::{TokenLookupKey, TokenSource};
use crate::types::descriptor::Descriptor;
use crate::types::display::{
    DisplayField, DisplayFormat, FieldFormat, FieldGroup, FormatParams, Iteration, VisibleRule,
};

/// Output model for clear signing display.
#[derive(Debug, Clone)]
pub struct DisplayModel {
    pub intent: String,
    pub interpolated_intent: Option<String>,
    pub entries: Vec<DisplayEntry>,
    pub warnings: Vec<String>,
}

/// A display entry — either a flat item or a group of items.
#[derive(Debug, Clone)]
pub enum DisplayEntry {
    Item(DisplayItem),
    Group {
        label: String,
        iteration: GroupIteration,
        items: Vec<DisplayItem>,
    },
}

#[derive(Debug, Clone)]
pub enum GroupIteration {
    Sequential,
    Bundled,
}

/// A single label+value pair for display.
#[derive(Debug, Clone)]
pub struct DisplayItem {
    pub label: String,
    pub value: String,
}

/// Known chain IDs → human-readable names (public for eip712 module).
pub(crate) fn chain_name_public(chain_id: u64) -> String {
    chain_name(chain_id)
}

fn chain_name(chain_id: u64) -> String {
    match chain_id {
        1 => "Ethereum".to_string(),
        10 => "Optimism".to_string(),
        56 => "BNB Chain".to_string(),
        100 => "Gnosis".to_string(),
        137 => "Polygon".to_string(),
        250 => "Fantom".to_string(),
        324 => "zkSync Era".to_string(),
        8453 => "Base".to_string(),
        42161 => "Arbitrum One".to_string(),
        42170 => "Arbitrum Nova".to_string(),
        43114 => "Avalanche".to_string(),
        59144 => "Linea".to_string(),
        534352 => "Scroll".to_string(),
        7777777 => "Zora".to_string(),
        _ => format!("Chain {chain_id}"),
    }
}

/// Rendering context passed through the pipeline.
struct RenderContext<'a> {
    descriptor: &'a Descriptor,
    decoded: &'a DecodedArguments,
    chain_id: u64,
    token_source: &'a dyn TokenSource,
    address_book: &'a AddressBook,
    warnings: Vec<String>,
}

/// Format calldata into a display model using a descriptor.
pub fn format_calldata(
    descriptor: &Descriptor,
    chain_id: u64,
    _to: &str,
    decoded: &DecodedArguments,
    _value: Option<&[u8]>,
    token_source: &dyn TokenSource,
) -> Result<DisplayModel, Error> {
    let address_book = AddressBook::from_descriptor(&descriptor.context, &descriptor.metadata);

    // Find matching format by function name + signature
    let format = find_format(descriptor, &decoded.function_name, &decoded.selector)?;

    let mut ctx = RenderContext {
        descriptor,
        decoded,
        chain_id,
        token_source,
        address_book: &address_book,
        warnings: Vec::new(),
    };

    let entries = render_fields(&mut ctx, &format.fields)?;

    let interpolated = format
        .interpolated_intent
        .as_ref()
        .map(|template| interpolate_intent(template, decoded));

    Ok(DisplayModel {
        intent: format
            .intent
            .clone()
            .unwrap_or_else(|| decoded.function_name.clone()),
        interpolated_intent: interpolated,
        entries,
        warnings: ctx.warnings,
    })
}

/// Find the display format matching the decoded function.
fn find_format<'a>(
    descriptor: &'a Descriptor,
    function_name: &str,
    selector: &[u8; 4],
) -> Result<&'a DisplayFormat, Error> {
    let selector_hex = hex::encode(selector);

    // Try exact match on format keys
    for (key, format) in &descriptor.display.formats {
        // Match by full signature or by function name
        if key == function_name {
            return Ok(format);
        }
        // Match by computing selector from the key
        if key.contains('(') {
            let key_selector = crate::decoder::selector_from_signature(key);
            if hex::encode(key_selector) == selector_hex {
                return Ok(format);
            }
        }
    }

    Err(Error::Render(format!(
        "no display format found for function '{}' (selector 0x{})",
        function_name, selector_hex
    )))
}

/// Render a list of display fields into display entries.
fn render_fields(
    ctx: &mut RenderContext<'_>,
    fields: &[DisplayField],
) -> Result<Vec<DisplayEntry>, Error> {
    let mut entries = Vec::new();

    for field in fields {
        match field {
            DisplayField::Reference { reference } => {
                if let Some(resolved) = resolve_reference(ctx.descriptor, reference) {
                    let mut sub = render_fields(ctx, std::slice::from_ref(&resolved))?;
                    entries.append(&mut sub);
                } else {
                    ctx.warnings
                        .push(format!("unresolved reference: {reference}"));
                }
            }
            DisplayField::Group { field_group } => {
                if let Some(entry) = render_field_group(ctx, field_group)? {
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
                // Resolve the value from decoded arguments
                let value = resolve_path(ctx.decoded, path);

                // Check visibility
                if !check_visibility(visible, &value) {
                    continue;
                }

                let formatted = format_value(
                    ctx,
                    &value,
                    format.as_ref(),
                    params.as_ref(),
                    path,
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

/// Render a field group recursively.
fn render_field_group(
    ctx: &mut RenderContext<'_>,
    group: &FieldGroup,
) -> Result<Option<DisplayEntry>, Error> {
    let mut items = Vec::new();

    for field in &group.fields {
        let sub_entries = render_fields(ctx, std::slice::from_ref(field))?;
        for entry in sub_entries {
            match entry {
                DisplayEntry::Item(item) => items.push(item),
                DisplayEntry::Group { items: sub_items, .. } => {
                    items.extend(sub_items);
                }
            }
        }
    }

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

/// Resolve a `$ref` to a definition.
fn resolve_reference(descriptor: &Descriptor, reference: &str) -> Option<DisplayField> {
    // Expected format: "#/definitions/foo"
    let key = reference.strip_prefix("#/definitions/")?;
    descriptor.display.definitions.get(key).cloned()
}

/// Resolve a path like `@.to` or `@.args[0]` to a decoded value.
fn resolve_path(decoded: &DecodedArguments, path: &str) -> Option<ArgumentValue> {
    let path = path.trim();

    // Strip "@." prefix if present
    let path = path.strip_prefix("@.").unwrap_or(path);

    // Try numeric index first (positional: "0", "1", etc.)
    if let Ok(index) = path.parse::<usize>() {
        return decoded.args.get(index).map(|a| a.value.clone());
    }

    // Try named parameter matching by splitting dotted paths
    let segments: Vec<&str> = path.split('.').collect();

    // First segment indexes into top-level args
    if let Ok(index) = segments[0].parse::<usize>() {
        if let Some(arg) = decoded.args.get(index) {
            if segments.len() == 1 {
                return Some(arg.value.clone());
            }
            return navigate_value(&arg.value, &segments[1..]);
        }
    }

    // Handle array index notation: "args[0]"
    if let Some(rest) = segments[0].strip_prefix("args") {
        if let Some(idx_str) = rest.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Ok(index) = idx_str.parse::<usize>() {
                if let Some(arg) = decoded.args.get(index) {
                    if segments.len() == 1 {
                        return Some(arg.value.clone());
                    }
                    return navigate_value(&arg.value, &segments[1..]);
                }
            }
        }
    }

    None
}

/// Navigate into a value using path segments.
fn navigate_value(value: &ArgumentValue, segments: &[&str]) -> Option<ArgumentValue> {
    if segments.is_empty() {
        return Some(value.clone());
    }

    match value {
        ArgumentValue::Tuple(members) | ArgumentValue::Array(members) => {
            let seg = segments[0];
            if let Ok(index) = seg.parse::<usize>() {
                members
                    .get(index)
                    .and_then(|v| navigate_value(v, &segments[1..]))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Check if a field should be visible based on the visibility rule and decoded value.
fn check_visibility(rule: &VisibleRule, value: &Option<ArgumentValue>) -> bool {
    match rule {
        VisibleRule::Always => true,
        VisibleRule::Bool(b) => *b,
        VisibleRule::Named(s) => s != "never",
        VisibleRule::Condition(cond) => {
            if let Some(val) = value {
                let json_val = val.to_json_value();
                cond.evaluate(&json_val)
            } else {
                true // Show if value is unresolvable
            }
        }
    }
}

/// Format a decoded value according to its format type.
fn format_value(
    ctx: &mut RenderContext<'_>,
    value: &Option<ArgumentValue>,
    format: Option<&FieldFormat>,
    params: Option<&FormatParams>,
    path: &str,
) -> Result<String, Error> {
    let Some(val) = value else {
        ctx.warnings
            .push(format!("could not resolve path: {path}"));
        return Ok("<unresolved>".to_string());
    };

    // Check for encryption — if present and we can't decrypt, use fallback
    if let Some(params) = params {
        if let Some(ref enc) = params.encryption {
            if let Some(ref fallback) = enc.fallback_label {
                return Ok(fallback.clone());
            }
        }
    }

    // Check for map reference
    if let Some(params) = params {
        if let Some(ref map_ref) = params.map_reference {
            if let Some(mapped) = resolve_map(ctx, map_ref, val) {
                return Ok(mapped);
            }
        }
    }

    let Some(fmt) = format else {
        return Ok(format_raw(val));
    };

    match fmt {
        FieldFormat::TokenAmount => format_token_amount(ctx, val, params),
        FieldFormat::Amount => format_amount(val),
        FieldFormat::Date => format_date(val),
        FieldFormat::Enum => format_enum(ctx, val, params),
        FieldFormat::Address => Ok(format_address(val)),
        FieldFormat::AddressName => Ok(format_address_name(ctx, val)),
        FieldFormat::Number => Ok(format_number(val)),
        FieldFormat::Raw => Ok(format_raw(val)),
        FieldFormat::TokenTicker => format_token_ticker(ctx, val, params),
        FieldFormat::ChainId => format_chain_id(val),
        FieldFormat::Calldata | FieldFormat::NftName | FieldFormat::Duration | FieldFormat::Unit => {
            // Not yet implemented — render raw with warning
            ctx.warnings
                .push(format!("format {:?} not yet implemented", fmt));
            Ok(format_raw(val))
        }
    }
}

fn format_raw(val: &ArgumentValue) -> String {
    match val {
        ArgumentValue::Address(addr) => format!("0x{}", hex::encode(addr)),
        ArgumentValue::Uint(bytes) | ArgumentValue::Int(bytes) => {
            let n = BigUint::from_bytes_be(bytes);
            n.to_string()
        }
        ArgumentValue::Bool(b) => b.to_string(),
        ArgumentValue::Bytes(b) | ArgumentValue::FixedBytes(b) => {
            format!("0x{}", hex::encode(b))
        }
        ArgumentValue::String(s) => s.clone(),
        ArgumentValue::Array(items) => {
            let rendered: Vec<String> = items.iter().map(format_raw).collect();
            format!("[{}]", rendered.join(", "))
        }
        ArgumentValue::Tuple(items) => {
            let rendered: Vec<String> = items.iter().map(format_raw).collect();
            format!("({})", rendered.join(", "))
        }
    }
}

fn format_address(val: &ArgumentValue) -> String {
    match val {
        ArgumentValue::Address(addr) => eip55_checksum(addr),
        _ => format_raw(val),
    }
}

fn format_address_name(ctx: &RenderContext<'_>, val: &ArgumentValue) -> String {
    if let ArgumentValue::Address(addr) = val {
        let hex_addr = format!("0x{}", hex::encode(addr));
        if let Some(label) = ctx.address_book.resolve(&hex_addr) {
            return label.to_string();
        }
        eip55_checksum(addr)
    } else {
        format_raw(val)
    }
}

/// EIP-55 mixed-case checksum encoding.
fn eip55_checksum(addr: &[u8; 20]) -> String {
    use tiny_keccak::{Hasher, Keccak};

    let hex_addr = hex::encode(addr);
    let mut hasher = Keccak::v256();
    hasher.update(hex_addr.as_bytes());
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);

    let mut result = String::with_capacity(42);
    result.push_str("0x");
    for (i, c) in hex_addr.chars().enumerate() {
        let hash_nibble = if i % 2 == 0 {
            (hash[i / 2] >> 4) & 0x0f
        } else {
            hash[i / 2] & 0x0f
        };
        if hash_nibble >= 8 {
            result.push(c.to_ascii_uppercase());
        } else {
            result.push(c);
        }
    }
    result
}

fn format_number(val: &ArgumentValue) -> String {
    match val {
        ArgumentValue::Uint(bytes) | ArgumentValue::Int(bytes) => {
            BigUint::from_bytes_be(bytes).to_string()
        }
        _ => format_raw(val),
    }
}

fn format_token_amount(
    ctx: &mut RenderContext<'_>,
    val: &ArgumentValue,
    params: Option<&FormatParams>,
) -> Result<String, Error> {
    let raw_amount = match val {
        ArgumentValue::Uint(bytes) | ArgumentValue::Int(bytes) => {
            BigUint::from_bytes_be(bytes)
        }
        _ => return Ok(format_raw(val)),
    };

    // Determine chain ID for token lookup (cross-chain support)
    let lookup_chain_id = resolve_chain_id(ctx, params);

    // Try to resolve token metadata
    let token_meta = if let Some(params) = params {
        if let Some(ref token_path) = params.token_path {
            // Resolve token address from calldata
            let token_addr = resolve_path(ctx.decoded, token_path);
            if let Some(ArgumentValue::Address(addr)) = token_addr {
                let addr_hex = format!("0x{}", hex::encode(addr));

                // Check for native currency
                if let Some(ref native) = params.native_currency_address {
                    if addr_hex.to_lowercase() == native.to_lowercase() {
                        Some(native_token_meta(lookup_chain_id))
                    } else {
                        let key = TokenLookupKey::new(lookup_chain_id, &addr_hex);
                        ctx.token_source.lookup(&key)
                    }
                } else {
                    let key = TokenLookupKey::new(lookup_chain_id, &addr_hex);
                    ctx.token_source.lookup(&key)
                }
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
        let formatted = format_with_decimals(&raw_amount, meta.decimals);
        Ok(format!("{} {}", formatted, meta.symbol))
    } else {
        ctx.warnings.push("token metadata not found".to_string());
        Ok(raw_amount.to_string())
    }
}

fn format_token_ticker(
    ctx: &mut RenderContext<'_>,
    val: &ArgumentValue,
    params: Option<&FormatParams>,
) -> Result<String, Error> {
    let lookup_chain_id = resolve_chain_id(ctx, params);

    if let ArgumentValue::Address(addr) = val {
        let addr_hex = format!("0x{}", hex::encode(addr));
        let key = TokenLookupKey::new(lookup_chain_id, &addr_hex);
        if let Some(meta) = ctx.token_source.lookup(&key) {
            return Ok(meta.symbol);
        }
    }

    ctx.warnings
        .push("token ticker not found".to_string());
    Ok(format_raw(val))
}

fn format_chain_id(val: &ArgumentValue) -> Result<String, Error> {
    if let ArgumentValue::Uint(bytes) = val {
        let n = BigUint::from_bytes_be(bytes);
        let chain_id: u64 = n
            .try_into()
            .unwrap_or(0);
        Ok(chain_name(chain_id))
    } else {
        Ok(format_raw(val))
    }
}

/// Resolve the chain ID for cross-chain token lookups.
fn resolve_chain_id(ctx: &RenderContext<'_>, params: Option<&FormatParams>) -> u64 {
    if let Some(params) = params {
        // Static chain ID takes precedence
        if let Some(cid) = params.chain_id {
            return cid;
        }
        // Dynamic chain ID from calldata path
        if let Some(ref path) = params.chain_id_path {
            if let Some(ArgumentValue::Uint(bytes)) = resolve_path(ctx.decoded, path) {
                let n = BigUint::from_bytes_be(&bytes);
                if let Ok(cid) = u64::try_from(n) {
                    return cid;
                }
            }
        }
    }
    ctx.chain_id
}

/// Get native token metadata for a chain.
fn native_token_meta(chain_id: u64) -> crate::token::TokenMeta {
    let (symbol, name) = match chain_id {
        1 | 5 | 11155111 => ("ETH", "Ether"),
        137 | 80001 => ("MATIC", "Polygon"),
        56 | 97 => ("BNB", "BNB"),
        43114 | 43113 => ("AVAX", "Avalanche"),
        250 => ("FTM", "Fantom"),
        42161 | 421613 => ("ETH", "Ether"),
        10 | 420 => ("ETH", "Ether"),
        8453 | 84531 => ("ETH", "Ether"),
        _ => ("ETH", "Ether"),
    };
    crate::token::TokenMeta {
        symbol: symbol.to_string(),
        decimals: 18,
        name: name.to_string(),
    }
}

fn format_amount(val: &ArgumentValue) -> Result<String, Error> {
    match val {
        ArgumentValue::Uint(bytes) | ArgumentValue::Int(bytes) => {
            let n = BigUint::from_bytes_be(bytes);
            Ok(n.to_string())
        }
        _ => Ok(format_raw(val)),
    }
}

fn format_date(val: &ArgumentValue) -> Result<String, Error> {
    match val {
        ArgumentValue::Uint(bytes) => {
            let n = BigUint::from_bytes_be(bytes);
            let timestamp: i64 = i64::try_from(n).unwrap_or(0);

            let dt = time::OffsetDateTime::from_unix_timestamp(timestamp)
                .map_err(|e| Error::Render(format!("invalid timestamp: {e}")))?;

            let format =
                time::format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second] UTC")
                    .map_err(|e| Error::Render(format!("format error: {e}")))?;

            Ok(dt
                .format(&format)
                .map_err(|e| Error::Render(format!("format error: {e}")))?)
        }
        _ => Ok(format_raw(val)),
    }
}

fn format_enum(
    ctx: &mut RenderContext<'_>,
    val: &ArgumentValue,
    params: Option<&FormatParams>,
) -> Result<String, Error> {
    let raw = format_raw(val);

    if let Some(params) = params {
        if let Some(ref enum_path) = params.enum_path {
            if let Some(enum_def) = ctx.descriptor.metadata.enums.get(enum_path) {
                if let Some(label) = enum_def.get(&raw) {
                    return Ok(label.clone());
                }
            }
        }
    }

    Ok(raw)
}

/// Resolve a map reference to a display value.
fn resolve_map(
    ctx: &RenderContext<'_>,
    map_ref: &str,
    val: &ArgumentValue,
) -> Option<String> {
    let raw = format_raw(val);
    let map_def = ctx.descriptor.metadata.maps.get(map_ref)?;
    map_def.entries.get(&raw).cloned()
}

/// Format a BigUint with decimal places (public for eip712 module).
pub(crate) fn format_with_decimals(amount: &BigUint, decimals: u8) -> String {
    let s = amount.to_string();
    let decimals = decimals as usize;

    if decimals == 0 {
        return s;
    }

    if s.len() <= decimals {
        let zeros = decimals - s.len();
        let mut result = String::from("0.");
        result.extend(std::iter::repeat_n('0', zeros));
        result.push_str(&s);
        // Trim trailing zeros after decimal point
        let trimmed = result.trim_end_matches('0');
        if trimmed.ends_with('.') {
            return format!("{trimmed}0");
        }
        return trimmed.to_string();
    }

    let (integer_part, decimal_part) = s.split_at(s.len() - decimals);
    let trimmed = decimal_part.trim_end_matches('0');
    if trimmed.is_empty() {
        integer_part.to_string()
    } else {
        format!("{integer_part}.{trimmed}")
    }
}

/// Interpolate `${path}` templates in an intent string.
fn interpolate_intent(template: &str, decoded: &DecodedArguments) -> String {
    let mut result = template.to_string();
    // Find all ${...} patterns and replace them
    while let Some(start) = result.find("${") {
        let end = match result[start..].find('}') {
            Some(e) => start + e,
            None => break,
        };
        let path = &result[start + 2..end];
        let replacement = resolve_path(decoded, path)
            .map(|v| format_raw(&v))
            .unwrap_or_else(|| "<?>".to_string());
        result.replace_range(start..=end, &replacement);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_with_decimals() {
        let amount = BigUint::from(1_000_000u64);
        assert_eq!(format_with_decimals(&amount, 6), "1");

        let amount = BigUint::from(1_500_000u64);
        assert_eq!(format_with_decimals(&amount, 6), "1.5");

        let amount = BigUint::from(500_000u64);
        assert_eq!(format_with_decimals(&amount, 6), "0.5");

        let amount = BigUint::from(123u64);
        assert_eq!(format_with_decimals(&amount, 6), "0.000123");

        let amount = BigUint::from(0u64);
        assert_eq!(format_with_decimals(&amount, 18), "0.0");
    }

    #[test]
    fn test_chain_name() {
        assert_eq!(chain_name(1), "Ethereum");
        assert_eq!(chain_name(137), "Polygon");
        assert_eq!(chain_name(99999), "Chain 99999");
    }

    #[test]
    fn test_eip55_checksum() {
        // Known checksum: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
        let addr_bytes =
            hex::decode("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&addr_bytes);
        let checksummed = eip55_checksum(&addr);
        assert_eq!(checksummed, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }

    #[test]
    fn test_interpolate_intent() {
        use crate::decoder::{DecodedArgument, ParamType};

        let decoded = DecodedArguments {
            function_name: "transfer".to_string(),
            selector: [0; 4],
            args: vec![
                DecodedArgument {
                    index: 0,
                    param_type: ParamType::Address,
                    value: ArgumentValue::Address([0u8; 20]),
                },
                DecodedArgument {
                    index: 1,
                    param_type: ParamType::Uint(256),
                    value: ArgumentValue::Uint(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0xe8]),
                },
            ],
        };

        let result = interpolate_intent("Send ${1} to ${0}", &decoded);
        assert_eq!(result, "Send 1000 to 0x0000000000000000000000000000000000000000");
    }
}
