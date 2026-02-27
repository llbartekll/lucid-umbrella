# Reference Patterns

Advanced patterns specific to the ERC-7730 v2 clear signing library.

## Signature-Based Decoding

Parse function signatures directly from descriptor format keys — no ABI JSON needed.

```rust
// Parse signature string into structured form
let sig = parse_signature("transfer(address,uint256)")?;
// sig.name = "transfer"
// sig.params = [Address, Uint(256)]
// sig.selector = [0xa9, 0x05, 0x9c, 0xbb]

// Decode calldata using the parsed signature
let decoded = decode_calldata(&sig, calldata)?;
```

Key: format keys in descriptors ARE the function signatures (`"transfer(address,uint256)": { ... }`).

## Trait Pattern: DescriptorSource / TokenSource

Trait defines the interface, static impl provides testing:

```rust
// Trait (in resolver.rs)
pub trait DescriptorSource {
    fn resolve_calldata(&self, chain_id: u64, address: &str)
        -> Result<ResolvedDescriptor, ResolveError>;
    fn resolve_typed(&self, chain_id: u64, address: &str)
        -> Result<ResolvedDescriptor, ResolveError>;
}

// Static test impl
pub struct StaticSource {
    calldata: HashMap<String, Descriptor>,
    typed: HashMap<String, Descriptor>,
}

impl StaticSource {
    pub fn new() -> Self { ... }
    fn make_key(chain_id: u64, address: &str) -> String {
        format!("{}:{}", chain_id, address.to_lowercase())
    }
    pub fn add_calldata(&mut self, chain_id: u64, address: &str, descriptor: Descriptor) { ... }
    pub fn add_calldata_json(&mut self, ...) -> Result<(), ResolveError> { ... }
}
```

Follow this exact pattern when adding new source traits.

## RenderContext Pipeline

Mutable context struct carries state through the rendering pipeline:

```rust
struct RenderContext<'a> {
    descriptor: &'a Descriptor,
    decoded: &'a DecodedArguments,
    chain_id: u64,
    token_source: &'a dyn TokenSource,
    address_book: &'a AddressBook,
    warnings: Vec<String>,   // accumulated warnings
}
```

Functions take `&mut RenderContext<'_>` and push warnings rather than returning errors for non-fatal issues:

```rust
fn format_value(ctx: &mut RenderContext<'_>, ...) -> Result<String, Error> {
    // Fatal: return Err
    // Non-fatal: push warning and continue
    ctx.warnings.push("token metadata not found".to_string());
    Ok(raw_value)
}
```

## ArgumentValue Recursive Enum

Values decoded from calldata, recursive for tuples and arrays:

```rust
pub enum ArgumentValue {
    Address([u8; 20]),
    Uint(Vec<u8>),        // big-endian bytes
    Int(Vec<u8>),
    Bool(bool),
    Bytes(Vec<u8>),
    FixedBytes(Vec<u8>),
    String(std::string::String),
    Array(Vec<ArgumentValue>),   // recursive
    Tuple(Vec<ArgumentValue>),   // recursive
}
```

Convert to JSON for visibility rule evaluation:
```rust
impl ArgumentValue {
    pub fn to_json_value(&self) -> serde_json::Value { ... }
}
```

## Format Renderer Dispatch

Match on `FieldFormat` variants in `format_value()`:

```rust
match fmt {
    FieldFormat::TokenAmount => format_token_amount(ctx, val, params),
    FieldFormat::Amount => format_amount(val),
    FieldFormat::Date => format_date(val),
    FieldFormat::Address => Ok(format_address(val)),
    // ...
    FieldFormat::Calldata | FieldFormat::NftName | ... => {
        ctx.warnings.push(format!("format {:?} not yet implemented", fmt));
        Ok(format_raw(val))
    }
}
```

When adding a new format:
1. Add variant to `FieldFormat` enum in `types/display.rs`
2. Add serde rename in the enum
3. Add match arm in `format_value()` in `engine.rs`
4. Implement the formatter function
5. Add test

## BigUint Decimal Formatting

Format raw uint256 bytes with token decimal places:

```rust
fn format_with_decimals(amount: &BigUint, decimals: u8) -> String {
    let s = amount.to_string();
    let decimals = decimals as usize;
    if s.len() <= decimals {
        // "0.000123" style
    } else {
        // Split at decimal point, trim trailing zeros
    }
}
```

## EIP-55 Checksum

Mixed-case checksum for Ethereum addresses:

```rust
fn eip55_checksum(addr: &[u8; 20]) -> String {
    let hex_addr = hex::encode(addr);
    // Keccak-256 of lowercase hex
    // Uppercase hex chars where hash nibble >= 8
    format!("0x{result}")
}
```

## AddressBook Merge

Merge address labels from descriptor context and metadata:

```rust
impl AddressBook {
    pub fn from_descriptor(context: &Context, metadata: &Metadata) -> Self {
        // 1. Collect contract deployment addresses → contractName
        // 2. Merge metadata.addressBook entries
        // Both keyed by lowercase address
    }
    pub fn resolve(&self, address: &str) -> Option<&str> { ... }
}
```

## Serde Patterns

### Untagged enums for flexible JSON:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DisplayField {
    Reference { reference: String },
    Group { #[serde(rename = "fieldGroup")] field_group: FieldGroup },
    Simple { path: String, label: String, ... },
}
```

### Visibility rules with mixed types:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VisibleRule {
    Bool(bool),
    Named(String),
    Condition(VisibilityCondition),
}
// Plus manual `Default` impl returning `Always` variant
```

## Future: UniFFI Preparation

When UniFFI bindings are added:
- Add `#[cfg_attr(feature = "uniffi", derive(uniffi::...))]` to public types
- Keep `uniffi` behind a feature flag
- Public API in `lib.rs` should remain stable
- Error types will need `uniffi::Error` derive
