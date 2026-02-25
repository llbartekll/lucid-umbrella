use tiny_keccak::{Hasher, Keccak};

use crate::error::DecodeError;

/// Parsed function signature.
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    pub name: String,
    pub params: Vec<ParamType>,
    pub canonical: String,
    pub selector: [u8; 4],
}

/// ABI parameter types — recursive to support tuples and arrays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamType {
    Address,
    Uint(usize),
    Int(usize),
    Bool,
    Bytes,
    FixedBytes(usize),
    String,
    Array(Box<ParamType>),
    FixedArray(Box<ParamType>, usize),
    Tuple(Vec<ParamType>),
}

impl ParamType {
    /// Whether this type is dynamically-sized in ABI encoding.
    pub fn is_dynamic(&self) -> bool {
        match self {
            ParamType::Bytes | ParamType::String => true,
            ParamType::Array(_) => true,
            ParamType::FixedArray(inner, _) => inner.is_dynamic(),
            ParamType::Tuple(members) => members.iter().any(|m| m.is_dynamic()),
            _ => false,
        }
    }
}

/// Decoded calldata arguments.
#[derive(Debug, Clone)]
pub struct DecodedArguments {
    pub function_name: String,
    pub selector: [u8; 4],
    pub args: Vec<DecodedArgument>,
}

/// A single decoded argument.
#[derive(Debug, Clone)]
pub struct DecodedArgument {
    pub index: usize,
    pub param_type: ParamType,
    pub value: ArgumentValue,
}

/// Decoded argument values.
#[derive(Debug, Clone)]
pub enum ArgumentValue {
    Address([u8; 20]),
    Uint(Vec<u8>),
    Int(Vec<u8>),
    Bool(bool),
    Bytes(Vec<u8>),
    FixedBytes(Vec<u8>),
    String(std::string::String),
    Array(Vec<ArgumentValue>),
    Tuple(Vec<ArgumentValue>),
}

impl ArgumentValue {
    /// Convert to a serde_json::Value for visibility rule evaluation.
    pub fn to_json_value(&self) -> serde_json::Value {
        match self {
            ArgumentValue::Address(addr) => {
                serde_json::Value::String(format!("0x{}", hex::encode(addr)))
            }
            ArgumentValue::Uint(bytes) => {
                let hex_str = format!("0x{}", hex::encode(bytes));
                serde_json::Value::String(hex_str)
            }
            ArgumentValue::Int(bytes) => {
                let hex_str = format!("0x{}", hex::encode(bytes));
                serde_json::Value::String(hex_str)
            }
            ArgumentValue::Bool(b) => serde_json::Value::Bool(*b),
            ArgumentValue::Bytes(b) => {
                serde_json::Value::String(format!("0x{}", hex::encode(b)))
            }
            ArgumentValue::FixedBytes(b) => {
                serde_json::Value::String(format!("0x{}", hex::encode(b)))
            }
            ArgumentValue::String(s) => serde_json::Value::String(s.clone()),
            ArgumentValue::Array(items) => {
                serde_json::Value::Array(items.iter().map(|i| i.to_json_value()).collect())
            }
            ArgumentValue::Tuple(items) => {
                serde_json::Value::Array(items.iter().map(|i| i.to_json_value()).collect())
            }
        }
    }

    /// Get the raw uint256 bytes, zero-extended to 32 bytes.
    pub fn as_uint_bytes(&self) -> Option<[u8; 32]> {
        match self {
            ArgumentValue::Uint(b) | ArgumentValue::Int(b) => {
                let mut result = [0u8; 32];
                let start = 32usize.saturating_sub(b.len());
                let copy_len = b.len().min(32);
                result[start..start + copy_len].copy_from_slice(&b[b.len() - copy_len..]);
                Some(result)
            }
            _ => None,
        }
    }
}

/// Parse a function signature string into a `FunctionSignature`.
///
/// Example: `"transfer(address,uint256)"` → name="transfer", params=[Address, Uint(256)]
pub fn parse_signature(sig: &str) -> Result<FunctionSignature, DecodeError> {
    let sig = sig.trim();
    let open = sig
        .find('(')
        .ok_or_else(|| DecodeError::InvalidSignature(format!("missing '(' in: {sig}")))?;

    if !sig.ends_with(')') {
        return Err(DecodeError::InvalidSignature(format!(
            "missing ')' in: {sig}"
        )));
    }

    let name = sig[..open].to_string();
    if name.is_empty() {
        return Err(DecodeError::InvalidSignature(
            "empty function name".to_string(),
        ));
    }

    let params_str = &sig[open + 1..sig.len() - 1];
    let params = if params_str.is_empty() {
        vec![]
    } else {
        parse_param_list(params_str)?
    };

    let canonical = format!("{}({})", name, canonical_params(&params));
    let selector = selector_from_signature(&canonical);

    Ok(FunctionSignature {
        name,
        params,
        canonical,
        selector,
    })
}

/// Parse a comma-separated list of param types, respecting nested parentheses for tuples.
fn parse_param_list(s: &str) -> Result<Vec<ParamType>, DecodeError> {
    let mut result = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;

    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| DecodeError::InvalidSignature("unbalanced ')'".to_string()))?;
            }
            ',' if depth == 0 => {
                result.push(parse_param_type(s[start..i].trim())?);
                start = i + 1;
            }
            _ => {}
        }
    }

    if depth != 0 {
        return Err(DecodeError::InvalidSignature(
            "unbalanced parentheses".to_string(),
        ));
    }

    let last = s[start..].trim();
    if !last.is_empty() {
        result.push(parse_param_type(last)?);
    }

    Ok(result)
}

/// Parse a single param type string.
fn parse_param_type(s: &str) -> Result<ParamType, DecodeError> {
    let s = s.trim();

    // Handle array suffixes: `type[]` or `type[N]`
    if let Some(bracket_pos) = s.rfind('[') {
        if s.ends_with(']') {
            let inner_str = &s[..bracket_pos];
            let size_str = &s[bracket_pos + 1..s.len() - 1];
            let inner = parse_param_type(inner_str)?;

            if size_str.is_empty() {
                return Ok(ParamType::Array(Box::new(inner)));
            } else {
                let size: usize = size_str.parse().map_err(|_| {
                    DecodeError::InvalidSignature(format!("invalid array size: {size_str}"))
                })?;
                return Ok(ParamType::FixedArray(Box::new(inner), size));
            }
        }
    }

    // Handle tuples: `(type1,type2,...)`
    if s.starts_with('(') && s.ends_with(')') {
        let inner = &s[1..s.len() - 1];
        let members = if inner.is_empty() {
            vec![]
        } else {
            parse_param_list(inner)?
        };
        return Ok(ParamType::Tuple(members));
    }

    // Primitive types
    match s {
        "address" => Ok(ParamType::Address),
        "bool" => Ok(ParamType::Bool),
        "string" => Ok(ParamType::String),
        "bytes" => Ok(ParamType::Bytes),
        _ if s.starts_with("uint") => {
            let bits = if s == "uint" {
                256
            } else {
                s[4..].parse::<usize>().map_err(|_| {
                    DecodeError::InvalidSignature(format!("invalid uint width: {s}"))
                })?
            };
            Ok(ParamType::Uint(bits))
        }
        _ if s.starts_with("int") => {
            let bits = if s == "int" {
                256
            } else {
                s[3..].parse::<usize>().map_err(|_| {
                    DecodeError::InvalidSignature(format!("invalid int width: {s}"))
                })?
            };
            Ok(ParamType::Int(bits))
        }
        _ if s.starts_with("bytes") => {
            let size: usize = s[5..].parse().map_err(|_| {
                DecodeError::InvalidSignature(format!("invalid bytes width: {s}"))
            })?;
            Ok(ParamType::FixedBytes(size))
        }
        _ => Err(DecodeError::InvalidSignature(format!(
            "unknown type: {s}"
        ))),
    }
}

/// Build a canonical param string for selector computation.
fn canonical_params(params: &[ParamType]) -> String {
    params
        .iter()
        .map(canonical_param)
        .collect::<Vec<_>>()
        .join(",")
}

fn canonical_param(p: &ParamType) -> String {
    match p {
        ParamType::Address => "address".to_string(),
        ParamType::Uint(bits) => format!("uint{bits}"),
        ParamType::Int(bits) => format!("int{bits}"),
        ParamType::Bool => "bool".to_string(),
        ParamType::Bytes => "bytes".to_string(),
        ParamType::FixedBytes(size) => format!("bytes{size}"),
        ParamType::String => "string".to_string(),
        ParamType::Array(inner) => format!("{}[]", canonical_param(inner)),
        ParamType::FixedArray(inner, size) => format!("{}[{size}]", canonical_param(inner)),
        ParamType::Tuple(members) => {
            let inner = members.iter().map(canonical_param).collect::<Vec<_>>().join(",");
            format!("({inner})")
        }
    }
}

/// Compute the 4-byte selector from a canonical function signature.
pub fn selector_from_signature(canonical: &str) -> [u8; 4] {
    let mut hasher = Keccak::v256();
    hasher.update(canonical.as_bytes());
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Decode calldata using a parsed function signature.
pub fn decode_calldata(
    sig: &FunctionSignature,
    calldata: &[u8],
) -> Result<DecodedArguments, DecodeError> {
    if calldata.len() < 4 {
        return Err(DecodeError::CalldataTooShort {
            expected: 4,
            actual: calldata.len(),
        });
    }

    let actual_selector = &calldata[..4];
    if actual_selector != sig.selector {
        return Err(DecodeError::SelectorMismatch {
            expected: hex::encode(sig.selector),
            actual: hex::encode(actual_selector),
        });
    }

    let data = &calldata[4..];
    let mut args = Vec::with_capacity(sig.params.len());

    // Decode head section
    let mut offset = 0;
    for (i, param) in sig.params.iter().enumerate() {
        let value = decode_value(param, data, offset)?;
        args.push(DecodedArgument {
            index: i,
            param_type: param.clone(),
            value,
        });
        offset += 32; // Each head entry is 32 bytes (value or offset pointer)
    }

    Ok(DecodedArguments {
        function_name: sig.name.clone(),
        selector: sig.selector,
        args,
    })
}

/// Decode a single value from ABI-encoded data.
fn decode_value(param: &ParamType, data: &[u8], head_offset: usize) -> Result<ArgumentValue, DecodeError> {
    if param.is_dynamic() {
        // Dynamic types: head contains offset to tail
        let offset = read_u256_as_usize(data, head_offset)?;
        decode_value_at(param, data, offset)
    } else {
        decode_value_at(param, data, head_offset)
    }
}

/// Decode a value at a specific byte offset.
fn decode_value_at(param: &ParamType, data: &[u8], offset: usize) -> Result<ArgumentValue, DecodeError> {
    ensure_bytes(data, offset, 32)?;

    match param {
        ParamType::Address => {
            let word = &data[offset..offset + 32];
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&word[12..32]);
            Ok(ArgumentValue::Address(addr))
        }
        ParamType::Uint(_) | ParamType::Int(_) => {
            let word = data[offset..offset + 32].to_vec();
            if matches!(param, ParamType::Uint(_)) {
                Ok(ArgumentValue::Uint(word))
            } else {
                Ok(ArgumentValue::Int(word))
            }
        }
        ParamType::Bool => {
            let b = data[offset + 31] != 0;
            Ok(ArgumentValue::Bool(b))
        }
        ParamType::FixedBytes(size) => {
            let bytes = data[offset..offset + size].to_vec();
            Ok(ArgumentValue::FixedBytes(bytes))
        }
        ParamType::Bytes => {
            let len = read_u256_as_usize(data, offset)?;
            let start = offset + 32;
            ensure_bytes(data, start, len)?;
            Ok(ArgumentValue::Bytes(data[start..start + len].to_vec()))
        }
        ParamType::String => {
            let len = read_u256_as_usize(data, offset)?;
            let start = offset + 32;
            ensure_bytes(data, start, len)?;
            let s = std::str::from_utf8(&data[start..start + len])
                .map_err(|e| DecodeError::InvalidEncoding(format!("invalid UTF-8: {e}")))?;
            Ok(ArgumentValue::String(s.to_string()))
        }
        ParamType::Array(inner) => {
            let len = read_u256_as_usize(data, offset)?;
            let elements_start = offset + 32;
            decode_array_elements(inner, data, elements_start, len)
        }
        ParamType::FixedArray(inner, len) => {
            decode_array_elements(inner, data, offset, *len)
        }
        ParamType::Tuple(members) => {
            let mut values = Vec::with_capacity(members.len());
            let mut member_offset = offset;
            for member in members {
                let value = decode_value(member, data, member_offset)?;
                values.push(value);
                member_offset += 32;
            }
            Ok(ArgumentValue::Tuple(values))
        }
    }
}

fn decode_array_elements(
    inner: &ParamType,
    data: &[u8],
    offset: usize,
    len: usize,
) -> Result<ArgumentValue, DecodeError> {
    let mut values = Vec::with_capacity(len);
    let mut elem_offset = offset;
    for _ in 0..len {
        let value = decode_value(inner, data, elem_offset)?;
        values.push(value);
        elem_offset += 32;
    }
    Ok(ArgumentValue::Array(values))
}

fn read_u256_as_usize(data: &[u8], offset: usize) -> Result<usize, DecodeError> {
    ensure_bytes(data, offset, 32)?;
    let word = &data[offset..offset + 32];
    // Check that high bytes are zero (offset should fit in usize)
    for &b in &word[..24] {
        if b != 0 {
            return Err(DecodeError::InvalidEncoding(
                "offset too large for usize".to_string(),
            ));
        }
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&word[24..32]);
    Ok(u64::from_be_bytes(bytes) as usize)
}

fn ensure_bytes(data: &[u8], offset: usize, len: usize) -> Result<(), DecodeError> {
    if offset + len > data.len() {
        Err(DecodeError::CalldataTooShort {
            expected: offset + len,
            actual: data.len(),
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_signature() {
        let sig = parse_signature("transfer(address,uint256)").unwrap();
        assert_eq!(sig.name, "transfer");
        assert_eq!(sig.params.len(), 2);
        assert_eq!(sig.params[0], ParamType::Address);
        assert_eq!(sig.params[1], ParamType::Uint(256));
        assert_eq!(sig.canonical, "transfer(address,uint256)");
    }

    #[test]
    fn test_parse_no_params() {
        let sig = parse_signature("pause()").unwrap();
        assert_eq!(sig.name, "pause");
        assert!(sig.params.is_empty());
    }

    #[test]
    fn test_parse_tuple_signature() {
        let sig = parse_signature("foo((address,uint256),bool)").unwrap();
        assert_eq!(sig.params.len(), 2);
        assert_eq!(
            sig.params[0],
            ParamType::Tuple(vec![ParamType::Address, ParamType::Uint(256)])
        );
        assert_eq!(sig.params[1], ParamType::Bool);
    }

    #[test]
    fn test_parse_array_types() {
        let sig = parse_signature("foo(uint256[],address[3])").unwrap();
        assert_eq!(
            sig.params[0],
            ParamType::Array(Box::new(ParamType::Uint(256)))
        );
        assert_eq!(
            sig.params[1],
            ParamType::FixedArray(Box::new(ParamType::Address), 3)
        );
    }

    #[test]
    fn test_selector_computation() {
        // transfer(address,uint256) selector = 0xa9059cbb
        let sig = parse_signature("transfer(address,uint256)").unwrap();
        assert_eq!(hex::encode(sig.selector), "a9059cbb");
    }

    #[test]
    fn test_decode_transfer_calldata() {
        let sig = parse_signature("transfer(address,uint256)").unwrap();

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&sig.selector);
        // address: 0x000...0001
        let mut addr_word = [0u8; 32];
        addr_word[31] = 1;
        calldata.extend_from_slice(&addr_word);
        // uint256: 1000
        let mut amount_word = [0u8; 32];
        amount_word[30] = 0x03;
        amount_word[31] = 0xe8;
        calldata.extend_from_slice(&amount_word);

        let decoded = decode_calldata(&sig, &calldata).unwrap();
        assert_eq!(decoded.function_name, "transfer");
        assert_eq!(decoded.args.len(), 2);

        if let ArgumentValue::Address(addr) = &decoded.args[0].value {
            assert_eq!(addr[19], 1);
        } else {
            panic!("expected Address");
        }

        if let ArgumentValue::Uint(bytes) = &decoded.args[1].value {
            assert_eq!(bytes[30], 0x03);
            assert_eq!(bytes[31], 0xe8);
        } else {
            panic!("expected Uint");
        }
    }

    #[test]
    fn test_decode_bool() {
        let sig = parse_signature("setApproval(bool)").unwrap();
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&sig.selector);
        let mut word = [0u8; 32];
        word[31] = 1;
        calldata.extend_from_slice(&word);

        let decoded = decode_calldata(&sig, &calldata).unwrap();
        if let ArgumentValue::Bool(b) = decoded.args[0].value {
            assert!(b);
        } else {
            panic!("expected Bool");
        }
    }

    #[test]
    fn test_selector_mismatch() {
        let sig = parse_signature("transfer(address,uint256)").unwrap();
        let calldata = [0u8; 36]; // wrong selector (all zeros)
        let result = decode_calldata(&sig, &calldata);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_all_basic_types() {
        let sig = parse_signature("f(address,uint256,int128,bool,bytes,bytes32,string)").unwrap();
        assert_eq!(sig.params[0], ParamType::Address);
        assert_eq!(sig.params[1], ParamType::Uint(256));
        assert_eq!(sig.params[2], ParamType::Int(128));
        assert_eq!(sig.params[3], ParamType::Bool);
        assert_eq!(sig.params[4], ParamType::Bytes);
        assert_eq!(sig.params[5], ParamType::FixedBytes(32));
        assert_eq!(sig.params[6], ParamType::String);
    }

    #[test]
    fn test_default_uint_int() {
        let sig = parse_signature("f(uint,int)").unwrap();
        assert_eq!(sig.params[0], ParamType::Uint(256));
        assert_eq!(sig.params[1], ParamType::Int(256));
    }
}
