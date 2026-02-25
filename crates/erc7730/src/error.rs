use thiserror::Error;

/// Unified error type for the ERC-7730 library.
#[derive(Debug, Error)]
pub enum Error {
    #[error("decode error: {0}")]
    Decode(#[from] DecodeError),

    #[error("descriptor error: {0}")]
    Descriptor(String),

    #[error("resolve error: {0}")]
    Resolve(#[from] ResolveError),

    #[error("token registry error: {0}")]
    TokenRegistry(String),

    #[error("render error: {0}")]
    Render(String),
}

/// Errors during signature parsing and calldata decoding.
#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("invalid function signature: {0}")]
    InvalidSignature(String),

    #[error("calldata too short: expected at least {expected} bytes, got {actual}")]
    CalldataTooShort { expected: usize, actual: usize },

    #[error("selector mismatch: expected {expected}, got {actual}")]
    SelectorMismatch { expected: String, actual: String },

    #[error("invalid ABI encoding: {0}")]
    InvalidEncoding(String),

    #[error("unsupported type: {0}")]
    UnsupportedType(String),
}

/// Errors during descriptor resolution.
#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("descriptor not found for chain_id={chain_id}, address={address}")]
    NotFound { chain_id: u64, address: String },

    #[error("parse error: {0}")]
    Parse(String),

    #[error("io error: {0}")]
    Io(String),
}
