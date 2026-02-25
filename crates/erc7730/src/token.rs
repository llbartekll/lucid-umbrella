/// Token metadata.
#[derive(Debug, Clone)]
pub struct TokenMeta {
    pub symbol: String,
    pub decimals: u8,
    pub name: String,
}

/// Normalized token lookup key (CAIP-19 style: `eip155:{chain_id}/erc20:{address}`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenLookupKey(pub String);

impl TokenLookupKey {
    /// Create a lookup key from chain ID and address.
    pub fn new(chain_id: u64, address: &str) -> Self {
        let addr = address.to_lowercase();
        Self(format!("eip155:{chain_id}/erc20:{addr}"))
    }
}

/// Trait for token metadata providers.
pub trait TokenSource {
    fn lookup(&self, key: &TokenLookupKey) -> Option<TokenMeta>;
}

/// A no-op token source that always returns None.
pub struct EmptyTokenSource;

impl TokenSource for EmptyTokenSource {
    fn lookup(&self, _key: &TokenLookupKey) -> Option<TokenMeta> {
        None
    }
}

/// In-memory token source for testing.
pub struct StaticTokenSource {
    tokens: std::collections::HashMap<TokenLookupKey, TokenMeta>,
}

impl StaticTokenSource {
    pub fn new() -> Self {
        Self {
            tokens: std::collections::HashMap::new(),
        }
    }

    pub fn insert(&mut self, chain_id: u64, address: &str, meta: TokenMeta) {
        self.tokens.insert(TokenLookupKey::new(chain_id, address), meta);
    }
}

impl Default for StaticTokenSource {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenSource for StaticTokenSource {
    fn lookup(&self, key: &TokenLookupKey) -> Option<TokenMeta> {
        self.tokens.get(key).cloned()
    }
}
