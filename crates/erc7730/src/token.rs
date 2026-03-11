//! Token metadata resolution via the [`TokenSource`] trait.
//! Uses CAIP-19 keys (`eip155:{chain}/erc20:{addr}`) for cross-chain lookups.

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
pub trait TokenSource: Send + Sync {
    fn lookup(&self, key: &TokenLookupKey) -> Option<TokenMeta>;
}

/// A no-op token source that always returns None.
pub struct EmptyTokenSource;

impl TokenSource for EmptyTokenSource {
    fn lookup(&self, _key: &TokenLookupKey) -> Option<TokenMeta> {
        None
    }
}

/// Well-known token source with embedded metadata for common tokens.
pub struct WellKnownTokenSource {
    tokens: std::collections::HashMap<TokenLookupKey, TokenMeta>,
}

impl WellKnownTokenSource {
    pub fn new() -> Self {
        let json_str = include_str!("assets/tokens.json");
        let raw: std::collections::HashMap<String, WellKnownEntry> =
            serde_json::from_str(json_str).expect("embedded tokens.json is valid");
        let mut tokens = std::collections::HashMap::new();
        for (key, entry) in raw {
            tokens.insert(
                TokenLookupKey(key),
                TokenMeta {
                    symbol: entry.symbol,
                    decimals: entry.decimals,
                    name: entry.name,
                },
            );
        }
        Self { tokens }
    }
}

impl Default for WellKnownTokenSource {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenSource for WellKnownTokenSource {
    fn lookup(&self, key: &TokenLookupKey) -> Option<TokenMeta> {
        self.tokens.get(key).cloned()
    }
}

#[derive(serde::Deserialize)]
struct WellKnownEntry {
    symbol: String,
    decimals: u8,
    name: String,
}

/// Composite token source that chains multiple sources, returning the first match.
pub struct CompositeTokenSource {
    sources: Vec<Box<dyn TokenSource + Send + Sync>>,
}

impl CompositeTokenSource {
    pub fn new(sources: Vec<Box<dyn TokenSource + Send + Sync>>) -> Self {
        Self { sources }
    }
}

impl TokenSource for CompositeTokenSource {
    fn lookup(&self, key: &TokenLookupKey) -> Option<TokenMeta> {
        for source in &self.sources {
            if let Some(meta) = source.lookup(key) {
                return Some(meta);
            }
        }
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
        self.tokens
            .insert(TokenLookupKey::new(chain_id, address), meta);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_well_known_usdc_mainnet() {
        let source = WellKnownTokenSource::new();
        let key = TokenLookupKey::new(1, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let meta = source
            .lookup(&key)
            .expect("USDC should be in well-known tokens");
        assert_eq!(meta.symbol, "USDC");
        assert_eq!(meta.decimals, 6);
    }

    #[test]
    fn test_well_known_usdc_base() {
        let source = WellKnownTokenSource::new();
        let key = TokenLookupKey::new(8453, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
        let meta = source.lookup(&key).expect("USDC on Base should be found");
        assert_eq!(meta.symbol, "USDC");
        assert_eq!(meta.decimals, 6);
    }

    #[test]
    fn test_well_known_not_found() {
        let source = WellKnownTokenSource::new();
        let key = TokenLookupKey::new(1, "0x0000000000000000000000000000000000000001");
        assert!(source.lookup(&key).is_none());
    }

    #[test]
    fn test_composite_source_fallthrough() {
        let mut custom = StaticTokenSource::new();
        custom.insert(
            1,
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            TokenMeta {
                symbol: "CUSTOM_USDC".to_string(),
                decimals: 6,
                name: "Custom USDC".to_string(),
            },
        );

        let composite = CompositeTokenSource::new(vec![
            Box::new(custom),
            Box::new(WellKnownTokenSource::new()),
        ]);

        // Custom takes precedence
        let key = TokenLookupKey::new(1, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let meta = composite.lookup(&key).unwrap();
        assert_eq!(meta.symbol, "CUSTOM_USDC");

        // Falls through to well-known for tokens not in custom
        let key2 = TokenLookupKey::new(1, "0xdac17f958d2ee523a2206206994597c13d831ec7");
        let meta2 = composite.lookup(&key2).unwrap();
        assert_eq!(meta2.symbol, "USDT");
    }
}
