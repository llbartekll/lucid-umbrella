//! Pluggable descriptor resolution via the [`DescriptorSource`] trait.
//! Includes [`StaticSource`] for testing and embedded use cases.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use crate::error::ResolveError;
use crate::types::descriptor::Descriptor;

/// A resolved descriptor ready for use.
#[derive(Debug, Clone)]
pub struct ResolvedDescriptor {
    pub descriptor: Descriptor,
    pub chain_id: u64,
    pub address: String,
}

/// Trait for descriptor sources (embedded, filesystem, GitHub API, etc.).
pub trait DescriptorSource: Send + Sync {
    /// Resolve a descriptor for contract calldata clear signing.
    fn resolve_calldata(
        &self,
        chain_id: u64,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ResolvedDescriptor, ResolveError>> + Send + '_>>;

    /// Resolve a descriptor for EIP-712 typed data clear signing.
    fn resolve_typed(
        &self,
        chain_id: u64,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ResolvedDescriptor, ResolveError>> + Send + '_>>;
}

/// Static in-memory descriptor source for testing.
pub struct StaticSource {
    /// Map of `"{chain_id}:{address}"` → Descriptor.
    calldata: HashMap<String, Descriptor>,
    typed: HashMap<String, Descriptor>,
}

impl StaticSource {
    pub fn new() -> Self {
        Self {
            calldata: HashMap::new(),
            typed: HashMap::new(),
        }
    }

    fn make_key(chain_id: u64, address: &str) -> String {
        format!("{}:{}", chain_id, address.to_lowercase())
    }

    /// Add a calldata descriptor.
    pub fn add_calldata(&mut self, chain_id: u64, address: &str, descriptor: Descriptor) {
        self.calldata
            .insert(Self::make_key(chain_id, address), descriptor);
    }

    /// Add a typed data descriptor.
    pub fn add_typed(&mut self, chain_id: u64, address: &str, descriptor: Descriptor) {
        self.typed
            .insert(Self::make_key(chain_id, address), descriptor);
    }

    /// Add a calldata descriptor from JSON.
    pub fn add_calldata_json(
        &mut self,
        chain_id: u64,
        address: &str,
        json: &str,
    ) -> Result<(), ResolveError> {
        let descriptor: Descriptor =
            serde_json::from_str(json).map_err(|e| ResolveError::Parse(e.to_string()))?;
        self.add_calldata(chain_id, address, descriptor);
        Ok(())
    }

    /// Add a typed data descriptor from JSON.
    pub fn add_typed_json(
        &mut self,
        chain_id: u64,
        address: &str,
        json: &str,
    ) -> Result<(), ResolveError> {
        let descriptor: Descriptor =
            serde_json::from_str(json).map_err(|e| ResolveError::Parse(e.to_string()))?;
        self.add_typed(chain_id, address, descriptor);
        Ok(())
    }
}

impl Default for StaticSource {
    fn default() -> Self {
        Self::new()
    }
}

impl DescriptorSource for StaticSource {
    fn resolve_calldata(
        &self,
        chain_id: u64,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ResolvedDescriptor, ResolveError>> + Send + '_>> {
        let key = Self::make_key(chain_id, address);
        let result = self
            .calldata
            .get(&key)
            .cloned()
            .map(|descriptor| ResolvedDescriptor {
                descriptor,
                chain_id,
                address: address.to_lowercase(),
            })
            .ok_or_else(|| ResolveError::NotFound {
                chain_id,
                address: address.to_string(),
            });
        Box::pin(async move { result })
    }

    fn resolve_typed(
        &self,
        chain_id: u64,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ResolvedDescriptor, ResolveError>> + Send + '_>> {
        let key = Self::make_key(chain_id, address);
        let result = self
            .typed
            .get(&key)
            .cloned()
            .map(|descriptor| ResolvedDescriptor {
                descriptor,
                chain_id,
                address: address.to_lowercase(),
            })
            .ok_or_else(|| ResolveError::NotFound {
                chain_id,
                address: address.to_string(),
            });
        Box::pin(async move { result })
    }
}

/// Filesystem-based descriptor source — reads and indexes all JSON descriptors from a directory.
pub struct FilesystemSource {
    index: HashMap<String, Descriptor>,
}

impl FilesystemSource {
    /// Load and index all descriptor JSON files recursively from a directory.
    pub fn from_directory(path: &std::path::Path) -> Result<Self, ResolveError> {
        let mut index = HashMap::new();

        fn walk_dir(
            dir: &std::path::Path,
            index: &mut HashMap<String, Descriptor>,
        ) -> Result<(), ResolveError> {
            let entries = std::fs::read_dir(dir).map_err(|e| ResolveError::Io(e.to_string()))?;
            for entry in entries {
                let entry = entry.map_err(|e| ResolveError::Io(e.to_string()))?;
                let path = entry.path();
                if path.is_dir() {
                    walk_dir(&path, index)?;
                } else if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    let content = std::fs::read_to_string(&path)
                        .map_err(|e| ResolveError::Io(e.to_string()))?;
                    match serde_json::from_str::<Descriptor>(&content) {
                        Ok(descriptor) => {
                            for deployment in descriptor.context.deployments() {
                                let key = format!(
                                    "{}:{}",
                                    deployment.chain_id,
                                    deployment.address.to_lowercase()
                                );
                                index.insert(key, descriptor.clone());
                            }
                        }
                        Err(_) => {
                            // Skip non-descriptor JSON files
                            continue;
                        }
                    }
                }
            }
            Ok(())
        }

        walk_dir(path, &mut index)?;
        Ok(Self { index })
    }

    fn make_key(chain_id: u64, address: &str) -> String {
        format!("{}:{}", chain_id, address.to_lowercase())
    }
}

impl DescriptorSource for FilesystemSource {
    fn resolve_calldata(
        &self,
        chain_id: u64,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ResolvedDescriptor, ResolveError>> + Send + '_>> {
        let key = Self::make_key(chain_id, address);
        let result = self
            .index
            .get(&key)
            .cloned()
            .map(|descriptor| ResolvedDescriptor {
                descriptor,
                chain_id,
                address: address.to_lowercase(),
            })
            .ok_or_else(|| ResolveError::NotFound {
                chain_id,
                address: address.to_string(),
            });
        Box::pin(async move { result })
    }

    fn resolve_typed(
        &self,
        chain_id: u64,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ResolvedDescriptor, ResolveError>> + Send + '_>> {
        self.resolve_calldata(chain_id, address)
    }
}

/// HTTP-based descriptor source that fetches from a GitHub registry.
///
/// Requires the `github-registry` feature.
#[cfg(feature = "github-registry")]
pub struct GitHubRegistrySource {
    base_url: String,
    /// Maps "{chain_id}:{address_lowercase}" → relative path in registry
    index: HashMap<String, String>,
    /// In-memory descriptor cache (tokio Mutex for async safety)
    cache: tokio::sync::Mutex<HashMap<String, Descriptor>>,
}

#[cfg(feature = "github-registry")]
impl GitHubRegistrySource {
    /// Create a new source with a manually provided index.
    ///
    /// `base_url`: raw content URL prefix (e.g., `"https://raw.githubusercontent.com/org/repo/main"`).
    /// `index`: maps `"{chain_id}:{address}"` → relative path (e.g., `"aave/calldata-lpv3.json"`).
    pub fn new(base_url: &str, index: HashMap<String, String>) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            index,
            cache: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Create a source by fetching `index.json` from the registry.
    ///
    /// The index maps `"{chain_id}:{address_lowercase}"` → relative descriptor path.
    pub async fn from_registry(base_url: &str) -> Result<Self, ResolveError> {
        let base = base_url.trim_end_matches('/');
        let index_url = format!("{}/index.json", base);
        let response = reqwest::get(&index_url).await.map_err(|e| {
            if e.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                ResolveError::NotFound {
                    chain_id: 0,
                    address: format!("index.json at {index_url}"),
                }
            } else {
                ResolveError::Io(format!("HTTP fetch index failed: {e}"))
            }
        })?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(ResolveError::NotFound {
                chain_id: 0,
                address: format!("index.json at {index_url}"),
            });
        }
        let body = response
            .text()
            .await
            .map_err(|e| ResolveError::Io(format!("read index response: {e}")))?;
        let index: HashMap<String, String> =
            serde_json::from_str(&body).map_err(|e| ResolveError::Parse(e.to_string()))?;
        Ok(Self::new(base, index))
    }

    fn make_key(chain_id: u64, address: &str) -> String {
        format!("eip155:{}:{}", chain_id, address.to_lowercase())
    }

    async fn fetch_descriptor(&self, rel_path: &str) -> Result<Descriptor, ResolveError> {
        let url = format!("{}/{}", self.base_url, rel_path);
        let response = reqwest::get(&url).await.map_err(|e| {
            if e.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                ResolveError::NotFound {
                    chain_id: 0,
                    address: format!("descriptor at {url}"),
                }
            } else {
                ResolveError::Io(format!("HTTP fetch failed: {e}"))
            }
        })?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(ResolveError::NotFound {
                chain_id: 0,
                address: format!("descriptor at {url}"),
            });
        }
        let body = response
            .text()
            .await
            .map_err(|e| ResolveError::Io(format!("read response: {e}")))?;
        serde_json::from_str(&body).map_err(|e| ResolveError::Parse(e.to_string()))
    }
}

#[cfg(feature = "github-registry")]
impl DescriptorSource for GitHubRegistrySource {
    fn resolve_calldata(
        &self,
        chain_id: u64,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ResolvedDescriptor, ResolveError>> + Send + '_>> {
        let address_owned = address.to_lowercase();
        Box::pin(async move {
            let key = Self::make_key(chain_id, &address_owned);

            // Check cache first
            if let Some(cached) = self.cache.lock().await.get(&key) {
                return Ok(ResolvedDescriptor {
                    descriptor: cached.clone(),
                    chain_id,
                    address: address_owned,
                });
            }

            let rel_path = self.index.get(&key).ok_or_else(|| ResolveError::NotFound {
                chain_id,
                address: address_owned.clone(),
            })?;

            let descriptor = self.fetch_descriptor(rel_path).await?;
            self.cache.lock().await.insert(key, descriptor.clone());

            Ok(ResolvedDescriptor {
                descriptor,
                chain_id,
                address: address_owned,
            })
        })
    }

    fn resolve_typed(
        &self,
        chain_id: u64,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Result<ResolvedDescriptor, ResolveError>> + Send + '_>> {
        self.resolve_calldata(chain_id, address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_static_source_not_found() {
        let source = StaticSource::new();
        let result = source.resolve_calldata(1, "0xabc").await;
        assert!(result.is_err());
    }
}
