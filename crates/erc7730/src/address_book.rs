use std::collections::HashMap;

use crate::types::context::DescriptorContext;
use crate::types::metadata::Metadata;

/// Address label resolver — merges labels from descriptor deployments,
/// metadata address book, and external sources.
#[derive(Debug, Clone)]
pub struct AddressBook {
    entries: HashMap<String, String>,
}

impl AddressBook {
    /// Build an address book from descriptor context and metadata.
    pub fn from_descriptor(context: &DescriptorContext, metadata: &Metadata) -> Self {
        let mut entries = HashMap::new();

        // Add deployment addresses with contract name as label
        if let Some(ref name) = metadata.contract_name {
            for deployment in context.deployments() {
                let addr = deployment.address.to_lowercase();
                entries.insert(addr, name.clone());
            }
        }

        // Merge metadata address book entries
        for (addr, label) in &metadata.address_book {
            entries.insert(addr.to_lowercase(), label.clone());
        }

        Self { entries }
    }

    /// Create an empty address book.
    pub fn empty() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Look up a label for an address.
    pub fn resolve(&self, address: &str) -> Option<&str> {
        self.entries
            .get(&address.to_lowercase())
            .map(|s| s.as_str())
    }

    /// Add or override an entry.
    pub fn insert(&mut self, address: String, label: String) {
        self.entries.insert(address.to_lowercase(), label);
    }

    /// Merge entries from another address book.
    pub fn merge(&mut self, other: &AddressBook) {
        for (addr, label) in &other.entries {
            self.entries
                .entry(addr.clone())
                .or_insert_with(|| label.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_case_insensitive() {
        let mut book = AddressBook::empty();
        book.insert(
            "0xdAC17F958D2ee523a2206206994597C13D831ec7".to_string(),
            "Tether USD".to_string(),
        );
        assert_eq!(
            book.resolve("0xdac17f958d2ee523a2206206994597c13d831ec7"),
            Some("Tether USD")
        );
        assert_eq!(
            book.resolve("0xDAC17F958D2EE523A2206206994597C13D831EC7"),
            Some("Tether USD")
        );
    }

    #[test]
    fn test_merge_no_overwrite() {
        let mut book1 = AddressBook::empty();
        book1.insert("0xabc".to_string(), "Original".to_string());

        let mut book2 = AddressBook::empty();
        book2.insert("0xabc".to_string(), "Override".to_string());
        book2.insert("0xdef".to_string(), "New".to_string());

        book1.merge(&book2);
        assert_eq!(book1.resolve("0xabc"), Some("Original"));
        assert_eq!(book1.resolve("0xdef"), Some("New"));
    }
}
