use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metadata section of a descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    /// Owner of this descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,

    /// Human-readable info about the descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<MetadataInfo>,

    /// Token metadata (for descriptors describing token contracts).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenInfo>,

    /// Enum definitions: key → { value → label }.
    #[serde(default)]
    pub enums: HashMap<String, HashMap<String, String>>,

    /// Constant definitions: key → value.
    #[serde(default)]
    pub constants: HashMap<String, serde_json::Value>,

    /// Address book: address → label.
    #[serde(rename = "addressBook")]
    #[serde(default)]
    pub address_book: HashMap<String, String>,

    /// Contract name for display.
    #[serde(rename = "contractName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_name: Option<String>,

    /// Named lookup tables (v2).
    #[serde(default)]
    pub maps: HashMap<String, MapDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    #[serde(rename = "legalName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legal_name: Option<String>,

    #[serde(rename = "lastUpdate")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_update: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticker: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,
}

/// A named map definition for value lookup/substitution (v2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapDefinition {
    /// The lookup entries: key → display value.
    #[serde(default)]
    pub entries: HashMap<String, String>,
}
