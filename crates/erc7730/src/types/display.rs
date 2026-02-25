use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level display section of a descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorDisplay {
    /// Reusable field definitions that can be referenced via `$ref`.
    #[serde(default)]
    pub definitions: HashMap<String, DisplayField>,

    /// Map of format key → display format.
    /// For calldata: key is function signature like `"transfer(address,uint256)"`.
    /// For EIP-712: key is primary type name.
    pub formats: HashMap<String, DisplayFormat>,
}

/// A single display format for a function or message type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayFormat {
    /// Human-readable intent label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<String>,

    /// Intent with `${path}` template variables for interpolation.
    #[serde(rename = "interpolatedIntent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpolated_intent: Option<String>,

    /// Ordered list of fields to display.
    #[serde(default)]
    pub fields: Vec<DisplayField>,

    /// Deprecated in v2 — list of excluded paths.
    #[serde(default)]
    pub excluded: Vec<String>,
}

/// A display field — can be a simple field, a field group, or a reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum DisplayField {
    /// A reference to a definition: `{ "$ref": "#/definitions/foo" }`.
    Reference {
        #[serde(rename = "$ref")]
        reference: String,
    },

    /// A grouped set of fields (v2): `{ "fieldGroup": { ... } }`.
    Group {
        #[serde(rename = "fieldGroup")]
        field_group: FieldGroup,
    },

    /// A simple field with path, label, format, etc.
    Simple {
        path: String,

        label: String,

        #[serde(skip_serializing_if = "Option::is_none")]
        format: Option<FieldFormat>,

        #[serde(skip_serializing_if = "Option::is_none")]
        params: Option<FormatParams>,

        #[serde(default = "default_visible")]
        visible: VisibleRule,
    },
}

fn default_visible() -> VisibleRule {
    VisibleRule::Always
}

/// A field group — replaces v1's `nestedFields`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldGroup {
    pub label: String,

    #[serde(default)]
    pub iteration: Iteration,

    pub fields: Vec<DisplayField>,
}

/// How grouped fields should be iterated for display.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Iteration {
    #[default]
    Sequential,
    Bundled,
}

/// Visibility rule for a field.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VisibleRule {
    /// Boolean shorthand: true = Always, false = Never.
    Bool(bool),

    /// String shorthand: "always" or "never".
    Named(String),

    /// Conditional visibility.
    Condition(VisibleCondition),

    /// Default: always visible.
    #[default]
    Always,
}

impl VisibleRule {
    /// Evaluate visibility against a decoded value.
    pub fn is_visible(&self, value: &serde_json::Value) -> bool {
        match self {
            VisibleRule::Always => true,
            VisibleRule::Bool(b) => *b,
            VisibleRule::Named(s) => s != "never",
            VisibleRule::Condition(cond) => cond.evaluate(value),
        }
    }
}

/// Conditional visibility: `ifNotIn` or `mustBe`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibleCondition {
    #[serde(rename = "ifNotIn")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub if_not_in: Option<Vec<serde_json::Value>>,

    #[serde(rename = "mustBe")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub must_be: Option<Vec<serde_json::Value>>,
}

impl VisibleCondition {
    pub fn evaluate(&self, value: &serde_json::Value) -> bool {
        if let Some(ref excluded) = self.if_not_in {
            if excluded.contains(value) {
                return false;
            }
        }
        if let Some(ref required) = self.must_be {
            if !required.contains(value) {
                return false;
            }
        }
        true
    }
}

/// Field format types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FieldFormat {
    TokenAmount,
    Amount,
    Date,
    #[serde(rename = "enum")]
    Enum,
    Address,
    AddressName,
    Number,
    Raw,
    TokenTicker,
    ChainId,
    Calldata,
    NftName,
    Duration,
    Unit,
}

/// Format parameters — varies by format type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatParams {
    /// Token address for tokenAmount/tokenTicker.
    #[serde(rename = "tokenPath")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_path: Option<String>,

    /// Native currency indicator.
    #[serde(rename = "nativeCurrencyAddress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_currency_address: Option<String>,

    /// Static chain ID for cross-chain token resolution.
    #[serde(rename = "chainId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,

    /// Dynamic chain ID path from calldata.
    #[serde(rename = "chainIdPath")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id_path: Option<String>,

    /// Enum lookup key in metadata.enums.
    #[serde(rename = "enumPath")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_path: Option<String>,

    /// Map reference key in metadata.maps.
    #[serde(rename = "mapReference")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub map_reference: Option<String>,

    /// Encryption parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionParams>,
}

/// Encryption parameters for encrypted fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionParams {
    #[serde(rename = "fallbackLabel")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_label: Option<String>,
}
