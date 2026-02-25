use serde::{Deserialize, Serialize};

/// Top-level context discriminator — either contract (calldata) or eip712.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DescriptorContext {
    Contract(ContractContext),
    Eip712(Eip712Context),
}

/// Context for contract calldata clear signing.
/// v2: no `abi` field — ABI is derived from function signatures in format keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractContext {
    #[serde(rename = "$id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    pub contract: ContractInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractInfo {
    #[serde(default)]
    pub deployments: Vec<Deployment>,
}

/// Context for EIP-712 typed data clear signing.
/// v2: no `schemas` field — deprecated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip712Context {
    #[serde(rename = "$id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    pub eip712: Eip712Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip712Info {
    #[serde(default)]
    pub deployments: Vec<Deployment>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<Eip712Domain>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip712Domain {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(rename = "verifyingContract")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifying_contract: Option<String>,
}

/// A single chain + address deployment entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    #[serde(rename = "chainId")]
    pub chain_id: u64,

    pub address: String,
}

impl DescriptorContext {
    pub fn deployments(&self) -> &[Deployment] {
        match self {
            DescriptorContext::Contract(c) => &c.contract.deployments,
            DescriptorContext::Eip712(e) => &e.eip712.deployments,
        }
    }

    pub fn is_contract(&self) -> bool {
        matches!(self, DescriptorContext::Contract(_))
    }

    pub fn is_eip712(&self) -> bool {
        matches!(self, DescriptorContext::Eip712(_))
    }
}
