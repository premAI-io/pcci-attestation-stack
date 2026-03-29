use std::fmt::Display;

use serde::{Deserialize, Serialize};

use crate::dcap::types::Fmspc;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    pub id: String,
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub fmspc: Fmspc,
    pub pce_id: String,
    pub tcb_type: u32,
    pub tcb_evaluation_data_number: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_module: Option<TdxModule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_module_identities: Option<Vec<TdxModuleIdentity>>,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModule {
    pub mrsigner: String,
    pub attributes: String,
    pub attributes_mask: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentity {
    pub id: String,
    pub mrsigner: String,
    pub attributes: String,
    pub attributes_mask: String,
    pub tcb_levels: Vec<TdxModuleTcbLevel>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleTcbLevel {
    pub tcb: TdxModuleTcb,
    pub tcb_date: String,
    pub tcb_status: TdxModuleTcbStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdxModuleTcb {
    pub isvsvn: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub enum TdxModuleTcbStatus {
    UpToDate,
    OutOfDate,
    Revoked,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[must_use]
pub struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_date: String,
    pub tcb_status: TcbStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tcb {
    pub pcesvn: u16,
    pub sgxtcbcomponents: Vec<TcbComponent>,
    pub tdxtcbcomponents: Option<Vec<TcbComponent>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcbComponent {
    pub svn: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub component_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd)]
pub enum TcbStatus {
    Revoked,
    OutOfDateConfigurationNeeded,
    OutOfDate,
    ConfigurationAndSWHardeningNeeded,
    ConfigurationNeeded,
    SWHardeningNeeded,
    UpToDate,
}

impl Display for TcbStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display = match self {
            Self::Revoked => "revoked",
            Self::OutOfDate => "out of date",
            Self::ConfigurationAndSWHardeningNeeded => "configuration and sw hardening needed",
            Self::ConfigurationNeeded => "configuration needed",
            Self::SWHardeningNeeded => "sw hardening needed",
            Self::UpToDate => "up to date",
            Self::OutOfDateConfigurationNeeded => "out of date and configuration needed",
        };

        f.write_str(display)
    }
}
