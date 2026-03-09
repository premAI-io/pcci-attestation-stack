use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentity {
    pub id: String,
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub tcb_evaluation_data_number: u32,
    pub miscselect: String,
    pub miscselect_mask: String,
    pub attributes: String,
    pub attributes_mask: String,
    pub mrsigner: String,
    pub isvprodid: u16,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_date: String,
    pub tcb_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tcb {
    pub isvsvn: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TcbStatus {
    UpToDate,
    OutOfDate,
    Revoked,
    ConfigurationNeeded,
    OutOfDateConfigurationNeeded,
    SWHardeningNeeded,
}
