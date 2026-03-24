use serde::{Deserialize, Serialize};

use crate::pcs::tcb::TcbLevel;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentity {
    pub id: String,
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub tcb_evaluation_data_number: u32,
    #[serde(with = "hex::serde")]
    pub miscselect: [u8; 4],
    #[serde(with = "hex::serde")]
    pub miscselect_mask: [u8; 4],
    pub attributes: String,
    #[serde(with = "hex::serde")]
    pub attributes_mask: [u8; 4],
    #[serde(with = "hex::serde")]
    pub mrsigner: [u8; 32],
    pub isvprodid: u16,
    pub tcb_levels: Vec<QeTcbLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeTcbLevel {
    pub tcb: QeTcb,
    pub tcb_date: String,
    pub tcb_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QeTcb {
    pub isvsvn: u16,
}
