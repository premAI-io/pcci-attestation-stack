use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Module {
    Sev,
    Tdx,
    Nvidia,
}

#[derive(Serialize, Deserialize)]
pub struct Modules {
    modules: Vec<Module>,
}
