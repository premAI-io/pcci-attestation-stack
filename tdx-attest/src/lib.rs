use tdx_quote::{QeReportCertificationData, Quote, QuoteParseError};
use thiserror::Error;

pub mod keychain;

#[derive(Error, Debug)]
pub enum TdxError {
    #[error("{0}")]
    Parsing(#[from] QuoteParseError),

    #[error("the tdx quote is missing QE identity")]
    MissingQe,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen(js_namespace = "sev"))]
pub struct TdxQuote {
    quote: Quote,
    qe_identity: QeReportCertificationData,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen(js_namespace = "sev"))]
impl TdxQuote {
    pub fn parse(quote: &[u8]) -> Result<Self, TdxError> {
        let quote = Quote::from_bytes(quote)?;
        let qe_identity = quote
            .qe_report_certification_data()
            .ok_or(TdxError::MissingQe)?;

        todo!();
    }
}
