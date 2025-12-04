/// Certificate chain structures and methods
pub mod chain;
/// Error structure
pub mod error;
/// Methods for interacting with AMD's keyserver
pub mod kds;
///
pub mod nonce;

use std::ops::Deref;

use crate::oid;
use der::Encode;
use nonce::Nonce;
use sev::{Generation, firmware::guest::AttestationReport, parser::ByteParser};
use wasm_bindgen::prelude::*;
use x509_parser::prelude::*;

use self::{
    chain::VerifiedChain,
    error::{AttestationError, ParseReason, VerificationReason},
};

#[wasm_bindgen]
/// Represents a parsed attestation report with some already
/// parsed commonly accessed fields
pub struct ParsedAttestation {
    cpu_fam_id: u8,
    cpu_mod_id: u8,
    generation: Generation,

    report: AttestationReport,
}

#[wasm_bindgen]
impl ParsedAttestation {
    #[wasm_bindgen(constructor)]
    /// Parses and constructs a new attestation report from a stream of binary data
    pub fn new(bytes: &[u8]) -> Result<Self, AttestationError> {
        let report =
            AttestationReport::from_bytes(bytes).map_err(|_| ParseReason::BadAttestationData)?;

        let cpu_fam_id = report
            .cpuid_fam_id
            .ok_or(ParseReason::MissingAttestationField)?;
        let cpu_mod_id = report
            .cpuid_mod_id
            .ok_or(ParseReason::MissingAttestationField)?;

        let generation = sev::Generation::identify_cpu(cpu_fam_id, cpu_mod_id)
            .map_err(|_| ParseReason::IdentifyCpu)?;

        Ok(ParsedAttestation {
            cpu_fam_id,
            cpu_mod_id,
            generation,
            report,
        })
    }

    #[wasm_bindgen]
    /// Verifies the attestation report against a certificate chain
    pub fn verify(&self, chain: &VerifiedChain, nonce: &Nonce) -> Result<(), AttestationError> {
        // let certificates = chain.parse_certificates()?;

        // TODO: unify everything and use either x509-cert or x509-parser
        let vek = chain.vek.cert();
        let vek = vek.to_der().unwrap();
        let (_, vek) = X509Certificate::from_der(&vek).unwrap();

        /* Check TCB */
        let exts_map = vek.extensions_map()?;

        oid::check_spl(self.report.reported_tcb, &exts_map).map_err(|_| VerificationReason::Spl)?;

        /* Compare HWID */
        if let Some(hwid) = exts_map.get(&oid::HWID) {
            oid::compare_bytes(hwid, &self.report.chip_id.to_vec())
                .then_some(())
                .ok_or(VerificationReason::ChipId)?;
        }

        let product_name_ext = exts_map.get(&oid::PRODUCT_NAME).unwrap();
        let (product_name, _) = crate::kds::decode_product_name(product_name_ext.value.to_vec())
            .map_err(|_| ParseReason::DecodeProductName)?;

        if product_name != self.generation.titlecase() {
            Err(VerificationReason::BadProductName)?;
        }

        /* Check full chain */
        log::info!("Verifying self report signature");
        chain.check_signature(&self.report)?;

        if &self.report.report_data != nonce.deref() {
            log::error!("wrong nonce in reported data");
            return Err(AttestationError::WrongNonce);
        }

        log::info!("Verification ok!");
        Ok(())
    }
}
