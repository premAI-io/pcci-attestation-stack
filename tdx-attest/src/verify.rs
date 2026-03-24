use sha2::{Digest, Sha256, digest::Update};
use signature::Verifier;
use zerocopy::IntoBytes;

use crate::{
    Certification, Quote,
    certificates::crl::VerifyCrl,
    dcap::{parser::ParseErrorExt, types::QuoteBody},
    error::TdxError,
    pcs::Collateral,
};

/// Verifies:
/// 1. QE report signature
/// 2. QE report hashes
///
/// After this function the ISV report key can be used to verify
/// the ISV report signature
fn verify_qe_report(quote: &Quote, collateral: &Collateral) -> Result<(), TdxError> {
    let certification = quote.certification();

    // Certificate revocation check
    let pck_chain = certification
        .data
        .pck_chain()
        .context("failed extracting pck chain from tdx quote")?;

    collateral.crl.check_revoked(pck_chain)?;

    // Verify that pck_chain attests the qe signature
    let qe_report = certification
        .data
        .qe_report()
        .context("qe report is not in the first level of nesting in dcap quote")?;

    let qe_report_data = qe_report.qe_report.as_bytes();
    pck_chain.verify(qe_report_data, &qe_report.qe_report_signature)?;

    // now verify hashes
    let attestation_key = certification.attestation_key.to_sec1_bytes();
    let attestation_key = &attestation_key[1..]; // remove 0x04 header
    debug_assert_eq!(attestation_key.len(), 64);

    let sha = Sha256::new()
        .chain(attestation_key)
        .chain(&qe_report.authentication_data)
        // .chain([0x00; 32])
        .finalize();

    let report_data = &qe_report.qe_report.report_data[..32]; // hash is found only in first 32 bytes as per dcap documentation

    if sha.as_bytes() != report_data {
        return TdxError::msg("qe report_data hash mismatch");
    }

    Ok(())
}

/// Verifies:
/// 1. ISV report signature using ISV report key
fn verify_isv_signature(quote: &Quote, collateral: &Collateral) -> Result<(), TdxError> {
    let mut signed_data = vec![];
    signed_data.extend_from_slice(quote.header.as_bytes());
    signed_data.extend_from_slice(quote.body.as_bytes());

    quote
        .certification
        .attestation_key
        .verify(&signed_data, &quote.certification.attestation_signature)?;

    Ok(())
}

fn verify_qe_identity_policy(quote: &Quote, collateral: &Collateral) -> Result<(), TdxError> {
    let enclave_report = &quote
        .certification
        .data
        .qe_report()
        .context("missing qe report from certification data")?
        .qe_report;
    let qe_identity = &collateral.qe_identity;

    if enclave_report.mrsigner != qe_identity.mrsigner {
        return TdxError::msg("mrsigner mismatch between qe identity and enclave report");
    }

    if enclave_report.isv_prod_id != qe_identity.isvprodid {
        return TdxError::msg("isv_prod_id mismatch between qe identity and enclave report");
    }

    if enclave_report.attributes[0] & 0x02 != 0x00 {
        return TdxError::msg("qe debug mode is active");
    }

    let expected_miscelect = u32::from_le_bytes(qe_identity.miscselect);
    let miscelect_mask = u32::from_le_bytes(qe_identity.miscselect_mask);

    if (expected_miscelect & miscelect_mask) != (enclave_report.miscselect & miscelect_mask) {
        return TdxError::msg("mismatched miscelect from qe identity");
    }

    todo!()
}

pub fn verify(quote: &Quote, collateral: &Collateral) -> Result<(), TdxError> {
    let certification = quote.certification();

    verify_qe_report(quote, collateral)?;
    verify_isv_signature(quote, collateral)?;

    Ok(())
}
