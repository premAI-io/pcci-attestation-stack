#![allow(unused)]
use p256::ecdsa::VerifyingKey;
use p256::{EncodedPoint, elliptic_curve};
use p256::{PublicKey, ecdsa::Signature};

use crate::dcap::TdQuote;
use crate::dcap::parser::Parse;
use crate::error::Error;

use crate::{
    certificates::CertificateChain,
    dcap::types::{EnclaveReport, QuoteBody, QuoteHeader},
};

pub mod certificates;
pub mod dcap;
pub mod error;
pub mod keychain;
pub mod pcs;

#[derive(Debug)]
pub struct QeReportCertificationData {
    qe_report: EnclaveReport,
    qe_report_signature: Signature,
    authentication_data: Vec<u8>,
    certification_data: CertificationData,
}

impl TryFrom<dcap::QeReportCertificationData<'_>> for QeReportCertificationData {
    type Error = Error;
    fn try_from(value: dcap::QeReportCertificationData<'_>) -> Result<Self, Self::Error> {
        let qe_report = value.qe_report.clone();
        let certification_data = value.certification_data.try_into()?;
        let qe_report_signature = Signature::from_bytes(value.qe_report_signature.into())?;
        let authentication_data = value.qe_authentication_data.inner().to_vec();

        Ok(Self {
            qe_report,
            qe_report_signature,
            authentication_data,
            certification_data,
        })
    }
}

#[derive(Debug)]
pub enum CertificationData {
    PlainText(Vec<u8>),
    EncryptedCpuSvnsRSA2048(Vec<u8>),
    EncryptedCpuSvnsRSA3072(Vec<u8>),
    PckChain(CertificateChain),
    QeReportCertificationData(Box<QeReportCertificationData>),
}

impl TryFrom<dcap::QeCertificationData<'_>> for CertificationData {
    type Error = Error;
    fn try_from(value: dcap::QeCertificationData<'_>) -> Result<Self, Self::Error> {
        use dcap::QeCertificationData::*;

        let certification_data = match value {
            PlainText(x) => Self::PlainText(x.to_owned()),
            EncryptedCpuSvnsRSA2048(x) => Self::EncryptedCpuSvnsRSA2048(x.to_owned()),
            EncryptedCpuSvnsRSA3072(x) => Self::EncryptedCpuSvnsRSA3072(x.to_owned()),
            PckChain(chain) => Self::PckChain(CertificateChain::parse_pem_chain(chain)?),
            QeReportCertificationData(report) => {
                Self::QeReportCertificationData(Box::new((*report).try_into()?))
            }
        };

        Ok(certification_data)
    }
}

#[derive(Debug)]
pub struct Certification {
    attestation_signature: Signature,
    attestation_key: VerifyingKey,
    certification_data: CertificationData,
}

impl TryFrom<dcap::Certification<'_>> for Certification {
    type Error = Error;
    fn try_from(value: dcap::Certification<'_>) -> Result<Self, Self::Error> {
        // let attestation_key = VerifyingKey::from_sec1_bytes(value.attestation_key)?;
        let attestation_key = decode_public_key(value.attestation_key)?;
        let attestation_signature = Signature::from_bytes(value.quote_signature.into())?;
        let certification_data = value.quote_data.try_into()?;

        Ok(Self {
            attestation_signature,
            attestation_key,
            certification_data,
        })
    }
}

#[derive(Debug)]
pub struct Quote {
    header: QuoteHeader,
    body: QuoteBody,
    certification: Certification,
}

impl TryFrom<dcap::TdQuote<'_>> for Quote {
    type Error = Error;
    fn try_from(value: dcap::TdQuote<'_>) -> Result<Self, Self::Error> {
        let header = value.quote_header.clone();
        let body = value.quote_body.clone();
        let certification = value.certification.try_into()?;

        Ok(Self {
            header,
            body,
            certification,
        })
    }
}

impl Quote {
    pub fn from_bytes(quote: &[u8]) -> Result<Self, Error> {
        let quote = TdQuote::parse(quote)?;
        let quote = quote.try_into()?;

        Ok(quote)
    }
}

/// public keys are encoded in dcap without the header for sec1 (0x04)
/// so we have to add it manually
pub fn decode_public_key(public_key: &[u8; 64]) -> Result<VerifyingKey, p256::ecdsa::Error> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(public_key);

    VerifyingKey::from_sec1_bytes(&sec1)
}
