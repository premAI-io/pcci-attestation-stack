use std::backtrace::Backtrace;

use thiserror::Error;

use crate::{certificates::CertificateError, dcap::parser::ParseError};

#[derive(Error, Debug)]
pub enum Error {
    #[error("certificate error: {0}")]
    Certificate(#[from] CertificateError),

    #[error("error parsing the dcap quote: {0}")]
    Parse(#[from] ParseError),

    #[error("cryptographic error: {0}")]
    Crypto(#[from] p256::ecdsa::Error),

    #[error("this error")]
    SignatureFormat(#[from] sec1::Error),
}
