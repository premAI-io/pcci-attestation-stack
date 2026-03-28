use std::{backtrace::Backtrace, convert::Infallible, fmt::Display};

use crate::{certificates::CertificateError, dcap::parser::ParseError};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[derive(Debug)]
pub struct TdxError {
    inner: anyhow::Error,
}

// impl std::error::Error for TdxError {}

impl Display for TdxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl TdxError {
    pub(crate) fn msg<T>(message: &'static str) -> Result<T, Self> {
        Err(Self {
            inner: anyhow::Error::msg(message),
        })
    }

    fn from_anyhow(inner: anyhow::Error) -> Self {
        TdxError { inner }
    }
}

impl From<TdxError> for anyhow::Error {
    fn from(value: TdxError) -> Self {
        value.inner
    }
}

#[allow(clippy::missing_errors_doc)]
pub trait Context<T, E> {
    fn context<C>(self, context: C) -> Result<T, TdxError>
    where
        C: Display + Send + Sync + 'static;

    fn with_context<C, F>(self, f: F) -> Result<T, TdxError>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C;
}

impl<A> Context<A, TdxError> for Result<A, TdxError> {
    fn context<C>(self, context: C) -> Result<A, TdxError>
    where
        C: Display + Send + Sync + 'static,
    {
        self.map_err(|TdxError { inner }| TdxError {
            inner: inner.context(context),
        })
    }

    fn with_context<C, F>(self, f: F) -> Result<A, TdxError>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.map_err(|TdxError { inner }| TdxError {
            inner: inner.context(f()),
        })
    }
}

impl<A, B: Send + Sync + 'static + std::error::Error> Context<A, B> for Result<A, B> {
    fn context<C>(self, context: C) -> Result<A, TdxError>
    where
        C: Display + Send + Sync + 'static,
    {
        anyhow::Context::context(self, context).map_err(TdxError::from_anyhow)
    }

    fn with_context<C, F>(self, f: F) -> Result<A, TdxError>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        anyhow::Context::with_context(self, f).map_err(TdxError::from_anyhow)
    }
}

impl<A> Context<A, Infallible> for Option<A> {
    fn context<C>(self, context: C) -> Result<A, TdxError>
    where
        C: Display + Send + Sync + 'static,
    {
        anyhow::Context::context(self, context).map_err(TdxError::from_anyhow)
    }

    fn with_context<C, F>(self, f: F) -> Result<A, TdxError>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        anyhow::Context::with_context(self, f).map_err(TdxError::from_anyhow)
    }
}

impl<T: std::error::Error + Send + Sync + 'static> From<T> for TdxError {
    fn from(value: T) -> Self {
        Self {
            inner: value.into(),
        }
    }
}

#[cfg(target_family = "wasm")]
impl From<TdxError> for JsValue {
    fn from(value: TdxError) -> Self {
        JsError::new(&value.inner.to_string()).into()
    }
}
// #[derive(Error, Debug)]
// pub enum Error {
//     #[error("certificate error: {0}")]
//     Certificate(#[from] CertificateError),

//     #[error("error parsing the dcap quote: {0}")]
//     Parse(#[from] ParseError),

//     #[error("cryptographic error: {0}")]
//     Crypto(#[from] p256::ecdsa::Error),

//     #[error("this error")]
//     SignatureFormat(#[from] sec1::Error),

//     #[error("error returned from pcs: {0}")]
//     Reqwest(#[from] reqwest::Error),

//     #[error("failed parsing json data: {0}")]
//     Json(#[from] serde_json::Error),

//     #[error("pcs response did not include a certificate chain header")]
//     MissingCertChain,
// }
