use std::{convert::Infallible, fmt::Display};

use wasm_bindgen::JsValue;

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    #[default]
    Internal,
    Exposed,
}

// #[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct AttestationError {
    kind: ErrorKind,
    error: anyhow::Error,
}

impl From<AttestationError> for JsValue {
    fn from(value: AttestationError) -> Self {
        let cause: String = value
            .error
            .chain()
            .enumerate()
            .map(|(n, cause)| format!("{n}: {cause}::\n"))
            .collect();

        let error_message = match value.kind {
            ErrorKind::Internal => "Unhandled error",
            ErrorKind::Exposed => &format!("{}", value.error),
        };

        let error = js_sys::Error::new(error_message);
        error.set_name("AttestationError");
        error.set_cause(&cause.into());
        error.into()
    }
}

impl Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl AttestationError {
    pub fn internal<T>(message: &'static str) -> Result<T, Self> {
        Err(Self {
            kind: ErrorKind::Internal,
            error: anyhow::Error::msg(message),
        })
    }

    pub fn exposed<T>(message: &'static str) -> Result<T, Self> {
        Err(Self {
            kind: ErrorKind::Exposed,
            error: anyhow::Error::msg(message),
        })
    }

    fn from_anyhow(error: anyhow::Error) -> Self {
        AttestationError {
            error,
            kind: ErrorKind::Internal,
        }
    }
}

impl From<AttestationError> for anyhow::Error {
    fn from(value: AttestationError) -> Self {
        value.error
    }
}

#[allow(clippy::missing_errors_doc)]
pub trait Context<T, E> {
    fn context<C>(self, context: C) -> Result<T, AttestationError>
    where
        C: Display + Send + Sync + 'static;

    fn with_context<C, F>(self, f: F) -> Result<T, AttestationError>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C;
}

impl<A> Context<A, AttestationError> for Result<A, AttestationError> {
    fn context<C>(self, context: C) -> Result<A, AttestationError>
    where
        C: Display + Send + Sync + 'static,
    {
        self.map_err(|AttestationError { kind, error }| AttestationError {
            kind,
            error: error.context(context),
        })
    }

    fn with_context<C, F>(self, f: F) -> Result<A, AttestationError>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.map_err(|AttestationError { kind, error }| AttestationError {
            kind,
            error: error.context(f()),
        })
    }
}

impl<A, B: Send + Sync + 'static + std::error::Error> Context<A, B> for Result<A, B> {
    fn context<C>(self, context: C) -> Result<A, AttestationError>
    where
        C: Display + Send + Sync + 'static,
    {
        anyhow::Context::context(self, context).map_err(AttestationError::from_anyhow)
    }

    fn with_context<C, F>(self, f: F) -> Result<A, AttestationError>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        anyhow::Context::with_context(self, f).map_err(AttestationError::from_anyhow)
    }
}

impl<A> Context<A, Infallible> for Option<A> {
    fn context<C>(self, context: C) -> Result<A, AttestationError>
    where
        C: Display + Send + Sync + 'static,
    {
        anyhow::Context::context(self, context).map_err(AttestationError::from_anyhow)
    }

    fn with_context<C, F>(self, f: F) -> Result<A, AttestationError>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        anyhow::Context::with_context(self, f).map_err(AttestationError::from_anyhow)
    }
}

impl<T: std::error::Error + Send + Sync + 'static> From<T> for AttestationError {
    fn from(value: T) -> Self {
        Self {
            kind: ErrorKind::Internal,
            error: value.into(),
        }
    }
}
