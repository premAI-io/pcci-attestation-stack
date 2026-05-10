use std::{collections::HashMap, ops::Deref};

use serde::Serialize;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::Client;

/// Generic per-request query parameters.
///
/// The `nonce` key is reserved and will be rejected.
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[derive(Clone, Serialize)]
#[serde(transparent)]
pub struct QueryParams(HashMap<String, String>);

impl Deref for QueryParams {
    type Target = HashMap<String, String>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl QueryParams {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        Self(Default::default())
    }

    /// Appends a query parameter.
    ///
    /// Reserved keywords for specific queries will get overwritten
    pub fn with(mut self, key: &str, value: &str) -> Self {
        self.0.insert(key.to_string(), value.to_string());
        self
    }
}

impl Default for QueryParams {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl Client {
    pub fn set_query(&mut self, query_params: QueryParams) {
        self.query_params = query_params;
    }
}
