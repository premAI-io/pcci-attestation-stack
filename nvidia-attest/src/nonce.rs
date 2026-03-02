use std::ops::Deref;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[derive(Debug, PartialEq, Eq)]
pub struct NvidiaNonce(libattest::ByteNonce<32>);

impl Deref for NvidiaNonce {
    type Target = libattest::ByteNonce<32>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// #[cfg_attr(target_family = "wasm", wasm_bindgen(js_namespace = "nvidia"))]
// #[derive(Debug, PartialEq, Eq)]
// pub struct NvidiaNonce(Box<[u8; 32]>);

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl NvidiaNonce {
    pub fn generate() -> Self {
        Self(libattest::ByteNonce::generate())
    }

    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}
//     #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
//     pub fn new() -> Self {
//         let mut bytes = Box::new([0u8; 32]);

//         getrandom::getrandom(bytes.as_mut_slice()).unwrap();

//         Self(bytes)
//     }

//     pub fn generate() -> Self {
//         Self::new()
//     }

//     pub fn to_hex(&self) -> String {
//         hex::encode_upper(self.0.as_ref())
//     }
// }

// impl Default for NvidiaNonce {
//     fn default() -> Self {
//         Self::new()
//     }
// }

// impl Deref for NvidiaNonce {
//     type Target = [u8; 32];

//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }

// impl From<Box<[u8; 32]>> for NvidiaNonce {
//     fn from(value: Box<[u8; 32]>) -> Self {
//         Self(value)
//     }
// }
