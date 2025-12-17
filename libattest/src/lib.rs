pub mod verification;
pub use verification::*;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

// #[cfg_attr(target_family = "wasm", wasm_bindgen(js_namespace = "sev"))]
// pub struct ByteNonce<const N: usize>(Box<[u8; N]>);

// // #[cfg_attr(target_family = "wasm", wasm_bindgen)]
// impl<const N: usize> ByteNonce<N> {
//     // #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
//     pub fn new() -> Self {
//         let mut bytes = Box::new([0u8; N]);

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

// impl<const N: usize> std::ops::Deref for ByteNonce<N> {
//     type Target = [u8; N];

//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }

// impl<const N: usize> From<Box<[u8; N]>> for ByteNonce<N> {
//     fn from(value: Box<[u8; N]>) -> Self {
//         Self(value)
//     }
// }
