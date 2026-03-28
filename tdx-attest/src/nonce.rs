use std::ops::Deref;

use libattest::ByteNonce;

pub struct TdxNonce(libattest::ByteNonce<64>);

impl Deref for TdxNonce {
    type Target = libattest::ByteNonce<64>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TdxNonce {
    pub fn generate() -> Self {
        Self(libattest::ByteNonce::generate())
    }

    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl From<ByteNonce<64>> for TdxNonce {
    fn from(value: ByteNonce<64>) -> Self {
        Self(value)
    }
}
