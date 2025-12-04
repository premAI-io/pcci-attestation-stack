pub struct SevNonce {
    bytes: [u8; 64],
}

impl SevNonce {
    pub fn new() -> Self {
        let mut bytes = [0u8; 64];

        getrandom::getrandom(&mut bytes).unwrap();

        SevNonce { bytes }
    }

    pub fn to_hex(&self) -> String {
        hex::encode_upper(&self.bytes)
    }

    pub fn get_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }
}

impl TryFrom<std::string::String> for SevNonce {
    type Error = anyhow::Error;

    fn try_from(value: std::string::String) -> anyhow::Result<Self, Self::Error> {
        let mut b_arr: [u8; 64] = [0u8; 64];

        hex::decode(&value)
            .expect("invalid hex")
            .into_iter()
            .take(64)
            .enumerate()
            .for_each(|(i, val)| b_arr[i] = val);

        Ok(SevNonce { bytes: b_arr })
    }
}

impl From<[u8; 64]> for SevNonce {
    fn from(value: [u8; 64]) -> Self {
        SevNonce { bytes: value }
    }
}
