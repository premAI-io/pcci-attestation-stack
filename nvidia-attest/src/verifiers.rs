use libattest::VerificationRule;

use crate::{error::GpuAttestationError, types::GpuClaims};

pub struct NonceVerifier<'a> {
    expected_nonce: &'a str,
}

impl<'a> NonceVerifier<'a> {
    pub fn new(expected_nonce: &'a str) -> Self {
        Self { expected_nonce }
    }
}

impl VerificationRule<GpuClaims> for NonceVerifier<'_> {
    type Error = GpuAttestationError;
    fn verify(&self, claims: &GpuClaims) -> Result<(), Self::Error> {
        let matching = claims
            .eat_nonce
            .as_ref()
            .map(|nonce| nonce == self.expected_nonce);

        match matching {
            None => Err(GpuAttestationError::Parse("missing eat_nonce from claims")),
            Some(false) => Err(GpuAttestationError::Nonce),
            Some(true) => Ok(()),
        }
    }
}
