use crate::{
    ca::INTEL_CA,
    error::{Context, TdxError},
};
use p256::ecdsa::Signature;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use signature::Verifier;

use crate::certificates::CertificateChain;

/// Every signed response from the PCS has these 3 things.
pub struct SignedResponse {
    chain: CertificateChain,
    signature: Signature,
    data: serde_json::Value,
}

impl SignedResponse {
    pub fn verify_signature<T: DeserializeOwned>(&self) -> Result<T, TdxError> {
        // message is re-compacted json
        let msg = serde_json::to_vec(&self.data)
            .context("failed re-serializing data into compact json")?;

        let _ = dbg!(String::from_utf8_lossy(&msg));

        // verify signature and message using certificate chain
        self.chain
            .verify(&msg, &self.signature)
            .context("signed response has a bad signature")?;

        let data = T::deserialize(&self.data).context("response data is in the wrong format")?;
        Ok(data)
    }
}

/// Helper method for [`reqwest::Response`] to parse a signed response off of pcs
pub(super) trait ParseSignedResponse {
    async fn parse_signed_response(
        self,
        chain_header: &str,
        data_field: &str,
    ) -> Result<SignedResponse, TdxError>;
}

impl ParseSignedResponse for reqwest::Response {
    async fn parse_signed_response(
        self,
        chain_header: &str,
        data_field: &str,
    ) -> Result<SignedResponse, TdxError> {
        let chain = self
            .headers()
            .get(chain_header)
            .context("response does not contain certificate chain header")?
            .as_bytes();
        let chain = urlencoding::decode_binary(chain);

        // anchor our trust in embedded intel_ca, still parsing pem chain from
        // response
        let chain = CertificateChain::with_anchor(&INTEL_CA)
            .parse_pem_chain(&chain)
            .context("failed parsing certificate chain from header")?;

        let PcsResponse { signature, data }: PcsResponse = self.json().await?;
        let signature = Signature::from_slice(&signature).context("failed decoding signature")?;

        // Since data was a flatten map over the remaining fields (except signature)
        // we now have to extract the contents of the actual data field we specified
        let Value::Object(mut map) = data else {
            return TdxError::msg("invalid data object in response does not contain a map");
        };

        let data = map
            .remove(data_field)
            .context("invalid data object does not contain specified data field")?;

        Ok(SignedResponse {
            chain,
            signature,
            data,
        })
    }
}

#[derive(Deserialize)]
struct PcsResponse {
    #[serde(flatten)]
    data: serde_json::Value,
    #[serde(deserialize_with = "hex::serde::deserialize")]
    signature: [u8; 64],
}
