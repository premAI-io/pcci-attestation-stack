const AZURE_IMDS_SCHEME: &str = "http";
const AZURE_IMDS_HOST: &str = "169.254.169.254/metadata";
const AZURE_THIM_CERT_PATH: &str = "/THIM/amd/certification";

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct THIM {
    tcbm: std::string::String,
    #[serde(rename = "cacheControl")]
    cache_control: std::string::String,
    #[serde(rename = "vcekCert")]
    vcek_cert: std::string::String,
    #[serde(rename = "certificateChain")]
    certificate_chain: std::string::String,
}

impl THIM {
    pub fn to_cert_bundle(&self) -> (&[u8], &[u8]) {
        let vek: &[u8] = self.vcek_cert.as_bytes();
        let ca: &[u8] = self.certificate_chain.as_bytes();
        (vek, ca)
    }
}

pub fn get() -> anyhow::Result<THIM> {
    let client = reqwest::blocking::Client::new();
    let req = client
        .get(format!(
            "{}://{}{}",
            AZURE_IMDS_SCHEME, AZURE_IMDS_HOST, AZURE_THIM_CERT_PATH,
        ))
        .header("Metadata", "true");
    Ok(req.send()?.json()?)
}
