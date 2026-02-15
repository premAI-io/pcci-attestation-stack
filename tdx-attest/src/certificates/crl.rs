use reqwest::tls::CertificateRevocationList;

use crate::certificates::CertificateChain;

pub struct Crl {
    inner_crl: CertificateRevocationList,
    issuer_chain: CertificateChain,
}
