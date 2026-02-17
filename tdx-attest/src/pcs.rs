use reqwest::{Client, IntoUrl, Url};

use crate::{Quote, certificates::IntermediateCa, error::Error};

const INTEL_PCS: &str = "https://api.trustedservices.intel.com/";

struct Pcs {
    base_url: Url,
    client: Client,
}

impl Default for Pcs {
    fn default() -> Self {
        Self {
            base_url: INTEL_PCS.parse().unwrap(),
            client: Client::default(),
        }
    }
}

impl Pcs {
    pub fn new(base_url: impl IntoUrl) -> Result<Self, reqwest::Error> {
        let base_url = base_url.into_url()?;
        let client = Client::default();

        Ok(Pcs { base_url, client })
    }

    pub async fn fetch_crl(&self, intermediate_ca: IntermediateCa) {
        let mut url = self.base_url.join("/sgx/certification/v4/pckcrl").unwrap();
        url.query_pairs_mut()
            .append_pair("ca", intermediate_ca.as_str());

        let text = self.client.get(url).send().await.unwrap().text().await;
        panic!("{text:?}");
    }
}

// pub struct Collateral {}

// pub fn fetch_collateral(quote: &Quote) -> Result<Collateral, Error> {
//     todo!()
// }

// #[cfg(test)]
// mod test {
//     use crate::pcs::Pcs;

//     #[tokio::test]
//     async fn fetch_crl() {
//         let pcs = Pcs::default();
//         pcs.fetch_crl(crate::certificates::IntermediateCa::Platform)
//             .await;
//     }
// }
