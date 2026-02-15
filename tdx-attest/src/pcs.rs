use reqwest::{Client, IntoUrl, Url};

use crate::{Quote, certificates::IntermediateCa, error::Error};

struct Pcs {
    base_url: Url,
    client: Client,
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

        self.client.get(url).send().await;
    }
}

// pub struct Collateral {}

// pub fn fetch_collateral(quote: &Quote) -> Result<Collateral, Error> {
//     todo!()
// }
