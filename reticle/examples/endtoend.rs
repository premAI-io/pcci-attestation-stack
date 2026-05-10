use reticle::{ClientBuilder, query::QueryParams};

#[tokio::main]
async fn main() {
    let api_url = std::env::args()
        .nth(1)
        .expect("must supply api url as first argument");

    let mut client = ClientBuilder::new(&api_url).build().await.unwrap();

    let query = QueryParams::new()
        .with("model", "qwen35-27b")
        .with("nonce", "1");
    client.set_query(query);

    let result = client.attest().await.unwrap();
    println!("{result:?}");
}
