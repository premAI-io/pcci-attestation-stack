use nvidia_attest::{EATToken, keychain::KeyChain};

const EAT_EXAMPLE: &'static str = include_str!("./eat_example.json");

#[tokio::test]
async fn get_chain() {
    let _ = KeyChain::fetch_keychain().await.unwrap();
}

// #[tokio::test]
// async fn test_validation() {
//     let chain = KeyChain::fetch_keychain().await.unwrap();
//     let token = EATToken::parse(EAT_EXAMPLE).unwrap();

//     let decoded = token.verify(&chain).unwrap();

//     panic!("{decoded:?}");
// }
