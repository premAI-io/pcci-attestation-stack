use nvidia_attest::{EATToken, keychain::KeyChain};

#[tokio::test]
async fn get_chain() {
    let _ = KeyChain::fetch_keychain().await.unwrap();
}

// #[tokio::test]
// async fn test_validation() {
//     let report = tokio::fs::read_to_string("./eat_example.json")
//         .await
//         .unwrap();

//     let token = EATToken::parse(&report).unwrap();
//     let chain = KeyChain::fetch_keychain().await.unwrap();
//     let decoded = token.verify(&chain).unwrap();
//     decoded.validate(&nonce);

//     // let nonce = "0000000000000000000000000000000000000000000000000000000000000000"; // this is the nonce requested when asking the server for attestation

//     // decoded.validate(nonce).unwrap();

//     // panic!("{decoded:?}");
// }
