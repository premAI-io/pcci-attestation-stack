fn main() {
    let path = std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    let cert = openssl::x509::X509::from_pem(path.as_bytes()).unwrap();

    let exts_map = verifier::oid::get_exts(&cert).unwrap();

    let key_usage = verifier::oid::get_key_usage(&exts_map).unwrap();

    if verifier::oid::tcg::is_aik_certificate(key_usage) == false {
        panic!("invalid key usage");
    }

    let akcert_ok = verifier::hyperv::vtpm_utils::verify_ak_cert(&cert).unwrap();
    println!("ak cert trusted: {}", akcert_ok);

    /*
    println!(
        "{}",
        std::string::String::from_utf8(cert.to_pem().unwrap()).unwrap()
    )
    */
}
