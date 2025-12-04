// TODO: PCR values can change between Quote generation and PCR retrieval
//       compare them and recalculate if differ.
fn main() {
    let mut ctx = verifier::hyperv::vtpm::get_session_context().unwrap();

    let mut nonce: [u8; 32] = [0u8; 32];
    openssl::rand::rand_bytes(&mut nonce).unwrap();

    let test = verifier::hyperv::vtpm_utils::get_pcr_quote(Some(&mut ctx), nonce).unwrap();

    let all_pcrs = verifier::hyperv::vtpm_utils::get_pcrs(Some(&mut ctx)).unwrap();

    let hash = verifier::hyperv::vtpm_utils::get_pcr_digest(&all_pcrs).unwrap();

    if !hash.eq(&test.digest) {
        panic!("invalid digest");
    }

    println!(
        "\
        computed hash: {}\n\
        reported hash: {}",
        hex::encode(hash),
        hex::encode(test.digest)
    );

    let ak_cert = verifier::hyperv::vtpm_utils::get_ak_cert(Some(&mut ctx)).unwrap();
    let pkey = ak_cert.public_key().unwrap();

    if !test.verify(&pkey).unwrap() {
        panic!("can't attest TPM Quote")
    }

    if test.get_nonce() != nonce {
        panic!("invalid nonce");
    }
}
