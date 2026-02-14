use tdx_attest::Quote;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = std::fs::read("./examples/tdx_quote").unwrap();
    let quote = Quote::from_bytes(&input)?;

    // let quote = TdQuote::parse(&input[..]).unwrap();
    // let quote_data = quote.certification.quote_data;
    // let QeCertificationData::QeReportCertificationData(data) = quote_data else {
    //     panic!()
    // };

    // let QeCertificationData::PckChain(chain) = data.certification_data else {
    //     panic!()
    // };

    // let chain = CertificateChain::parse_pem_chain(chain).unwrap();
    // // let chain = String::from_utf8_lossy(chain);

    println!("{quote:?}");
    Ok(())
}
