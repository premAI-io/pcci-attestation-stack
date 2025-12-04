use anyhow::anyhow;
// use verifier::hyperv;
use verifier::nonce;

fn main() {
    #[cfg(feature = "hyperv")]
    let hv = hyperv::present();

    #[cfg(not(feature = "hyperv"))]
    let hv = false;

    let mut args = std::env::args();
    let snp_report_path = args.nth(1).unwrap_or("snp_report.bin".to_string());
    let snp_vek_path = args.next().unwrap_or("vcek.pem".to_string());
    let snp_ca_path = args.next().unwrap_or("ca.pem".to_string());
    let nonce_arg: std::option::Option<std::string::String> = args.next();

    let nonce = match nonce_arg {
        Some(n) => nonce::SevNonce::try_from(n).unwrap(),
        None => nonce::SevNonce::new(),
    };

    println!("nonce: {:?}", nonce.to_hex());

    if hv == true {
        // println!("running on Hyper-V with vTPM");

        // // fetch fresh (vcek, ca) from THIM
        // let thim_resp = hyperv::thim::get().unwrap();
        // let (vcek_bytes, ca_bytes) = thim_resp.to_cert_bundle();

        // std::fs::write(&snp_vek_path, vcek_bytes).unwrap();
        // std::fs::write(&snp_ca_path, ca_bytes).unwrap();

        // /*
        //  * write random 64 bytes nonce that will be reflected in runtime claims RSV2
        //  */
        // hyperv::report::write_user_data(nonce.get_bytes()).unwrap();

        // // write full HCL report to file
        // let snpguest_bytes: Vec<u8> = {
        //     let mut test_bytes: std::option::Option<Vec<u8>> = None;

        //     for i in 1..=3 {
        //         let (_, snpguest_bytes) = hyperv::report::get(0).unwrap();
        //         let claims = hyperv::report::validate_hcl_claims(&snpguest_bytes, &nonce);

        //         let is_race = claims.as_ref().is_err_and(|e| {
        //             e.downcast_ref::<verifier::hyperv::report::ExtendedHclError>()
        //                 .map_or(false, |hcl_err| {
        //                     matches!(
        //                         hcl_err,
        //                         verifier::hyperv::report::ExtendedHclError::InvalidNonce(_)
        //                     )
        //                 })
        //         });

        //         if !is_race {
        //             if claims.is_err() {
        //                 panic!("{:?}", claims.err())
        //             }

        //             let _ = test_bytes.insert(snpguest_bytes);
        //             break;
        //         }

        //         std::thread::sleep(std::time::Duration::from_millis(500 * i));
        //         println!("can't find a report with matching nonce, retry: {}", i);
        //     }

        //     match test_bytes {
        //         Some(b) => Ok(b),
        //         None => Err(anyhow!("can't find a report with matching nonce")),
        //     }
        // }
        // .unwrap();

        // println!("successfully read attestation report from HCL");

        // // println!("{}", report.report);
        // // write attn report to file
        // // let mut report_bytes = vec!();
        // // report.report.write_bytes(&mut report_bytes).unwrap();

        // std::fs::write(&snp_report_path, &snpguest_bytes).unwrap();
    } else {
        // fix: back-off retry function to ensure nonce is set correctly
        let mut firmware =
            sev::firmware::guest::Firmware::open().expect("virt sev-snp topology not implemented");
        println!("running on native SEV-SNP");

        // https://github.com/confidential-containers/trustee/issues/456#issuecomment-2326614979
        let (snp_ext_report, certificates) = firmware
            .get_ext_report(None, Some(*nonce.get_bytes()), None)
            .expect("unable to get Attestation Report");

        if let Some(_) = certificates {
            let chain = sev::certs::snp::Chain::from_cert_table_der(certificates.unwrap()).unwrap();

            std::fs::write(&snp_vek_path, chain.vek.to_pem().unwrap()).unwrap();

            let mut ca_bytes = vec![];
            ca_bytes.extend(chain.ca.ask.to_pem().unwrap());
            ca_bytes.extend(chain.ca.ark.to_pem().unwrap());
            std::fs::write(&snp_ca_path, &ca_bytes).unwrap();
        }

        std::fs::write(&snp_report_path, &snp_ext_report).unwrap();
    }
}
