use clap::Parser;
use core::panic;
use sev::certs::snp::{Verifiable, ca};
use sev::parser::ByteParser;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::{fs::File, io::Read};
use x509_cert::certificate::CertificateInner;
use x509_parser::prelude::{CertificateRevocationList, FromDer, X509Certificate};

#[cfg(feature = "hyperv")]
use verifier::hyperv;

use verifier::kds;
use verifier::nonce::{self, SevNonce};
use verifier::oid;

#[derive(Parser)]
struct Cli {
    snp_report_path: PathBuf,
    snp_vek_path: PathBuf,
    snp_ca_path: PathBuf,
    nonce: String,
}

fn main() {
    #[cfg(feature = "hyperv")]
    let hv = hyperv::present();

    #[cfg(not(feature = "hyperv"))]
    let hv = false;

    let mut args = std::env::args();

    let args = Cli::parse();
    let Cli {
        snp_report_path,
        snp_vek_path,
        snp_ca_path,
        nonce,
    } = args;

    // let snp_report_path = args.nth(1).unwrap_or("snp_report.bin".to_string());
    // let snp_vek_path = args.next().unwrap_or("vcek.pem".to_string());
    // let snp_ca_path = args.next().unwrap_or("ca.pem".to_string()); // ARK + ASK, Certificate Chain
    // let nonce_arg: std::option::Option<std::string::String> = args.next();

    // let nonce = nonce::SevNonce::try_from(nonce_arg.expect("missing nonce argument"))
    //     .expect("invalid nonce");
    let nonce = SevNonce::try_from(nonce).expect("invalid nonce");

    println!("nonce: {:?}", nonce.to_hex());

    let mut f = File::open(&snp_report_path).expect("snp report is required");

    let mut buf: Vec<u8> = Vec::new();
    f.read_to_end(&mut buf).expect("can't read snp report");

    // TODO: not bound by running computing architecture
    // doc: nonce is validated differently in Hyper-V based SEV-SNP Guests
    let report = if hv == true {
        unimplemented!()
        // validate_hcl_claims(&buf, &nonce).unwrap()
    } else {
        let report = sev::firmware::guest::AttestationReport::from_bytes(&buf).unwrap();
        if &report.report_data != nonce.get_bytes() {
            panic!("invalid nonce");
        }

        report
    };

    // println!("claims json: {:?}", hcl.rsv2.claims_json().unwrap());

    let generation =
        sev::Generation::identify_cpu(report.cpuid_fam_id.unwrap(), report.cpuid_mod_id.unwrap())
            .unwrap();
    println!("generation: {}", generation.titlecase());

    let chain = get_chain_by_path(snp_vek_path, snp_ca_path).ok();
    if let Some(ref _chain) = chain {
        println!("{:?}", _chain);
    }

    //let chain_verify = chain.verify().unwrap();
    //println!("{:?}", chain_verify);

    /* verify cert chain ( AMD Root Key -> AMD SEV Key -> vCEK (CPU-bound) ) */
    //verify_cert_chain(&chain).unwrap();

    /* get report bytes */
    //let mut report_bytes: Vec<u8> = Vec::new();
    //hcl.report.write_bytes(&mut report_bytes).unwrap();

    /* automated report verify */
    if let Some(ref _chain) = chain {
        (_chain, &report).verify().unwrap();
    }

    /* manual report verify */
    // signature bytes starts at 0x2A0
    // let report_no_sig: Vec<u8> = report_bytes[0..0x2A0].into();

    /*
    let sig: openssl::ecdsa::EcdsaSig = openssl::ecdsa::EcdsaSig::try_from(&hcl.report.signature).unwrap();
    let vek_pk = chain.vek.public_key().context("failed to get public key from VEK.").unwrap().ec_key().context("failed to convert vek public key into ECKey").unwrap();

    let mut hasher: openssl::sha::Sha384 = openssl::sha::Sha384::new();
    hasher.update(&report_no_sig);
    let digest = hasher.finish();

    let is_verified = sig.verify(digest.as_ref(), vek_pk.as_ref());
    println!("{:?}", is_verified);
    */

    let kds_chain = kds::get_chain(
        &report.chip_id,
        report.reported_tcb,
        &generation.titlecase(),
    )
    .unwrap();

    let runtime_chain = (|| {
        if let Some(ref _chain) = chain {
            return _chain;
        }
        &kds_chain
    })();

    /* verify TCB */

    // see attested TCB
    println!("{:?}", report.reported_tcb);

    let runtime_vek = runtime_chain.vek.to_der().unwrap();
    let (_, runtime_vek) = X509Certificate::from_der(&runtime_vek).unwrap();
    let exts_map = oid::get_exts(&runtime_vek).unwrap();

    oid::check_spl(report.reported_tcb, &exts_map).unwrap();

    /*
        compare hwid
    */
    if let Some(hwid) = exts_map.get(&oid::HWID) {
        if !oid::compare_bytes(hwid, &report.chip_id.to_vec()) {
            panic!("different chip_id");
        }
    }

    /* AMD KDS interactions */
    // TODO: implement KDS caching proxy for at-scale usage

    let product_name_ext = exts_map.get(&oid::PRODUCT_NAME).unwrap();
    let (product_name, stepping) =
        kds::decode_product_name(product_name_ext.value.to_vec()).unwrap();

    println!(
        "\
    vcek data:\n \
    product name: {}\n \
    stepping: {:?}",
        product_name,
        if let Some(step) = stepping {
            kds::decode_stepping(step)
        } else {
            None
        }
    );

    if product_name != generation.titlecase() {
        panic!("invalid product name");
    }

    /* verify full chain */
    (&kds_chain, &report).verify().unwrap();

    let vek_cert = kds_chain.vek.to_der().unwrap();
    let (_, vek_cert_parsed) = X509Certificate::from_der(&vek_cert).unwrap();
    let kds_exts_map = oid::get_exts(&vek_cert_parsed).unwrap();
    oid::check_spl(report.reported_tcb, &kds_exts_map).unwrap();

    let kds_crl = kds::get_crl(&generation.titlecase()).unwrap();
    let (_, kds_crl) = CertificateRevocationList::from_der(&kds_crl)
        .expect("crl downloaded from kds is not parsable");

    // crl signed by AMD Root Key
    let ark_cert = kds_chain.ca.ark.to_der().unwrap();
    let (_, ark_cert_parsed) = X509Certificate::from_der(&ark_cert).unwrap();
    if kds::crl::verify(&ark_cert_parsed, &kds_crl).unwrap() == false {
        panic!("crl not signed by ARK")
    }

    let ask_cert = kds_chain.ca.ask.to_der().unwrap();
    let (_, ask_cert_parsed) = X509Certificate::from_der(&ask_cert).unwrap();
    // https://github.com/google/go-sev-guest/blob/b60b35cc8d0330af09023824d110e28b81e61f60/verify/verify.go#L339
    if kds::crl::is_revoked(&ask_cert_parsed, &kds_crl) {
        panic!("ASK revoked")
    }

    if let Some(_chain) = chain {
        is_chain_valid(&_chain).unwrap();
    }
    is_chain_valid(&kds_chain).unwrap();

    println!("all good")

    /*
    todo:
    [*] check certs valid from\to
    (not sure) * get processor model\family, create enum for it (https://github.com/virtee/snpguest/blob/main/src/fetch.rs#L111)
    (tbd) * differenziare famiglia processori per delle robe esclusive delle nuove generazioni

    [*] TPM runtime claims attestation
    [*] TPM random data check (ie user manda 64 byte random e report gli torna quei bytes signed per verificare che è live)
      [*] tpm handle invalid index
       [*] tpm handle race condition between write and HCL claims read (?)

    [*] verify TPM Quote in order to attest the platform state (PCRs)
    */
}

use anyhow::{Context, bail};

fn get_chain_by_path(
    snp_vek_path: impl AsRef<Path>,
    snp_ca_path: impl AsRef<Path>,
) -> anyhow::Result<sev::certs::snp::Chain> {
    let vek_bytes = std::fs::read(snp_vek_path).context("cannot read vek")?;
    let ca_bytes = std::fs::read(snp_ca_path).context("cannot read ca")?;

    let chain = CertificateInner::load_pem_chain(&ca_bytes)
        .context("failed loading pem certificate chain")?;

    let [ask, ark]: [CertificateInner; 2] = chain
        .try_into()
        .map_err(|_| anyhow::format_err!("missing ask or ark from certificate chain"))?;

    let chain = sev::certs::snp::Chain {
        vek: sev::certs::snp::Certificate::from_pem(&vek_bytes).unwrap(),
        ca: ca::Chain {
            ask: ask.into(),
            ark: ark.into(),
        },
    };

    Ok(chain)
}

/**
   verify cert chain ( AMD Root Key -> AMD SEV Key -> vCEK (CPU-bound) )
*/
#[allow(dead_code)]
fn verify_cert_chain(chain: &sev::certs::snp::Chain) -> anyhow::Result<()> {
    (&chain.ca.ark, &chain.ca.ark)
        .verify()
        .context("ark verify failed")?;
    (&chain.ca.ark, &chain.ca.ask)
        .verify()
        .context("ask verify failed")?;
    (&chain.ca.ask, &chain.vek)
        .verify()
        .context("vcek verify failed")?;

    Ok(())
}

fn is_cert_valid(cert: &sev::certs::snp::Certificate) -> anyhow::Result<()> {
    // let cert_x509: openssl::x509::X509 = cert.into();
    // let time_now = openssl::asn1::Asn1Time::from_unix(
    //     std::time::SystemTime::now()
    //         .duration_since(std::time::SystemTime::UNIX_EPOCH)
    //         .unwrap()
    //         .as_secs() as i64,
    // )?;

    // match time_now.compare(cert_x509.not_before())? {
    //     std::cmp::Ordering::Less | std::cmp::Ordering::Equal => return Err(anyhow!("err")),
    //     _ => {}
    // }

    // match cert_x509.not_after().compare(&time_now)? {
    //     std::cmp::Ordering::Less | std::cmp::Ordering::Equal => return Err(anyhow!("err")),
    //     _ => {}
    // }
    let now = SystemTime::now();

    let cert = cert.cert();
    let validity = cert.tbs_certificate.validity;

    match (
        validity.not_after.to_system_time() > now,
        validity.not_before.to_system_time() < now,
    ) {
        (false, _) => bail!("certificate expired"),
        (_, false) => bail!("certificate is not yet valid"),
        (true, true) => Ok(()),
    }
}

/**
   verify cert chain expiry
*/
fn is_chain_valid(chain: &sev::certs::snp::Chain) -> anyhow::Result<()> {
    is_cert_valid(&chain.ca.ark)?;
    is_cert_valid(&chain.ca.ask)?;
    is_cert_valid(&chain.vek)?;

    Ok(())
}

#[cfg(feature = "hyperv")]
fn validate_hcl_claims(
    buf: &Vec<u8>,
    nonce: &nonce::SevNonce,
) -> anyhow::Result<sev::firmware::guest::AttestationReport> {
    let hcl = hyperv::report::new_hcl(&buf).expect("hcl error");
    // println!("{:#?}", hcl);

    println!("{:?}", hcl.rsv1);
    println!("{:?}", hcl.report);
    println!("{:?}", hcl.rsv2);

    /*
     * improve this
     *
     * rsv2 claims validation
     */
    let validate_claims = hyperv::report::verify_report_data(
        hyperv::types::Hash::try_from(hcl.rsv2.hash_type).unwrap(),
        &hcl.report.report_data.to_vec(),
        hcl.rsv2.claims_bytes(),
    )
    .unwrap();
    if validate_claims == false {
        return Err(anyhow!("rsv2 runtime claims validation failed"));
    }

    println!("claims validation: {}", validate_claims);

    // verify rsv2 user-data nonce
    let claims_json = hcl.rsv2.claims_json().unwrap();
    let claims_nonce = verifier::json::extract_as_string(&claims_json, "user-data").unwrap();

    println!("claims nonce: {}", claims_nonce);
    if nonce.to_hex() != claims_nonce {
        return Err(verifier::hyperv::report::ExtendedHclError::InvalidNonce(claims_nonce).into());
    }

    Ok(hcl.report)
}
