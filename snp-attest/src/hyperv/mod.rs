// SPDX-License-Identifier: Apache-2.0
// This file contains code related to Hyper-V integration (Hypervisor). It provides a flag (`hyperv::present`) indicating whether the SNP Guest is running within a Hyper-V guest environment.

use std::arch::x86_64::__cpuid;
use std::mem::size_of;

const CPUID_GET_HIGHEST_FUNCTION: u32 = 0x80000000;
const CPUID_PROCESSOR_INFO_AND_FEATURE_BITS: u32 = 0x1;

// https://github.com/torvalds/linux/blob/f83ec76bf285bea5727f478a68b894f5543ca76e/include/hyperv/hvgdk_mini.h#L264
const CPUID_FEATURE_HYPERVISOR: u32 = 1 << 31;

// https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
const CPUID_HYPERV_SIG: &str = "Microsoft Hv";
const CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x40000000;
const CPUID_HYPERV_FEATURES: u32 = 0x40000003;
const CPUID_HYPERV_MIN: u32 = 0x40000005;
const CPUID_HYPERV_MAX: u32 = 0x4000ffff;
const CPUID_HYPERV_ISOLATION: u32 = 1 << 22;
const CPUID_HYPERV_CPU_MANAGEMENT: u32 = 1 << 12;

// https://github.com/torvalds/linux/blob/f83ec76bf285bea5727f478a68b894f5543ca76e/include/hyperv/hvhdk.h#L320
const CPUID_HYPERV_ISOLATION_CONFIG: u32 = 0x4000000C;
const CPUID_HYPERV_ISOLATION_TYPE_MASK: u32 = 0xf;
const CPUID_HYPERV_ISOLATION_TYPE_SNP: u32 = 2;

pub const RSV1_SIZE: usize = size_of::<u32>() * 8;
pub const REPORT_SIZE: usize = 1184;
pub const RSV2_SIZE: usize = size_of::<u32>() * 5;
const TOTAL_SIZE: usize = RSV1_SIZE + REPORT_SIZE + RSV2_SIZE;

const RSV1_RANGE: std::ops::Range<usize> = 0..RSV1_SIZE;
const REPORT_RANGE: std::ops::Range<usize> = RSV1_RANGE.end..(RSV1_RANGE.end + REPORT_SIZE);
const RSV2_RANGE: std::ops::Range<usize> = REPORT_RANGE.end..(REPORT_RANGE.end + RSV2_SIZE);

pub fn present() -> bool {
    let mut cpuid = unsafe { __cpuid(CPUID_PROCESSOR_INFO_AND_FEATURE_BITS) };
    if (cpuid.ecx & CPUID_FEATURE_HYPERVISOR) == 0 {
        return false;
    }

    cpuid = unsafe { __cpuid(CPUID_GET_HIGHEST_FUNCTION) };
    if cpuid.eax < CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS {
        return false;
    }

    cpuid = unsafe { __cpuid(CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS) };
    if cpuid.eax < CPUID_HYPERV_MIN || cpuid.eax > CPUID_HYPERV_MAX {
        return false;
    }

    let mut sig: Vec<u8> = vec![];
    sig.append(&mut cpuid.ebx.to_le_bytes().to_vec());
    sig.append(&mut cpuid.ecx.to_le_bytes().to_vec());
    sig.append(&mut cpuid.edx.to_le_bytes().to_vec());

    if sig != CPUID_HYPERV_SIG.as_bytes() {
        return false;
    }

    cpuid = unsafe { __cpuid(CPUID_HYPERV_FEATURES) };

    let isolated: bool = (cpuid.ebx & CPUID_HYPERV_ISOLATION) != 0;
    let managed: bool = (cpuid.ebx & CPUID_HYPERV_CPU_MANAGEMENT) != 0;

    if !isolated || managed {
        return false;
    }

    cpuid = unsafe { __cpuid(CPUID_HYPERV_ISOLATION_CONFIG) };
    let mask = cpuid.ebx & CPUID_HYPERV_ISOLATION_TYPE_MASK;
    let snp = CPUID_HYPERV_ISOLATION_TYPE_SNP;

    if mask != snp {
        return false;
    }

    true
}

pub mod thim;
pub mod vtpm;

pub mod vtpm_utils {
    use anyhow::{Context, anyhow};
    use openssl::bn::BigNum;
    use tss_esapi::{
        structures::PcrSlot,
        traits::{Marshall, UnMarshall},
    };

    use crate::hyperv::vtpm;

    /**
     * https://learn.microsoft.com/en-us/azure/confidential-computing/how-to-leverage-virtual-tpms-in-azure-confidential-vms
     * `We recommend you use PCR23 to extend measurements of user mode components or runtime data.`
     * [0-7], Pre-Boot
     * [8-22], OS
     * [23], Available for guest measurement
     */
    pub const VTPM_DEFAULT_PCR_SLOTS: [PcrSlot; 24] = [
        PcrSlot::Slot0,
        PcrSlot::Slot1,
        PcrSlot::Slot2,
        PcrSlot::Slot3,
        PcrSlot::Slot4,
        PcrSlot::Slot5,
        PcrSlot::Slot6,
        PcrSlot::Slot7,
        PcrSlot::Slot8,
        PcrSlot::Slot9,
        PcrSlot::Slot10,
        PcrSlot::Slot11,
        PcrSlot::Slot12,
        PcrSlot::Slot13,
        PcrSlot::Slot14,
        PcrSlot::Slot15,
        PcrSlot::Slot16,
        PcrSlot::Slot17,
        PcrSlot::Slot18,
        PcrSlot::Slot19,
        PcrSlot::Slot20,
        PcrSlot::Slot21,
        PcrSlot::Slot22,
        PcrSlot::Slot23,
    ];

    pub fn get_pcr_selection_list() -> anyhow::Result<tss_esapi::structures::PcrSelectionList> {
        Ok(tss_esapi::structures::PcrSelectionListBuilder::new()
            .with_selection(
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
                &self::VTPM_DEFAULT_PCR_SLOTS,
            )
            .with_size_of_select(tss_esapi::structures::PcrSelectSize::default())
            .build()
            .expect("unable to build PCR Selection List"))
    }

    pub struct Quote {
        pub message: Vec<u8>,
        pub digest: [u8; 32],
        pub signature: Vec<u8>,
    }

    impl Quote {
        pub fn verify(
            &self,
            pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
        ) -> anyhow::Result<bool> {
            let mut verifier =
                openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), pkey)?;

            verifier.update(&self.message)?;
            Ok(verifier.verify(&self.signature)?)
        }

        pub fn unmarshal(&self) -> tss_esapi::structures::Attest {
            tss_esapi::structures::Attest::unmarshall(&self.message).expect("invalid quote message")
        }

        pub fn get_nonce(&self) -> Vec<u8> {
            self.unmarshal().extra_data().to_vec()
        }
    }

    pub fn get_pcr_quote(
        ctx: std::option::Option<&mut tss_esapi::Context>,
        nonce: [u8; 32],
    ) -> anyhow::Result<Quote> {
        let mut ctx: &mut tss_esapi::Context = match ctx {
            Some(c) => c,
            None => &mut vtpm::get_session_context()?,
        };

        let key_handle = get_ak_handle(Some(&mut ctx))?;
        let (attest_info, attest_sig) = ctx.quote(
            key_handle,
            nonce.to_vec().try_into()?,
            tss_esapi::structures::SignatureScheme::Null,
            get_pcr_selection_list()?,
        )?;

        let tss_esapi::structures::AttestInfo::Quote { info: quote_info } = attest_info.attested()
        else {
            return Err(anyhow!("invalid Attestation Info"));
        };

        if !quote_info.pcr_selection().eq(&get_pcr_selection_list()?) {
            return Err(anyhow!("invalid PCRs Attested"));
        }

        let digest: [u8; 32] = quote_info.pcr_digest().value().try_into()?;
        let message = attest_info.marshall()?;

        let tss_esapi::structures::Signature::RsaSsa(rsa_sig) = attest_sig else {
            return Err(anyhow!("invalid Signature Type"));
        };
        let signature: Vec<u8> = rsa_sig.signature().to_vec();

        Ok(Quote {
            message,
            digest,
            signature,
        })
    }

    pub fn get_pcrs(
        ctx: std::option::Option<&mut tss_esapi::Context>,
    ) -> anyhow::Result<tss_esapi::abstraction::pcr::PcrData> {
        let ctx: &mut tss_esapi::Context = match ctx {
            Some(c) => c,
            None => &mut vtpm::get_session_context()?,
        };

        vtpm::tpm2_get_pcrs(get_pcr_selection_list()?, Some(ctx))
    }

    pub fn get_pcr_digest(pcrs: &tss_esapi::abstraction::pcr::PcrData) -> anyhow::Result<[u8; 32]> {
        let mut hasher = openssl::sha::Sha256::new();

        pcrs
            // get bank with such algorithm
            .pcr_bank(tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256)
            .ok_or(anyhow!("empty PCR bank"))?
            .into_iter()
            .map(|(_, digest)| digest.value().try_into().unwrap())
            .collect::<Vec<[u8; 32]>>()
            .into_iter()
            .for_each(|digest| hasher.update(&digest));

        Ok(hasher.finish())
    }

    const VTPM_HCL_AKPUB_PERSISTENT_HANDLE: u32 = 0x81000003;
    const VTPM_HCL_AKPUBCERT_NV_INDEX: u32 = 0x1C101D0;

    static VTPM_CA_CERT: std::sync::LazyLock<openssl::x509::X509> =
        std::sync::LazyLock::new(|| {
            openssl::x509::X509::from_pem(include_bytes!("../.././certs/microsoft/vTPMCA2023.crt"))
                .expect("failed to parse Azure vTPM CA")
        });

    static VTPM_INTERMEDIATE_CERT: std::sync::LazyLock<Vec<openssl::x509::X509>> =
        std::sync::LazyLock::new(|| {
            vec![
                openssl::x509::X509::from_pem(include_bytes!("../.././certs/microsoft/ICA01.cer"))
                    .expect("failed to parse Azure vTPM ICA-01"),
                openssl::x509::X509::from_pem(include_bytes!("../.././certs/microsoft/ICA03.cer"))
                    .expect("failed to parse Azure vTPM ICA-03"),
            ]
        });

    pub fn get_intermediate_cert(
        ak_cert: &openssl::x509::X509,
    ) -> anyhow::Result<&'static openssl::x509::X509> {
        Ok(VTPM_INTERMEDIATE_CERT
            .iter()
            .find(|ica| ica.subject_name_hash() == ak_cert.issuer_name_hash())
            .context("Attestation Key has an invalid issuer")?)
    }

    pub fn verify_ak_cert(ak_cert: &openssl::x509::X509) -> anyhow::Result<bool> {
        let ica_cert = get_intermediate_cert(&ak_cert)?;

        ak_cert.verify(&ica_cert.public_key().unwrap())?;
        Ok(ica_cert.verify(&VTPM_CA_CERT.public_key().unwrap())?)
    }

    /**
     * Retrieve Attestation (Identity) Public Certificate
     */
    pub fn get_ak_cert(
        ctx: std::option::Option<&mut tss_esapi::Context>,
    ) -> anyhow::Result<openssl::x509::X509> {
        let mut ctx: &mut tss_esapi::Context = match ctx {
            Some(c) => c,
            None => &mut vtpm::get_session_context()?,
        };
        let cert: &[u8; 4096];

        let bytes = vtpm::tpm2_read(VTPM_HCL_AKPUBCERT_NV_INDEX, Some(&mut ctx))?;
        cert = bytes[..4096].try_into()?;

        Ok(openssl::x509::X509::from_der(cert)?)
    }

    pub fn get_ak_handle(
        ctx: std::option::Option<&mut tss_esapi::Context>,
    ) -> anyhow::Result<tss_esapi::handles::KeyHandle> {
        let ctx: &mut tss_esapi::Context = match ctx {
            Some(c) => c,
            None => &mut vtpm::get_session_context()?,
        };

        let tpm_handle: tss_esapi::handles::TpmHandle =
            VTPM_HCL_AKPUB_PERSISTENT_HANDLE.try_into()?;

        Ok(ctx
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(tpm_handle))?
            .into())
    }

    /**
     * Retrieve Attestation (Identity) Public Key
     */
    pub fn get_ak(
        ctx: std::option::Option<&mut tss_esapi::Context>,
    ) -> Result<openssl::rsa::Rsa<openssl::pkey::Public>, anyhow::Error> {
        let ctx: &mut tss_esapi::Context = match ctx {
            Some(c) => c,
            None => &mut vtpm::get_session_context()?,
        };

        let key_handle = get_ak_handle(Some(ctx))?;
        let (pk, _, _) = ctx
            .execute_without_session(|ctx| ctx.read_public(key_handle.into()))
            .expect("unable to read AK Public Key");

        let decoded_pk: tss_esapi::abstraction::public::DecodedKey =
            tss_esapi::abstraction::public::DecodedKey::try_from(pk)?;
        let tss_esapi::abstraction::public::DecodedKey::RsaPublicKey(rsa_public_key) = decoded_pk
        else {
            return Err(anyhow!("invalid key"));
        };

        Ok(openssl::rsa::Rsa::from_public_components(
            BigNum::from_slice(&rsa_public_key.modulus)?,
            BigNum::from_slice(&rsa_public_key.public_exponent)?,
        )?)
    }
}

pub mod report {
    use super::*;

    use anyhow::{Context, Result, anyhow};
    use serde::{Deserialize, Serialize};
    use sev::firmware::guest::AttestationReport;

    const VTPM_HCL_REPORT_NV_INDEX: u32 = 0x01400001;
    const VTPM_HCL_REPORT_DATA_NV_INDEX: u32 = 0x01400002;

    // https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design#attestation-report
    #[repr(C)]
    #[derive(Deserialize, Serialize, Debug, Clone)]
    pub struct Hcl {
        pub rsv1: types::RSV1, // [u8; RSV1_SIZE], // header
        pub report: AttestationReport,
        pub rsv2: types::RSV2, // Runtime Data (20 + variable length bytes)
    }

    pub fn get(vmpl: u32) -> Result<(Hcl, Vec<u8>)> {
        if vmpl > 0 {
            eprintln!(
                "Warning: --vmpl argument was ignored because attestation report is pre-fetched at VMPL 0 and stored in vTPM."
            );
        }
        let bytes = vtpm::tpm2_read(VTPM_HCL_REPORT_NV_INDEX, None)
            .context("unable to read attestation report bytes from vTPM")?;

        Ok((new_hcl(&bytes)?, bytes))
    }

    pub fn new_hcl(bytes: &[u8]) -> Result<Hcl> {
        // HCL minumum byte length
        if bytes.len() < TOTAL_SIZE {
            return Err(anyhow!(
                "HCL report size mismatch: expected at least {}, got {}",
                TOTAL_SIZE,
                bytes.len()
            ));
        }

        let rsv1_bytes = &bytes[RSV1_RANGE];
        let report_bytes = &bytes[REPORT_RANGE];

        let mut rsv2_bytes: Vec<u8> = (&bytes[RSV2_RANGE]).to_vec();

        let claims_len = u32::from_le_bytes(
            rsv2_bytes[16..20]
                .try_into()
                .context("can't decode claims length")?,
        );
        rsv2_bytes.extend((&bytes[TOTAL_SIZE..TOTAL_SIZE + (claims_len as usize)]).iter());

        Ok(Hcl {
            rsv1: types::RSV1::from_bytes(rsv1_bytes.try_into()?)?,
            report: AttestationReport::from_bytes(report_bytes)?,
            rsv2: types::RSV2::from_vec(rsv2_bytes)?,
        })
    }

    /**
     * verify hash of runtime claims in attestation report's report_data field
     */
    pub fn verify_report_data(
        hash: types::Hash,
        report_data: &[u8],
        claims: &[u8],
    ) -> anyhow::Result<bool> {
        Ok(hash.hash(claims)? == &report_data[..(hash.byte_len() as usize)])
    }

    /**
     * write nonce to attest vTPM runtime claims facts.
     */
    pub fn write_user_data(nonce: [u8; 64]) -> anyhow::Result<()> {
        vtpm::tpm2_write(VTPM_HCL_REPORT_DATA_NV_INDEX, &nonce)
    }

    use crate::nonce;
    pub fn validate_hcl_claims(
        buf: &Vec<u8>,
        nonce: &nonce::SevNonce,
    ) -> anyhow::Result<sev::firmware::guest::AttestationReport> {
        let hcl = new_hcl(&buf).expect("hcl error");
        // println!("{:#?}", hcl);

        println!("{:?}", hcl.rsv1);
        println!("{:?}", hcl.report);
        println!("{:?}", hcl.rsv2);

        /*
         * improve this
         *
         * rsv2 claims validation
         */
        let validate_claims = verify_report_data(
            types::Hash::try_from(hcl.rsv2.hash_type).unwrap(),
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
        let claims_nonce = crate::json::extract_as_string(&claims_json, "user-data").unwrap();

        println!("claims nonce: {}", claims_nonce);
        if nonce.to_hex() != claims_nonce {
            return Err(ExtendedHclError::InvalidNonce(claims_nonce).into());
        }

        Ok(hcl.report)
    }
    use thiserror::Error;
    #[derive(Error, Debug)]
    pub enum ExtendedHclError {
        #[error("invalid nonce: {0}")]
        InvalidNonce(String),
    }
}

/**
 * TODO: get original bytes from structs
 */
pub mod types {
    use super::RSV1_SIZE;
    use super::RSV2_SIZE;
    use anyhow::anyhow;
    use serde::{Deserialize, Serialize};

    const HCL_RSV1_SIG: &str = "HCLA";

    #[derive(Deserialize, Serialize, Debug, Clone)]
    pub struct RSV1 {
        pub signature: std::string::String,
        pub version: u32,
    }

    impl RSV1 {
        pub fn from_bytes(bytes: [u8; RSV1_SIZE]) -> anyhow::Result<RSV1> {
            let signature = std::str::from_utf8(&bytes[..4])?;
            if signature != HCL_RSV1_SIG {
                return Err(anyhow!("invalid RSV1 signature."));
            }

            let version = u32::from_le_bytes(bytes[4..8].try_into()?);

            Ok(RSV1 {
                signature: signature.to_string(),
                version: version,
            })
        }
    }

    #[derive(Clone, Copy)]
    pub enum Hash {
        SHA256,
        SHA384,
        SHA512,
    }

    impl Hash {
        pub fn byte_len(self) -> u32 {
            match self {
                Hash::SHA256 => 32,
                Hash::SHA384 => 48,
                Hash::SHA512 => 64,
            }
        }

        pub fn hash(self, bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
            match self {
                Hash::SHA256 => Ok(openssl::sha::sha256(bytes).to_vec()),
                Hash::SHA384 => Ok(openssl::sha::sha384(bytes).to_vec()),
                Hash::SHA512 => Ok(openssl::sha::sha512(bytes).to_vec()),
            }
        }
    }

    impl std::convert::TryFrom<u32> for Hash {
        type Error = anyhow::Error;
        fn try_from(hash_type: u32) -> anyhow::Result<Hash, anyhow::Error> {
            match hash_type {
                1 => Ok(Hash::SHA256),
                2 => Ok(Hash::SHA384),
                3 => Ok(Hash::SHA512),
                _ => Err(anyhow!("")),
            }
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct RSV2 {
        pub version: u32,
        pub hash_type: u32,
        runtime_claims: Vec<u8>,
    }

    impl RSV2 {
        pub fn from_vec(bytes: Vec<u8>) -> anyhow::Result<RSV2> {
            let version = u32::from_le_bytes(bytes[4..8].try_into()?);
            let hash_type = u32::from_le_bytes(bytes[12..16].try_into()?);

            Ok(RSV2 {
                version,
                hash_type,
                runtime_claims: bytes[RSV2_SIZE..].to_vec(),
            })
        }

        pub fn claims_json(&self) -> anyhow::Result<serde_json::Value> {
            Ok(serde_json::from_str(std::str::from_utf8(
                &self.runtime_claims,
            )?)?)
        }

        pub fn claims_bytes(&self) -> &Vec<u8> {
            &self.runtime_claims
        }
    }
}
