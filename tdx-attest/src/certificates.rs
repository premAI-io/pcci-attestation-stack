pub mod ca;
pub mod crl;

use std::{fmt::Display, time::SystemTime};

use der::{
    Encode,
    oid::db::rfc5912::{ECDSA_WITH_SHA_256, ID_EC_PUBLIC_KEY},
};
use p256::{
    PublicKey,
    ecdsa::{DerSignature, Signature, VerifyingKey, signature::Verifier},
};
use spki::{DecodePublicKey, ObjectIdentifier};
use thiserror::Error;
use x509_cert::{anchor::CertPolicies, crl::TbsCertList, serial_number::SerialNumber};

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("tried parsing a certificate with an unsupported algorithm: {0}")]
    WrongAlgorithm(spki::Error),

    #[error("a signature or key was serialized in the wrong format in the certificate")]
    WrongFormat,

    #[error("the format for the certificate chain is wrong")]
    BadChain,

    #[error("error while verifying the signature of one or more certificates: {0}")]
    BadSignature(p256::ecdsa::Error),

    #[error("this cryptographic entity is expired")]
    Expired,

    #[error("an error occurred while parsing the certificate: {0}")]
    Der(#[from] der::Error),

    #[error("a certificate (serial_number = {serial_number}) has been revoked")]
    Revoked { serial_number: SerialNumber },
}

#[derive(Debug)]
pub enum IntermediateCa {
    Platform,
    Processor,
}

impl IntermediateCa {
    pub fn as_str(&self) -> &'static str {
        match self {
            IntermediateCa::Platform => "platform",
            IntermediateCa::Processor => "processor",
        }
    }
}

#[derive(Debug)]
pub struct EcdsaCert {
    /// the original certificate where public_key and signature were derived from
    certificate: x509_cert::Certificate,
    /// this is the public key the certificate is trying to attest
    public_key: VerifyingKey,
    /// this is the signature attesting the authenticity and trustworthyness of the public key
    signature: Signature,
}

pub type PinnedCertificate = &'static EcdsaCert;

impl EcdsaCert {
    /// verifies that this certificate (`self`) contains a signed public key
    /// that attests for the authenticity of the signature of another certificate (`other`)
    pub fn verify_cert(&self, other: &Self) -> Result<(), CertificateError> {
        let other_tbs = other.certificate.tbs_certificate().to_der()?;
        self.public_key
            .verify(&other_tbs, &other.signature)
            .map_err(CertificateError::BadSignature)?;

        Ok(())
    }

    /// verifies if the certificate is self-signed
    pub fn verify_self(&self) -> Result<(), CertificateError> {
        self.verify_cert(self)
    }

    /// Steps:
    /// - decode signature and public key
    /// - check for certificate validity
    fn from_cert(certificate: x509_cert::Certificate) -> Result<Self, CertificateError> {
        // Check that the signature and public key are in the
        // format supported by the library (elliptic curve certificates)
        certificate
            .signature_algorithm()
            .assert_algorithm_oid(ECDSA_WITH_SHA_256)
            .map_err(CertificateError::WrongAlgorithm)?;

        certificate
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .assert_algorithm_oid(ID_EC_PUBLIC_KEY)
            .map_err(CertificateError::WrongAlgorithm)?;

        // signature
        let signature = certificate
            .signature()
            .as_bytes()
            .ok_or(CertificateError::WrongFormat)?;

        let signature =
            Signature::from_der(signature).expect("could not re-decode an encoded signature");

        // signed public key
        let public_key = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .as_bytes()
            .ok_or(CertificateError::WrongFormat)?;

        let public_key = VerifyingKey::from_sec1_bytes(public_key)
            .expect("could not re-decode an encoded public key");

        // check for certificate validity
        let not_after = certificate
            .tbs_certificate()
            .validity()
            .not_after
            .to_system_time();

        let not_before = certificate
            .tbs_certificate()
            .validity()
            .not_before
            .to_system_time();

        let now = SystemTime::now();

        if not_before > now || not_after < now {
            return Err(CertificateError::Expired);
        }

        Ok(Self {
            certificate,
            signature,
            public_key,
        })
    }
}

impl Verifier<Signature> for EcdsaCert {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        self.public_key.verify(msg, signature)
    }
}

impl TryFrom<x509_cert::Certificate> for EcdsaCert {
    type Error = CertificateError;
    fn try_from(value: x509_cert::Certificate) -> Result<Self, Self::Error> {
        Self::from_cert(value)
    }
}

#[derive(Debug)]
/// represents a cryptographically verified
/// certificate chain
pub struct CertificateChain {
    anchor: Option<PinnedCertificate>,
    chain: Vec<EcdsaCert>,
}

impl Verifier<Signature> for CertificateChain {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        let certificate = self.chain.last().or(self.anchor).unwrap();
        certificate.verify(msg, signature)
    }
}

impl CertificateChain {
    pub fn with_anchor(anchor: PinnedCertificate) -> Self {
        Self {
            anchor: Some(anchor),
            chain: vec![],
        }
    }

    pub fn push_certificate(&mut self, other: EcdsaCert) -> Result<(), CertificateError> {
        let verifier = self.chain.last().or(self.anchor);

        match verifier {
            Some(verifier) => verifier.verify_cert(&other)?,
            None => other.verify_self()?,
        };

        self.chain.push(other);

        Ok(())
    }

    pub fn parse_pem_chain(mut self, chain: &[u8]) -> Result<Self, CertificateError> {
        let chain = chain.strip_suffix(b"\0").unwrap_or(chain); // chain from tdx could be 0 terminated so we do a little sanitization

        let chain: Vec<EcdsaCert> = x509_cert::Certificate::load_pem_chain(chain)?
            .into_iter()
            .map(EcdsaCert::from_cert)
            .collect::<Result<_, _>>()?;

        let mut chain = chain.into_iter().rev();

        if let Some(anchor) = self.anchor {
            // discard the root certificate from the pem chain if we already have our own embedded trust
            let _root = chain.next().ok_or(CertificateError::BadChain)?;
        }

        chain.try_for_each(|cert| self.push_certificate(cert))?;

        Ok(self)
    }

    // verifies the current certificate chain with an out of bounds
    // certificate, by veryfying it signs our root of trust
    // fn verify_oob(&self, oob_root: &EcdsaCert) -> Result<(), CertificateError> {
    //     let mut chain = self.chain.iter();
    //     let chain_root = chain.next().unwrap();

    //     oob_root.verify_cert(chain_root)?;
    //     if let Some(certificate) = chain.next() {
    //         // if there's an intermediate right after the root
    //         // certificate optionally verify that as well
    //         oob_root.verify_cert(certificate);
    //     }

    //     Ok(())
    // }
}
