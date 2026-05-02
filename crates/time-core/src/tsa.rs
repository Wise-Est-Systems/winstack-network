use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sha2::{Digest, Sha256, Sha512};

#[derive(Debug, thiserror::Error)]
pub enum TsaError {
    #[error("malformed DER in request")]
    MalformedRequest,
    #[error("malformed DER in response")]
    MalformedResponse,
    #[error("TSA rejected request (status {0})")]
    Rejected(u8),
    #[error("no token in TSA response")]
    NoToken,
    #[error("hash mismatch: token contains different hash")]
    HashMismatch,
    #[error("invalid base64")]
    InvalidBase64,
    #[error("CMS signature invalid: {0}")]
    SignatureInvalid(String),
    #[error("certificate chain invalid: {0}")]
    CertificateChainInvalid(String),
    #[error("TSA not trusted: {0}")]
    NotTrusted(String),
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("certificate expired or not yet valid: {0}")]
    CertificateExpired(String),
}

#[derive(Debug, Clone)]
pub struct TsaTokenInfo {
    pub message_hash_hex: String,
    pub gen_time: String,
    pub tsa_subject: Option<String>,
    pub signature_verified: bool,
    pub chain_verified: bool,
    pub trust_mode: String,
}

#[derive(Debug, thiserror::Error)]
#[error("certificate expired or not yet valid: {0}")]
pub struct CertValidityError(pub String);

/// A set of trusted TSA root certificate fingerprints (SHA-256 of DER-encoded cert).
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    /// SHA-256 hex fingerprints of trusted root certificates.
    /// If empty, any self-consistent chain is accepted (open trust).
    pub trusted_roots: Vec<String>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_roots(roots: Vec<String>) -> Self {
        Self {
            trusted_roots: roots,
        }
    }

    pub fn is_open(&self) -> bool {
        self.trusted_roots.is_empty()
    }

    pub fn is_trusted(&self, cert_fingerprint: &str) -> bool {
        self.is_open() || self.trusted_roots.iter().any(|r| r == cert_fingerprint)
    }
}

// ── DER constants ──

const TAG_SEQUENCE: u8 = 0x30;
const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_BOOLEAN: u8 = 0x01;
const TAG_CONTEXT_0: u8 = 0xa0;
const TAG_GENERALIZED_TIME: u8 = 0x18;

const SHA256_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

// ── DER helpers ──

fn der_len(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend(content);
    out
}

fn read_element(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let tag = data[0];
    let (len, hdr) = if data[1] < 128 {
        (data[1] as usize, 2)
    } else if data[1] == 0x81 && data.len() >= 3 {
        (data[2] as usize, 3)
    } else if data[1] == 0x82 && data.len() >= 4 {
        ((data[2] as usize) << 8 | data[3] as usize, 4)
    } else if data[1] == 0x83 && data.len() >= 5 {
        (
            (data[2] as usize) << 16 | (data[3] as usize) << 8 | data[4] as usize,
            5,
        )
    } else {
        return None;
    };
    if data.len() < hdr + len {
        return None;
    }
    Some((tag, &data[hdr..hdr + len], &data[hdr + len..]))
}

fn children(data: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = vec![];
    let mut rest = data;
    while let Some((tag, content, remaining)) = read_element(rest) {
        out.push((tag, content));
        rest = remaining;
    }
    out
}

// ── Public API ──

/// Build an RFC 3161 TimeStampReq for the given SHA-256 hash (hex string).
pub fn build_timestamp_request(hash_hex: &str) -> Result<Vec<u8>, TsaError> {
    let hash_bytes = hex::decode(hash_hex).map_err(|_| TsaError::MalformedRequest)?;
    if hash_bytes.len() != 32 {
        return Err(TsaError::MalformedRequest);
    }

    let version = der_wrap(TAG_INTEGER, &[1]);
    let oid = der_wrap(TAG_OID, SHA256_OID);
    let hash_alg = der_wrap(TAG_SEQUENCE, &oid);
    let hashed_msg = der_wrap(TAG_OCTET_STRING, &hash_bytes);
    let mut mi = hash_alg;
    mi.extend(hashed_msg);
    let message_imprint = der_wrap(TAG_SEQUENCE, &mi);
    let cert_req = der_wrap(TAG_BOOLEAN, &[0xff]);

    let mut body = version;
    body.extend(message_imprint);
    body.extend(cert_req);
    Ok(der_wrap(TAG_SEQUENCE, &body))
}

/// Extract the ContentInfo (CMS token) from a TimeStampResp.
/// Returns (status, token_bytes) where token_bytes is the raw ContentInfo DER.
fn extract_token_from_response(resp: &[u8]) -> Result<(u8, Vec<u8>), TsaError> {
    let (tag, resp_content, _) = read_element(resp).ok_or(TsaError::MalformedResponse)?;
    if tag != TAG_SEQUENCE {
        return Err(TsaError::MalformedResponse);
    }
    let top = children(resp_content);
    if top.is_empty() {
        return Err(TsaError::MalformedResponse);
    }

    let status_children = children(top[0].1);
    if status_children.is_empty() {
        return Err(TsaError::MalformedResponse);
    }
    let status_val = *status_children[0]
        .1
        .last()
        .ok_or(TsaError::MalformedResponse)?;
    if status_val > 1 {
        return Err(TsaError::Rejected(status_val));
    }

    if top.len() < 2 {
        return Err(TsaError::NoToken);
    }

    // Reconstruct the raw DER of the ContentInfo element
    let ci_der = der_wrap(top[1].0, top[1].1);
    Ok((status_val, ci_der))
}

/// Parse an RFC 3161 TimeStampResp and extract hash + genTime (basic, no CMS verification).
pub fn parse_timestamp_response(resp: &[u8]) -> Result<TsaTokenInfo, TsaError> {
    let (tag, resp_content, _) = read_element(resp).ok_or(TsaError::MalformedResponse)?;
    if tag != TAG_SEQUENCE {
        return Err(TsaError::MalformedResponse);
    }
    let top = children(resp_content);
    if top.is_empty() {
        return Err(TsaError::MalformedResponse);
    }

    let status_children = children(top[0].1);
    if status_children.is_empty() {
        return Err(TsaError::MalformedResponse);
    }
    let status_val = *status_children[0]
        .1
        .last()
        .ok_or(TsaError::MalformedResponse)?;
    if status_val > 1 {
        return Err(TsaError::Rejected(status_val));
    }

    if top.len() < 2 {
        return Err(TsaError::NoToken);
    }

    // Navigate to TSTInfo
    let (hash_hex, gen_time) = extract_tst_info_fields(top[1].1)?;

    Ok(TsaTokenInfo {
        message_hash_hex: hash_hex,
        gen_time,
        tsa_subject: None,
        signature_verified: false,
        chain_verified: false,
        trust_mode: "none".to_string(),
    })
}

/// Navigate ContentInfo -> SignedData -> EncapContentInfo -> TSTInfo
/// and extract the message hash and genTime.
fn extract_tst_info_fields(ci_content: &[u8]) -> Result<(String, String), TsaError> {
    let ci_children = children(ci_content);
    if ci_children.len() < 2 {
        return Err(TsaError::MalformedResponse);
    }
    let (_, sd_raw, _) = read_element(ci_children[1].1).ok_or(TsaError::MalformedResponse)?;
    let sd_children = children(sd_raw);
    if sd_children.len() < 3 {
        return Err(TsaError::MalformedResponse);
    }

    let ecap = children(sd_children[2].1);
    if ecap.len() < 2 {
        return Err(TsaError::MalformedResponse);
    }

    let (_, octet_raw, _) = read_element(ecap[1].1).ok_or(TsaError::MalformedResponse)?;

    let (_, tst_content, _) = read_element(octet_raw).ok_or(TsaError::MalformedResponse)?;
    let tst = children(tst_content);
    if tst.len() < 5 {
        return Err(TsaError::MalformedResponse);
    }

    let mi = children(tst[2].1);
    if mi.len() < 2 {
        return Err(TsaError::MalformedResponse);
    }
    let hash_hex = hex::encode(mi[1].1);

    let gen_time = if tst[4].0 == TAG_GENERALIZED_TIME {
        String::from_utf8_lossy(tst[4].1).to_string()
    } else {
        "unknown".to_string()
    };

    Ok((hash_hex, gen_time))
}

// ── CMS Signature Verification ──

/// Fully verify an RFC 3161 token: hash match, CMS signature, and certificate chain.
pub fn verify_token_full(
    token_base64: &str,
    expected_hash_hex: &str,
    trust_store: &TrustStore,
) -> Result<TsaTokenInfo, TsaError> {
    let token_bytes = B64
        .decode(token_base64)
        .map_err(|_| TsaError::InvalidBase64)?;

    // 1. Parse basic response and check hash
    let basic_info = parse_timestamp_response(&token_bytes)?;
    if basic_info.message_hash_hex != expected_hash_hex {
        return Err(TsaError::HashMismatch);
    }

    // 2. Extract ContentInfo DER for CMS parsing
    let (_status, ci_der) = extract_token_from_response(&token_bytes)?;

    // 3. Parse CMS ContentInfo using the cms crate
    use cms::content_info::ContentInfo;
    use der::Decode;

    let content_info = ContentInfo::from_der(&ci_der).map_err(|_| TsaError::MalformedResponse)?;

    // 4. Extract SignedData
    use cms::signed_data::SignedData;
    let signed_data = content_info
        .content
        .decode_as::<SignedData>()
        .map_err(|_| TsaError::MalformedResponse)?;

    // 5. Extract the encapsulated content (TSTInfo DER) for digest computation
    let econtent = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(TsaError::MalformedResponse)?;
    let econtent_bytes = econtent.value();

    // 6. Extract certificates from the CMS structure
    use x509_cert::Certificate;
    let certs: Vec<Certificate> = if let Some(cert_set) = &signed_data.certificates {
        cert_set
            .0
            .iter()
            .filter_map(|choice| {
                if let cms::cert::CertificateChoices::Certificate(cert) = choice {
                    Some(cert.clone())
                } else {
                    None
                }
            })
            .collect()
    } else {
        return Err(TsaError::CertificateChainInvalid(
            "no certificates in CMS".into(),
        ));
    };

    if certs.is_empty() {
        return Err(TsaError::CertificateChainInvalid(
            "no certificates in CMS".into(),
        ));
    }

    // 7. Get the signer info
    let signer_info = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or(TsaError::SignatureInvalid("no signer info".into()))?;

    // 8. Find the signer's certificate by matching issuer/serial
    let signer_cert = match &signer_info.sid {
        cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(iasn) => certs
            .iter()
            .find(|c| {
                c.tbs_certificate.issuer == iasn.issuer
                    && c.tbs_certificate.serial_number == iasn.serial_number
            })
            .ok_or(TsaError::SignatureInvalid(
                "signer certificate not found in CMS".into(),
            ))?,
        _ => {
            return Err(TsaError::SignatureInvalid(
                "unsupported signer identifier type".into(),
            ));
        },
    };

    // 9. Determine the digest algorithm from signer info
    let digest_oid = &signer_info.digest_alg.oid;
    let sha256_oid = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    let sha512_oid = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

    // Compute the content digest
    let content_digest: Vec<u8> = if *digest_oid == sha256_oid {
        Sha256::digest(econtent_bytes).to_vec()
    } else if *digest_oid == sha512_oid {
        Sha512::digest(econtent_bytes).to_vec()
    } else {
        return Err(TsaError::UnsupportedAlgorithm(format!(
            "digest algorithm {}",
            digest_oid
        )));
    };

    // 10. If signed attributes exist, verify the digest attribute matches,
    //     then the signature is over the DER-encoded signed attributes.
    //     If no signed attributes, the signature is over the content directly.
    let signature_input: Vec<u8> = if let Some(ref signed_attrs) = signer_info.signed_attrs {
        // Verify message-digest attribute matches
        let md_oid = const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
        let md_attr = signed_attrs.iter().find(|a| a.oid == md_oid);
        if let Some(attr) = md_attr {
            if let Some(val) = attr.values.iter().next() {
                let attr_digest = val.value();
                if attr_digest != content_digest.as_slice() {
                    return Err(TsaError::SignatureInvalid(
                        "message-digest attribute does not match content digest".into(),
                    ));
                }
            }
        }

        // Signature is computed over SET-encoded signed attributes
        // We need the raw DER with SET tag (0x31) instead of IMPLICIT [0] (0xa0)
        use der::Encode;
        let mut attrs_der = Vec::new();
        signed_attrs
            .encode_to_vec(&mut attrs_der)
            .map_err(|_| TsaError::SignatureInvalid("cannot encode signed attrs".into()))?;
        // Replace the tag from IMPLICIT [0] (0xa0) to SET (0x31)
        if !attrs_der.is_empty() {
            attrs_der[0] = 0x31;
        }
        attrs_der
    } else {
        econtent_bytes.to_vec()
    };

    // 11. Verify the CMS signature using the signer certificate's public key
    let sig_bytes = signer_info.signature.as_bytes();
    let sig_alg_oid = &signer_info.signature_algorithm.oid;

    let rsa_sha256 = const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    let rsa_sha512 = const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
    let ecdsa_sha256 = const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    let ecdsa_sha384 = const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
    let ecdsa_sha512 = const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

    let spki_der = {
        use der::Encode;
        let mut buf = Vec::new();
        signer_cert
            .tbs_certificate
            .subject_public_key_info
            .encode_to_vec(&mut buf)
            .map_err(|_| TsaError::SignatureInvalid("cannot encode SPKI".into()))?;
        buf
    };

    let sig_valid = if *sig_alg_oid == rsa_sha256 {
        verify_rsa_sha256(&spki_der, &signature_input, sig_bytes)
    } else if *sig_alg_oid == rsa_sha512 {
        verify_rsa_sha512(&spki_der, &signature_input, sig_bytes)
    } else if *sig_alg_oid == ecdsa_sha256 {
        verify_ecdsa_p256(&spki_der, &signature_input, sig_bytes)
    } else if *sig_alg_oid == ecdsa_sha384 {
        verify_ecdsa_p384(&spki_der, &signature_input, sig_bytes)
    } else if *sig_alg_oid == ecdsa_sha512 {
        // P-384 with SHA-512 (used by FreeTSA)
        verify_ecdsa_p384_sha512(&spki_der, &signature_input, sig_bytes)
    } else {
        return Err(TsaError::UnsupportedAlgorithm(format!(
            "signature algorithm {}",
            sig_alg_oid
        )));
    };

    if !sig_valid {
        return Err(TsaError::SignatureInvalid(
            "CMS signature verification failed".into(),
        ));
    }

    // 12. Validate certificate chain
    if !verify_certificate_chain(&certs, signer_cert) {
        return Err(TsaError::CertificateChainInvalid(
            "signer certificate chain signature verification failed".into(),
        ));
    }

    // 13. Check certificate validity (notBefore / notAfter)
    for cert in &certs {
        check_cert_validity(cert)?;
    }

    // 14. Check trust store
    let root_cert = find_root_cert(&certs);
    let root_fingerprint = root_cert.map(|c| {
        use der::Encode;
        let mut cert_der = Vec::new();
        c.encode_to_vec(&mut cert_der).ok();
        hex::encode(Sha256::digest(&cert_der))
    });

    let trusted = match &root_fingerprint {
        Some(fp) => trust_store.is_trusted(fp),
        None => trust_store.is_open(),
    };

    if !trusted {
        return Err(TsaError::NotTrusted(format!(
            "root certificate fingerprint {} not in trust store",
            root_fingerprint.as_deref().unwrap_or("unknown")
        )));
    }

    let trust_mode = if trust_store.is_open() {
        "open"
    } else {
        "pinned"
    };

    // Extract subject name for display
    let subject = format!("{}", signer_cert.tbs_certificate.subject);

    Ok(TsaTokenInfo {
        message_hash_hex: basic_info.message_hash_hex,
        gen_time: basic_info.gen_time,
        tsa_subject: Some(subject),
        signature_verified: true,
        chain_verified: true,
        trust_mode: trust_mode.to_string(),
    })
}

/// Simple hash-only verification (backward compatible, no CMS).
pub fn verify_token(token_base64: &str, expected_hash_hex: &str) -> Result<TsaTokenInfo, TsaError> {
    let token_bytes = B64
        .decode(token_base64)
        .map_err(|_| TsaError::InvalidBase64)?;
    let info = parse_timestamp_response(&token_bytes)?;
    if info.message_hash_hex != expected_hash_hex {
        return Err(TsaError::HashMismatch);
    }
    Ok(info)
}

// ── Signature verification helpers ──

fn verify_rsa_sha256(spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;

    let pk: rsa::RsaPublicKey = match rsa::pkcs8::DecodePublicKey::from_public_key_der(spki_der) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(pk);
    let sig = match Signature::try_from(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifying_key.verify(message, &sig).is_ok()
}

fn verify_rsa_sha512(spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;

    let pk: rsa::RsaPublicKey = match rsa::pkcs8::DecodePublicKey::from_public_key_der(spki_der) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let verifying_key: VerifyingKey<Sha512> = VerifyingKey::new(pk);
    let sig = match Signature::try_from(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifying_key.verify(message, &sig).is_ok()
}

fn verify_ecdsa_p256(spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let pk = match VerifyingKey::from_sec1_bytes(extract_ec_point_from_spki(spki_der)) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match Signature::from_der(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    pk.verify(message, &sig).is_ok()
}

fn verify_ecdsa_p384(spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let point = extract_ec_point_from_spki(spki_der);
    let pk = match VerifyingKey::from_sec1_bytes(point) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match Signature::from_der(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    pk.verify(message, &sig).is_ok()
}

fn verify_ecdsa_p384_sha512(spki_der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    // P-384 with SHA-512: compute SHA-512 digest first, then verify with P-384
    // This is what ecdsa-with-SHA512 on secp384r1 means
    use p384::ecdsa::{Signature, VerifyingKey};

    let point = extract_ec_point_from_spki(spki_der);
    let pk = match VerifyingKey::from_sec1_bytes(point) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match Signature::from_der(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // p384 ecdsa verify with SHA-384 by default — for SHA-512 we need prehash
    let digest = Sha512::digest(message);
    use p384::ecdsa::signature::hazmat::PrehashVerifier;
    pk.verify_prehash(&digest, &sig).is_ok()
}

/// Extract the EC public key point bytes from an SPKI DER structure.
fn extract_ec_point_from_spki(spki_der: &[u8]) -> &[u8] {
    // SPKI = SEQUENCE { AlgorithmIdentifier, BIT STRING }
    // The BIT STRING contains: 0x00 (unused bits) followed by the EC point
    let elems = children(
        read_element(spki_der)
            .map(|(_, c, _)| c)
            .unwrap_or(spki_der),
    );
    if elems.len() >= 2 && elems[1].0 == 0x03 {
        // BIT STRING: first byte is unused-bits count
        if !elems[1].1.is_empty() {
            &elems[1].1[1..] // skip the unused-bits byte
        } else {
            elems[1].1
        }
    } else {
        spki_der
    }
}

// ── Certificate chain validation ──

fn verify_certificate_chain(
    certs: &[x509_cert::Certificate],
    signer_cert: &x509_cert::Certificate,
) -> bool {
    // Find the issuer of the signer cert and verify the signer was signed by it
    let issuer_name = &signer_cert.tbs_certificate.issuer;
    let issuer_cert = certs.iter().find(|c| {
        c.tbs_certificate.subject == *issuer_name
            && c.tbs_certificate.serial_number != signer_cert.tbs_certificate.serial_number
    });

    match issuer_cert {
        Some(issuer) => verify_cert_signature(signer_cert, issuer),
        None => {
            // Self-signed or issuer not in chain — accept if self-signed
            verify_cert_signature(signer_cert, signer_cert)
        },
    }
}

fn verify_cert_signature(cert: &x509_cert::Certificate, issuer: &x509_cert::Certificate) -> bool {
    use der::Encode;

    // Get the TBS (to-be-signed) certificate DER
    let mut tbs_der = Vec::new();
    if cert.tbs_certificate.encode_to_vec(&mut tbs_der).is_err() {
        return false;
    }

    let sig_bytes = cert.signature.raw_bytes();
    let sig_alg = &cert.signature_algorithm.oid;

    let mut spki_der = Vec::new();
    if issuer
        .tbs_certificate
        .subject_public_key_info
        .encode_to_vec(&mut spki_der)
        .is_err()
    {
        return false;
    }

    let rsa_sha256 = const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    let rsa_sha512 = const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

    if *sig_alg == rsa_sha256 {
        verify_rsa_sha256(&spki_der, &tbs_der, sig_bytes)
    } else if *sig_alg == rsa_sha512 {
        verify_rsa_sha512(&spki_der, &tbs_der, sig_bytes)
    } else {
        // Unknown algorithm — fail closed
        false
    }
}

fn check_cert_validity(cert: &x509_cert::Certificate) -> Result<(), TsaError> {
    let validity = &cert.tbs_certificate.validity;
    let now = chrono::Utc::now();

    // Convert x509 Time to a comparable form
    let not_before = match &validity.not_before {
        x509_cert::time::Time::UtcTime(t) => t.to_date_time(),
        x509_cert::time::Time::GeneralTime(t) => t.to_date_time(),
    };
    let not_after = match &validity.not_after {
        x509_cert::time::Time::UtcTime(t) => t.to_date_time(),
        x509_cert::time::Time::GeneralTime(t) => t.to_date_time(),
    };

    let subject = format!("{}", cert.tbs_certificate.subject);

    // der::DateTime -> compare via to_string (both are ISO-like)
    let now_str = now.format("%Y%m%d%H%M%S").to_string();
    let nb_str = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        not_before.year(),
        not_before.month(),
        not_before.day(),
        not_before.hour(),
        not_before.minutes(),
        not_before.seconds()
    );
    let na_str = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        not_after.year(),
        not_after.month(),
        not_after.day(),
        not_after.hour(),
        not_after.minutes(),
        not_after.seconds()
    );

    if now_str < nb_str {
        return Err(TsaError::CertificateExpired(format!(
            "{} not yet valid (notBefore: {})",
            subject, nb_str
        )));
    }
    if now_str > na_str {
        return Err(TsaError::CertificateExpired(format!(
            "{} has expired (notAfter: {})",
            subject, na_str
        )));
    }

    Ok(())
}

fn find_root_cert(certs: &[x509_cert::Certificate]) -> Option<&x509_cert::Certificate> {
    // Root cert: issuer == subject (self-signed)
    certs
        .iter()
        .find(|c| c.tbs_certificate.issuer == c.tbs_certificate.subject)
}

// ── Test fixture builder ──

/// Build a synthetic RFC 3161 TimeStampResp for testing.
/// The response is structurally valid DER but has no real TSA signature.
pub fn build_test_tsa_response(hash: &[u8]) -> Vec<u8> {
    let tst_version = der_wrap(TAG_INTEGER, &[1]);
    let tst_policy = der_wrap(TAG_OID, &[0x2a, 0x03, 0x04]);
    let oid = der_wrap(TAG_OID, SHA256_OID);
    let hash_alg = der_wrap(TAG_SEQUENCE, &oid);
    let hashed_msg = der_wrap(TAG_OCTET_STRING, hash);
    let mut mi_body = hash_alg;
    mi_body.extend(hashed_msg);
    let msg_imprint = der_wrap(TAG_SEQUENCE, &mi_body);
    let serial = der_wrap(TAG_INTEGER, &[1]);
    let gen_time = der_wrap(TAG_GENERALIZED_TIME, b"20260405120000Z");

    let mut tst_body = tst_version;
    tst_body.extend(tst_policy);
    tst_body.extend(msg_imprint);
    tst_body.extend(serial);
    tst_body.extend(gen_time);
    let tst_info_der = der_wrap(TAG_SEQUENCE, &tst_body);

    let econtent_type = der_wrap(
        TAG_OID,
        &[
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04,
        ],
    );
    let econtent_octet = der_wrap(TAG_OCTET_STRING, &tst_info_der);
    let econtent_explicit = der_wrap(TAG_CONTEXT_0, &econtent_octet);
    let mut ecap_body = econtent_type;
    ecap_body.extend(econtent_explicit);
    let ecap_info = der_wrap(TAG_SEQUENCE, &ecap_body);

    let sd_version = der_wrap(TAG_INTEGER, &[3]);
    let sd_digest_algos = der_wrap(0x31, &[]);
    let sd_signer_infos = der_wrap(0x31, &[]);
    let mut sd_body = sd_version;
    sd_body.extend(sd_digest_algos);
    sd_body.extend(ecap_info);
    sd_body.extend(sd_signer_infos);
    let signed_data = der_wrap(TAG_SEQUENCE, &sd_body);

    let ci_oid = der_wrap(
        TAG_OID,
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02],
    );
    let ci_explicit = der_wrap(TAG_CONTEXT_0, &signed_data);
    let mut ci_body = ci_oid;
    ci_body.extend(ci_explicit);
    let content_info = der_wrap(TAG_SEQUENCE, &ci_body);

    let status = der_wrap(TAG_INTEGER, &[0]);
    let status_info = der_wrap(TAG_SEQUENCE, &status);

    let mut resp_body = status_info;
    resp_body.extend(content_info);
    der_wrap(TAG_SEQUENCE, &resp_body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_request() {
        let hash_hex = "a".repeat(64);
        let req = build_timestamp_request(&hash_hex).unwrap();
        assert!(!req.is_empty());
        assert_eq!(req[0], TAG_SEQUENCE);
    }

    #[test]
    fn build_and_parse_test_response() {
        let hash = [0xab_u8; 32];
        let resp = build_test_tsa_response(&hash);
        let info = parse_timestamp_response(&resp).unwrap();
        assert_eq!(info.message_hash_hex, hex::encode(hash));
        assert_eq!(info.gen_time, "20260405120000Z");
    }

    #[test]
    fn verify_token_matches() {
        let hash = hex::decode("a".repeat(64)).unwrap();
        let resp = build_test_tsa_response(&hash);
        let token_b64 = B64.encode(&resp);
        let info = verify_token(&token_b64, &"a".repeat(64)).unwrap();
        assert_eq!(info.message_hash_hex, "a".repeat(64));
    }

    #[test]
    fn verify_token_mismatch() {
        let hash = hex::decode("a".repeat(64)).unwrap();
        let resp = build_test_tsa_response(&hash);
        let token_b64 = B64.encode(&resp);
        let result = verify_token(&token_b64, &"b".repeat(64));
        assert!(matches!(result, Err(TsaError::HashMismatch)));
    }

    #[test]
    fn verify_token_malformed() {
        let token_b64 = B64.encode(b"not a valid der");
        let result = verify_token(&token_b64, &"a".repeat(64));
        assert!(result.is_err());
    }

    #[test]
    fn backward_compat_no_token() {
        let json = r#"{"time_event_id":"00000000-0000-0000-0000-000000000000","timestamp":"t","time_authority_identity_id":"00000000-0000-0000-0000-000000000000","predecessor_event_id":null,"predecessor_hash":null,"payload_hash":"h","signature":"s"}"#;
        let evt: canon_types::ChainedTimeEvent = serde_json::from_str(json).unwrap();
        assert_eq!(evt.time_source, canon_types::TimeSource::Local);
        assert!(evt.rfc3161_token.is_none());
        assert!(evt.anchored_time.is_none());
    }

    #[test]
    fn trust_store_open_accepts_all() {
        let store = TrustStore::new();
        assert!(store.is_open());
        assert!(store.is_trusted("anything"));
    }

    #[test]
    fn trust_store_pinned_rejects_unknown() {
        let store = TrustStore::with_roots(vec!["abc123".into()]);
        assert!(!store.is_open());
        assert!(store.is_trusted("abc123"));
        assert!(!store.is_trusted("xyz789"));
    }

    #[test]
    fn full_verify_test_fixture_no_cms() {
        // Test fixture has no real CMS signatures, so full verify should fail
        // on CMS parsing (no signer infos). This confirms we don't accept
        // unsigned test fixtures through the full verification path.
        let hash = hex::decode("a".repeat(64)).unwrap();
        let resp = build_test_tsa_response(&hash);
        let token_b64 = B64.encode(&resp);
        let store = TrustStore::new();
        let result = verify_token_full(&token_b64, &"a".repeat(64), &store);
        // Should fail because test fixtures have no real CMS signatures
        assert!(result.is_err());
    }
}
