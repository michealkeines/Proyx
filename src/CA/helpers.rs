use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{X509, X509Builder, X509Extension, X509NameBuilder},
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

pub unsafe fn build_fake_cert_for_domain(
    domain: &str,
) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    // Load CA cert + key
    let ca_cert_der = std::fs::read("/Users/michealkeines/Proyx/src/CA/root.der").unwrap();
    let ca_key_pem = std::fs::read("/Users/michealkeines/Proyx/src/CA/root.key").unwrap();

    let ca_cert = X509::from_der(&ca_cert_der).unwrap();
    let ca_key = PKey::private_key_from_pem(&ca_key_pem).unwrap();

    // ---- FIX: Use ECDSA for leaf cert ----
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let leaf_key = PKey::from_ec_key(ec_key).unwrap();

    // Subject
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", domain).unwrap();
    let name = name.build();

    // Build certificate
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();

    // Serial
    let mut serial = BigNum::new().unwrap();
    serial
        .rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    let serial = serial.to_asn1_integer().unwrap();
    builder.set_serial_number(&serial).unwrap();

    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    builder.set_pubkey(&leaf_key).unwrap();

    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();

    // SAN
    let san = X509Extension::new_nid(
        None,
        Some(&builder.x509v3_context(Some(&ca_cert), None)),
        openssl::nid::Nid::SUBJECT_ALT_NAME,
        &format!("DNS:{}", domain),
    )
    .unwrap();
    builder.append_extension(san).unwrap();

    // KU
    let ku = X509Extension::new_nid(
        None,
        None,
        openssl::nid::Nid::KEY_USAGE,
        "digitalSignature,keyEncipherment",
    )
    .unwrap();
    builder.append_extension(ku).unwrap();

    // EKU
    let eku =
        X509Extension::new_nid(None, None, openssl::nid::Nid::EXT_KEY_USAGE, "serverAuth").unwrap();
    builder.append_extension(eku).unwrap();

    // ---- FIX: ECDSA signing using SHA256 ----
    builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let leaf_cert = builder.build();

    let der_cert = leaf_cert.to_der().unwrap();
    let der_key = leaf_key.private_key_to_der().unwrap();

    (
        CertificateDer::from(der_cert),
        PrivateKeyDer::try_from(der_key).unwrap(),
    )
}
