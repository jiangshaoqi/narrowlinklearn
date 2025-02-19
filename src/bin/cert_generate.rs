use std::fs;

use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::CertificateDer;
use time::{Duration, OffsetDateTime};



fn main() {

    // generate ca cert-key pair
	// proxy_demo: 74.235.241.242
    // let ca_addr = Ipv4Addr::new(74, 235, 241, 242);
    // let (ca_cert, ca_key) = generate_ca_cert(ca_addr, &ca_org);

    // let ca_org = "whatcanisay";
    // let (ca_cert, ca_key) = generate_ca_cert(&ca_org);
    let ca_cert_name = "wciscert.der";
    let ca_key_name = "wciskey.der";
    // fs::write(ca_key_name, ca_key.serialize_der()).expect("failed to write ca key");
    // fs::write(ca_cert_name, ca_cert.der()).expect("failed to write ca cert");

    // generate server leaf cert-key pair
    // let ca_key = fs::read(ca_key_name).expect("cannot read ca key");
    // let ca_key = KeyPair::try_from(ca_key).expect("cannot convert to key pair");
    // let ca_cert = fs::read(ca_cert_name).expect("cannot read ca cert");
    // let ca_cert = CertificateDer::from(ca_cert);
    // let ca_cert_param = CertificateParams::from_ca_cert_der(&ca_cert).expect("parse ca from der");
    // let ca_cert = ca_cert_param.self_signed(&ca_key).expect("failed to load ca certificate");
    
    // let proxy_name = "whatcanisay";
    // let (server_cert, server_key) = generate_leaf_ca_sign(
    //     rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    //     &proxy_name, 
    //     ca_cert,
    //     ca_key
    // );
    // fs::write("wcis_server_key.der", server_key.serialize_der()).expect("failed to write server key");
    // fs::write("wcis_server_cert.der", server_cert.der()).expect("failed to write server cert");


    // generate for client
    let ca_key = fs::read(ca_key_name).expect("cannot read ca key");
    let ca_key = KeyPair::try_from(ca_key).expect("cannot convert to key pair");
    let ca_cert = fs::read(ca_cert_name).expect("cannot read ca cert");
    let ca_cert = CertificateDer::from(ca_cert);
    let ca_cert_param = CertificateParams::from_ca_cert_der(&ca_cert).expect("parse ca from der");
    let ca_cert = ca_cert_param.self_signed(&ca_key).expect("failed to load ca certificate");
    let client_name = "man";
    let (client_cert, client_key) = generate_leaf_ca_sign(
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        &client_name,
        ca_cert,
        ca_key
    );
    fs::write("wcis_client_key.der", client_key.serialize_der()).expect("failed to write client key");
    fs::write("wcis_client_cert.der", client_cert.der()).expect("failed to write client cert");
    
}



fn generate_leaf_ca_sign(
    purpose: rcgen::ExtendedKeyUsagePurpose,
    // leaf_addr: Ipv4Addr,
    // leaf_org: &str,
    domain_name: &str,
    ca_cert: Certificate,
    ca_key: KeyPair
) -> (Certificate, KeyPair) {
    // let name: String = leaf_addr.to_string();
    let name = domain_name.to_string();
	let mut params = CertificateParams::new(vec![name.clone().into()])
        .expect("we know the name is valid");
	let (yesterday, tomorrow) = validity_period();
	params.distinguished_name.push(DnType::CommonName, name);
	params.use_authority_key_identifier_extension = true;
	params.key_usages.push(KeyUsagePurpose::DigitalSignature);
	params
		.extended_key_usages
		.push(purpose);
	params.not_before = yesterday;
	params.not_after = tomorrow;

	let proxy_key = KeyPair::generate().expect("cannot generate leaf certificate");
	let proxy_cert = params.signed_by(&proxy_key, &ca_cert, &ca_key)
        .expect("cannot sign the leaf certificate with ca");

    (proxy_cert, proxy_key)
}


#[allow(dead_code)]
fn generate_ca_cert(
    org_name: &str
    // ipv4: Ipv4Addr, 
) -> (Certificate, KeyPair) {
    let mut params =
		CertificateParams::new(Vec::default()).expect("empty subject alt name can't produce error");
    // params.subject_alt_names = vec![
    //     rcgen::SanType::IpAddress(std::net::IpAddr::V4(ipv4))
    // ];

    let (before, after) = validity_period();
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	params.distinguished_name.push(DnType::CountryName, "CA");
	params
		.distinguished_name
		.push(DnType::OrganizationName, org_name);
    params
        .distinguished_name
        .push(DnType::CommonName, org_name);
	params.key_usages.push(KeyUsagePurpose::DigitalSignature);
	params.key_usages.push(KeyUsagePurpose::KeyCertSign);
	params.key_usages.push(KeyUsagePurpose::CrlSign);

	params.not_before = before;
	params.not_after = after;

	let key_pair = KeyPair::generate().unwrap();
    
    (params.self_signed(&key_pair).unwrap(), key_pair)
}



fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
	// let day = Duration::new(86400, 0);
    let three_month = Duration::new(86400 * 30 * 12, 0);
	let before = OffsetDateTime::now_utc().checked_sub(three_month).unwrap();
	let after = OffsetDateTime::now_utc().checked_add(three_month).unwrap();
	(before, after)
}