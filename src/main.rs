use http_mitm_proxy::{MitmProxy, default_client::DefaultClient};
use hyper::{Request, body::Incoming, service::service_fn};
use moka::sync::Cache;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, DnValue, IsCa, KeyPair,
    KeyUsagePurpose,
};
use std::{env, error::Error as StdError, fs, net::SocketAddr, path::Path};

fn make_root_issuer() -> (rcgen::Issuer<'static, KeyPair>, String, String) {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, DnValue::Utf8String("Proxy CA".into()));
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let signing_key = KeyPair::generate().expect("failed to generate CA key");
    let cert = params
        .self_signed(&signing_key)
        .expect("failed to self sign proxy CA");
    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();

    (rcgen::Issuer::new(params, signing_key), cert_pem, key_pem)
}

fn load_or_create_ca<P: AsRef<Path>>(
    dir: P,
) -> Result<(rcgen::Issuer<'static, KeyPair>, String, String), Box<dyn StdError>> {
    let cert_dir = dir.as_ref();
    let cert_path = cert_dir.join("proxy-ca.pem");
    let key_path = cert_dir.join("proxy-ca.key");

    if cert_path.exists() && key_path.exists() {
        let cert_pem = fs::read_to_string(&cert_path)?;
        let key_pem = fs::read_to_string(&key_path)?;
        let signing_key = KeyPair::from_pem(&key_pem)?;
        let issuer = rcgen::Issuer::from_ca_cert_pem(&cert_pem, signing_key)?;
        Ok((issuer, cert_pem, key_pem))
    } else {
        fs::create_dir_all(cert_dir)?;
        let (issuer, cert_pem, key_pem) = make_root_issuer();
        fs::write(&cert_path, &cert_pem)?;
        fs::write(&key_path, &key_pem)?;
        Ok((issuer, cert_pem, key_pem))
    }
}

fn ca_storage_dir() -> String {
    env::var("PROXY_CA_DIR").unwrap_or_else(|_| "./proxy-ca".into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    tracing_subscriber::fmt().init();

    let ca_dir = ca_storage_dir();
    let (root_issuer, ca_pem, ca_key) = load_or_create_ca(&ca_dir)?;
    println!();
    println!("=== Trust this CA in your browser ===");
    println!("{ca_pem}");
    println!("=== Private key (keep secret) ===");
    println!("{ca_key}");
    println!(
        "Save the certificate to `proxy-ca.pem` and import it into your browser/system trust store."
    );
    println!();

    let proxy = MitmProxy::new(Some(root_issuer), Some(Cache::new(1024)));
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    let client = DefaultClient::new();
    let service = service_fn(move |req: Request<Incoming>| {
        let client = client.clone();
        async move {
            let (res, upgrade) = client.send_request(req).await?;
            if let Some(handle) = upgrade {
                tokio::spawn(async move {
                    let _ = handle.await;
                });
            }
            Ok::<_, http_mitm_proxy::default_client::Error>(res)
        }
    });

    let server = proxy.bind(addr, service).await?;
    tracing::info!("State-machine proxy listening on {addr}");
    server.await;

    Ok(())
}
