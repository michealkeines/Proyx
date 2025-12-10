use Proyx::{Config, MitmProxy, default_client::DefaultClient, load_or_create_ca};
use hyper::{Request, body::Incoming, service::service_fn};
use moka::sync::Cache;
use std::{env, error::Error as StdError, net::SocketAddr, path::Path};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    let config_path = env::var("PROXY_CONFIG").unwrap_or_else(|_| "proxy-config.toml".into());
    let config = Config::load(Path::new(&config_path))?;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&config.log_level))
        .init();

    let (root_issuer, ca_pem, ca_key) = load_or_create_ca(&config.ca_dir)?;
    println!();
    println!("=== Trust this CA in your browser ===");
    println!("{ca_pem}");
    println!("=== Private key (keep secret) ===");
    println!("{ca_key}");
    println!(
        "Save the certificate to `proxy-ca.pem` and import it into your browser/system trust store."
    );
    println!();

    let proxy = MitmProxy::new(Some(root_issuer), Some(Cache::new(config.cache_capacity)));
    let addr: SocketAddr = config.address.parse()?;

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
            Ok::<_, Proyx::default_client::Error>(res)
        }
    });

    let server = proxy.bind(addr, service).await?;
    tracing::info!("State-machine proxy listening on {addr}");
    server.await;

    Ok(())
}
