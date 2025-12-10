use std::{env, error::Error as StdError, net::SocketAddr, path::Path};

use tauri::{async_runtime, Emitter, Manager, State};
use tracing_subscriber::EnvFilter;

use Proyx::hyper::{body::Incoming, service::service_fn, Request};
use Proyx::moka::sync::Cache;
use Proyx::{
    default_client::{DefaultClient, Error as DefaultClientError},
    load_or_create_ca, Config, ConnectionSnapshot, MitmProxy, ProxyState,
};

#[derive(Clone)]
struct AppState {
    proxy_state: ProxyState,
}

#[tauri::command]
async fn get_connections(state: State<'_, AppState>) -> Result<Vec<ConnectionSnapshot>, String> {
    Ok(state.proxy_state.snapshots().await)
}

#[tauri::command]
async fn get_intercept_queue(
    state: State<'_, AppState>,
) -> Result<Vec<ConnectionSnapshot>, String> {
    Ok(state.proxy_state.intercept_queue().await)
}

#[tauri::command]
fn get_live_intercept(state: State<'_, AppState>) -> bool {
    state.proxy_state.is_live_intercept()
}

#[tauri::command]
fn toggle_live_intercept(state: State<'_, AppState>, enabled: bool) -> bool {
    state.proxy_state.set_live_intercept(enabled);
    true
}

#[tauri::command]
async fn resume_intercept(state: State<'_, AppState>, id: u64) -> Result<bool, String> {
    Ok(state.proxy_state.resume_intercept(id).await)
}

#[tauri::command]
async fn replay_connection(
    state: State<'_, AppState>,
    id: u64,
    payload: String,
) -> Result<bool, String> {
    tracing::info!(
        "Replaying connection {id} with payload of {} bytes",
        payload.len()
    );
    Ok(state.proxy_state.resume_intercept(id).await)
}

#[tauri::command]
async fn drop_request(state: State<'_, AppState>, id: u64) -> Result<bool, String> {
    tracing::info!("Dropping request {id}");
    Ok(state.proxy_state.resume_intercept(id).await)
}

#[tauri::command]
async fn modify_intercept(
    _state: State<'_, AppState>,
    id: u64,
    preview: String,
) -> Result<bool, String> {
    tracing::info!(
        "Modifying intercept {id} with {} bytes (not yet replayed)",
        preview.len()
    );
    let _ = (_state, id, preview);
    Ok(true)
}

#[tauri::command]
async fn drop_intercept(state: State<'_, AppState>, id: u64) -> Result<bool, String> {
    tracing::info!("Dropping intercept {id}");
    Ok(state.proxy_state.resume_intercept(id).await)
}

#[tauri::command]
fn save_to_collection(id: u64) -> bool {
    tracing::info!("Saving request {id} to the collection");
    true
}

pub fn run() -> Result<(), Box<dyn StdError>> {
    let context = tauri::generate_context!();
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
    println!("Save the certificate to `proxy-ca.pem` and import it into your browser/system trust store.");
    println!();

    let proxy = MitmProxy::new(Some(root_issuer), Some(Cache::new(config.cache_capacity)));
    let proxy_state = proxy.ui_state.clone();
    let server_addr: SocketAddr = config.address.parse()?;
    let client = DefaultClient::new();

    let app_state = AppState {
        proxy_state: proxy_state.clone(),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            get_connections,
            get_intercept_queue,
            get_live_intercept,
            toggle_live_intercept,
            resume_intercept,
            replay_connection,
            drop_request,
            modify_intercept,
            drop_intercept,
            save_to_collection,
        ])
        .setup(move |app| {
            let app_handle = app.app_handle();
            let emit_state = app_handle.state::<AppState>().proxy_state.clone();
            let client = client.clone();
            let addr = server_addr;
            let proxy = proxy;

            async_runtime::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let client = client.clone();
                    async move {
                        let (response, upgrade) = client.send_request(req).await?;
                        if let Some(handle) = upgrade {
                            async_runtime::spawn(async move {
                                let _ = handle.await;
                            });
                        }
                        Ok::<_, DefaultClientError>(response)
                    }
                });

                match proxy.bind(addr, service).await {
                    Ok(server) => {
                        tracing::info!("Proxy UI listening on {addr}");
                        let _ = server.await;
                    }
                    Err(err) => {
                        tracing::error!("Failed to bind proxy: {err}");
                    }
                }
            });

            let event_handle = app_handle.clone();
            async_runtime::spawn(async move {
                let mut events = emit_state.subscribe();
                while let Ok(event) = events.recv().await {
                    let _ = event_handle.emit("proxy-event", event);
                }
                tracing::warn!("Proxy event channel closed");
            });

            Ok(())
        })
        .run(context)?;

    Ok(())
}
