use std::{
    env,
    error::Error as StdError,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use tauri::{async_runtime, Emitter, Manager, State};
use tracing_subscriber::EnvFilter;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use Proyx::hyper::{body::Incoming, service::service_fn, Request};
use Proyx::moka::sync::Cache;
use Proyx::{
    default_client::{DefaultClient, Error as DefaultClientError, Upgraded},
    load_or_create_ca, Config, ConnectionContext, ConnectionSnapshot, MitmProxy, ProxyState,
    WebSocketDirection, WebSocketEvent,
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
    state: State<'_, AppState>,
    id: u64,
    preview: String,
) -> Result<bool, String> {
    tracing::info!(
        "Modifying intercept {id} with {} bytes (queued for replay)",
        preview.len()
    );
    state
        .proxy_state
        .queue_intercept_modification(id, preview)
        .await;
    Ok(true)
}

#[tauri::command]
async fn drop_intercept(state: State<'_, AppState>, id: u64) -> Result<bool, String> {
    tracing::info!("Dropping intercept {id}");
    Ok(state.proxy_state.drop_intercept(id).await)
}

#[tauri::command]
fn save_to_collection(id: u64) -> bool {
    tracing::info!("Saving request {id} to the collection");
    true
}

fn detect_config_path() -> PathBuf {
    if let Ok(env_path) = env::var("PROXY_CONFIG") {
        return PathBuf::from(env_path);
    }

    let mut current = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    loop {
        let candidate = current.join("proxy-config.toml");
        if candidate.exists() {
            return candidate;
        }
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            break;
        }
    }

    PathBuf::from("proxy-config.toml")
}

pub fn run() -> Result<(), Box<dyn StdError>> {
    let context = tauri::generate_context!();
    let config_path = detect_config_path();
    tracing::info!("Loading configuration from {}", config_path.display());
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
    let client = DefaultClient::new().with_upgrades();

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

            let service_state = emit_state.clone();
            async_runtime::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let client = client.clone();
                    let proxy_state = service_state.clone();
                    async move {
                        let connection_context =
                            req.extensions().get::<ConnectionContext>().copied();
                        let (response, upgrade) = client.send_request(req).await?;
                        if let Some(handle) = upgrade {
                            let proxy_state = proxy_state.clone();
                            async_runtime::spawn(async move {
                                match handle.await {
                                    Ok(Ok(upgraded)) => {
                                        if let Some(context) = connection_context {
                                            log_websocket_connection(
                                                proxy_state,
                                                context,
                                                upgraded,
                                            )
                                            .await;
                                        } else {
                                            drain_upgraded(upgraded).await;
                                        }
                                    }
                                    Ok(Err(err)) => {
                                        tracing::warn!("WebSocket relay failed: {}", err);
                                    }
                                    Err(err) => {
                                        tracing::warn!("WebSocket upgrade join failed: {}", err);
                                    }
                                }
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

async fn log_websocket_connection(
    proxy_state: ProxyState,
    context: ConnectionContext,
    upgraded: Upgraded,
) {
    let (client_reader, client_writer) = tokio::io::split(upgraded.client);
    let (server_reader, server_writer) = tokio::io::split(upgraded.server);

    let c2s = relay_with_logging(
        client_reader,
        server_writer,
        WebSocketDirection::ClientToServer,
        proxy_state.clone(),
        context,
    );
    let s2c = relay_with_logging(
        server_reader,
        client_writer,
        WebSocketDirection::ServerToClient,
        proxy_state,
        context,
    );
    let _ = tokio::join!(c2s, s2c);
}

async fn relay_with_logging<R, W>(
    mut reader: R,
    mut writer: W,
    direction: WebSocketDirection,
    proxy_state: ProxyState,
    context: ConnectionContext,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 4096];

    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(size) => {
                if writer.write_all(&buffer[..size]).await.is_err() {
                    break;
                }

                let event = WebSocketEvent {
                    timestamp_ms: current_millis(),
                    direction,
                    payload_preview: summarize_payload(&buffer[..size]),
                };
                proxy_state.append_websocket_event(context.id, event).await;
            }
            Err(err) => {
                tracing::warn!("WebSocket relay error ({:?}): {}", direction, err);
                break;
            }
        }
    }

    let _ = writer.shutdown().await;
}

async fn drain_upgraded(mut upgraded: Upgraded) {
    let _ = tokio::io::copy_bidirectional(&mut upgraded.client, &mut upgraded.server).await;
}

fn summarize_payload(data: &[u8]) -> String {
    let mut payload = String::from_utf8_lossy(data).to_string();
    if payload.len() > 1024 {
        payload.truncate(1024);
        payload.push('…');
    }
    payload
}

fn current_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_millis() as u64)
        .unwrap_or_default()
}
