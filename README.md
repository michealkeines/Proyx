# Proyx

Proyx is an HTTP/HTTPS proxy server that can act as an MITM by dynamically generating certificates for inspected HTTPS traffic. It is built on top of `hyper`, provides a configurable cache for certificates, and ships with a default client implementation for relaying proxied requests.

## Highlights

- Transparently forwards HTTP and HTTPS requests while optionally inspecting TLS traffic when a trusted CA is provided.
- Uses a lightweight nginx-style state machine to drive the request/response lifecycle (`src/state_machine.rs`).
- Generates per-host certificates from a single root issuer (`src/tls.rs`) and caches them in-memory via `moka`.
- Ships with a `DefaultClient` helper that knows how to drive HTTP/1 and HTTP/2 connections with native TLS or Rustls backends.

## Getting started

1. Configure the proxy by editing `proxy-config.toml` or setting `PROXY_CONFIG` to point to another TOML file.
2. Build and run with Cargo (default feature enables a native TLS client):

```sh
cargo run
```

If you prefer `rustls` for outgoing connections, enable the `rustls-client` feature and disable `native-tls-client`:

```sh
cargo run --no-default-features --features rustls-client
```

## Configuration (`config::Config`, `proxy-config.toml`)

| Key | Description | Default |
|-----|-------------|---------|
| `address` | Socket address to bind the proxy to. | `127.0.0.1:8080` |
| `cache_capacity` | Certificate cache size (entries). | `1024` |
| `ca_dir` | Directory where the automatically generated CA certificate and key are stored. | `./proxy-ca` |
| `log_level` | Used for `tracing` env filter (see `main.rs`, lines 40-43). | `info` |

The first time the proxy starts it creates the CA under `ca_dir` (`proxy-ca.pem` and `proxy-ca.key`). The PEM blobs printed to stdout should be trusted by your browser/system to intercept HTTPS.

## Running examples

`src/main.rs` sets up the MITM infrastructure:

- Loads or creates the CA via `load_or_create_ca`.
- Builds a `MitmProxy` with the optional issuer and an in-memory cache.
- Spawns a `DefaultClient` to relay requests to their destinations, honoring HTTP upgrades when requested.
- Prints the CA certificate/key for trust installation and runs the proxy loop produced by `MitmProxy::bind`.

## Architecture overview

- `MitmProxy` (`proxy-backend/src/lib.rs`) exposes `bind` and `wrap_service`, handling CONNECT upgrades, TLS interception, certificate generation, request injection (`inject_authority`), and a shared `ProxyState` for UI consumers.
- `state_machine::process_request` drives every downstream request through request/intercept/IO/response stages while keeping metadata and wiring updates into `ProxyState`.
- `ProxyState` (`proxy-backend/src/proxy_state.rs`) keeps connection snapshots, live-intercept toggles, and resume waiters; it feeds the UI via tauri commands/events.
- `default_client::DefaultClient` is the outgoing HTTP client that negotiates TLS (native or rustls) and copies upgraded connections when needed.

## Certificates

Certificates are generated with `rcgen` on the fly. You can trust the CA by copying the printed PEM from startup (or the files at `ca_dir`). If you disable `root_issuer` in `MitmProxy::new(None, …)`, the proxy will simply tunnel CONNECT requests without inspecting HTTPS.

## Frontend / UI mode

- The project is now a workspace with two crates: `proxy-backend` (Rust proxy + state machine) and a Tauri UI (`src-tauri`) that runs the renderer served from `src-tauri/dist`.
- `src-tauri/main.rs` spins up the same backend proxy, exposes tauri commands (`toggle_live_intercept`, `resume_intercept`, `replay_connection`, `get_connections`, `get_intercept_queue`), and forwards backend events (`proxy-event`) to the renderer.
- The renderer currently mounts a tab bar, sitemap, replay, and live-intercept panels in vanilla JS/HTML/CSS located under `src-tauri/dist`.
- The Tauri layer now mirrors the working `example-code` template: the UI crate is a library (`proyx_ui_lib`) with a thin `main.rs` shim, `build.rs` runs `tauri_build::build`, and the runtime wires up the tray/menu, plugins, and proxy state before launching the window.
- `src-tauri/tauri.conf.json` keeps the template schema while pointing at `../dist` and the “Proyx Control Center” assets we copied from the example; icons, capability files, and the `frontendDist`/`devUrl` settings match the expected layout so the config parser succeeds.
- Run `cargo tauri dev -p proyx-ui` from `src-tauri` (with your renderer dev server running at the `devUrl`) to build the native shell that drives the multi-tab UI described in `ui_mode_design.md`.
- UI design notes live in `ui_mode_design.md`; follow that guide to extend tabs, shared components, and connection badges to match the described request/intercept/response states.
- Tauri’s config file (`src-tauri/tauri.conf.json`) follows the v2 schema (`https://schema.tauri.app/config/2`) and declares the window metadata, bundle settings, and allowlist needed by the runtime.

## Building / running

1. **Backend**: `cargo run -p Proyx` from the repo root will compile the proxy and start it on the address specified in `proxy-config.toml` (default `127.0.0.1:8080`).
2. **UI**: `cargo tauri dev` (from `src-tauri`) launches the Tauri window that connects to the running proxy backend. The renderer uses the HTML/JS under `src-tauri/dist`; you can replace that with your preferred front-end toolchain so long as the built files end up in the same folder.
3. **Config changes**: edit `proxy-config.toml` or set `PROXY_CONFIG` to point to a different file. The Tauri binary will reuse the same config and emit the CA PEM/key during startup so you can trust it in your browser.

## Open gaps & improvements

1. **UI wiring** – the renderer is currently static (vanilla JS). Flesh out real JSON/TS-based components, virtualize long lists, and replace the manual DOM updates with a framework if preferred.
2. **Intercept controls** – currently `resume_intercept` just releases requests; the plan is to add edit/resume/drop controls in the UI and persist lifecycle events (`request`, `intercept`, `response`) through the store.
3. **Replay actions** – replay currently just resets the proxy state; integrate request editors, stored collections, and replay scheduling via additional commands/events.
4. **Testing & tooling** – introduce unit/integration tests over the state machine, ProxyState, and tauri commands; consider harnesses for capturing live intercept scenarios.
5. **Documentation** – keep `ui_mode_design.md` in sync with any tab/component changes, expand this README with build/run scripts for the UI toolchain you adopt, and document how the renderer consumes `proxy-event` payloads.
