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

- The workspace includes the `proxy-backend` crate that drives the MITM machinery and the Tauri UI under `proyxui/src-tauri` that now renders a React/Vite application from `proyxui/src`.
- `src/App.tsx` wraps the tabbed layout inside `ConnectionProvider`, which lives in `src/state/connection-store.tsx`. That store hydrates from `get_connections`/`get_intercept_queue`, listens to `proxy-event`, and normalizes backend snapshots into the data consumed by the `SiteMapTab`, `RequestReplayTab`, and `LiveInterceptTab`.
- Each tab (`src/tabs/*`) ships focused layouts and actions that call the accompanying Tauri commands (`resume_intercept`, `drop_request`, `replay_connection`, `toggle_live_intercept`, `modify_intercept`, `drop_intercept`, etc.) through `@tauri-apps/api/core` so the UI stays in sync with backend state.
- The Tauri backend (`proyxui/src-tauri/src/lib.rs`) now exposes the same proxy state as commands/events, forwards `ProxyEvent` via `app_handle.emit("proxy-event", …)`, and spins up the proxy server from `MitmProxy::bind` before launching the window.
- The shell mirrors the example template: a thin `src-tauri/src/main.rs` calls `proyxui_lib::run()`, `build.rs` runs `tauri_build::build`, and `tauri.conf.json` keeps the v2 schema while pointing at the React build output.
- Run `cargo tauri dev` from `proyxui/src-tauri` (with the React dev server on `devUrl`) to iterate, or `npm run build` from `proyxui` and then `cargo tauri build` to bundle.
- `Config::load` now walks up the directory tree when locating `proxy-config.toml` and resolves `ca_dir` relative to that location so both the CLI proxy and the Tauri shell reuse the same CA directory regardless of how they were launched.

## Building / running

1. **Backend**: `cargo run -p Proyx` from the repo root will compile the proxy and start it on the address specified in `proxy-config.toml` (default `127.0.0.1:8080`).
2. **UI**: `cargo tauri dev` (from `src-tauri`) launches the Tauri window that connects to the running proxy backend. The renderer uses the HTML/JS under `src-tauri/dist`; you can replace that with your preferred front-end toolchain so long as the built files end up in the same folder.
3. **Config changes**: edit `proxy-config.toml` or set `PROXY_CONFIG` to point to a different file. The Tauri binary will reuse the same config and emit the CA PEM/key during startup so you can trust it in your browser.

## Open gaps & improvements

1. **Live intercept controls** – Resume/Drop now resolve to actual decisions so waiting requests complete, and the UI queues modified bodies in `ProxyState`, yet we still need the state machine to inject the edited payload back into the resumed `Incoming` stream so downstream servers see the latest edits.
2. **Replay enrichment** – the replay tab already exposes headers, tags, sizes, durations, and previews emitted from `ProxyState`, but we can extend this by supporting persistent replay collections, scheduling helpers, and storing response metadata so editors can rehydrate a session end-to-end.
3. **State metadata & filtering** – `ConnectionStore` now preserves tags, durations, timestamps, and size hints for richer badges and filters; future work includes virtualization/pagination, memoized selectors for large histories, and exposing header/tag facets for filtering.
4. **Testing & tooling** – add unit/integration coverage for the `ConnectionStore`, tauri commands, and `ProxyEvent` wiring so UI workflows (toggle, resume, replay) stay reliable across refactors.
5. **Documentation** – keep `ui_mode_design.md` synced with the React tabs/components, catalog the Tauri invocations, and capture how the renderer consumes `proxy-event` payloads for future contributors.
