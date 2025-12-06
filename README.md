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

- `MitmProxy` (`src/lib.rs`) exposes `bind` and `wrap_service`, handling CONNECT upgrades, TLS interception, certificate generation, and request injection (`inject_authority`).
- `state_machine::process_request` drives each request through request/intercept/IO/response stages while keeping metadata for logging.
- `default_client::DefaultClient` is the outgoing HTTP client that negotiates TLS (native or rustls) and copies upgraded connections when `with_upgrades()` is not enabled.

## Certificates

Certificates are generated with `rcgen` on the fly. You can trust the CA by copying the printed PEM from startup (or the files at `ca_dir`). If you disable `root_issuer` in `MitmProxy::new(None, …)`, the proxy will simply tunnel CONNECT requests without inspecting HTTPS.

## Next steps

- Add tests or example clients under `dev-dependencies` if you need custom behavior (see `Cargo.toml` for available crates).
- Tune tracing/filtering through `log_level` in the configuration file.
